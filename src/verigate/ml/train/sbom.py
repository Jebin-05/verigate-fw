"""Train the SBOM risk model (P5-04): corpus → features@T0 → label@T1 → HGBR → ONNX + card.

Target (stated exactly, Manual §11): **KEV exposure at T1** — the fraction of the release's
unique CVEs that CISA lists as known-exploited on date T1, predicted from features computed
with the EPSS snapshot and KEV membership as of an earlier date T0. Rows are whole releases;
the train/test split is by release date (the newest releases are held out), so nothing about a
test release leaks into training. The label is exploitation ground truth, not a hand-made
severity score; the baseline scorer (``ml/baseline.py``) is evaluated on the same label.

Every step is seeded and deterministic: running ``verigate-train sbom`` twice produces
byte-identical ONNX files (tested).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import platform
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import date
from importlib import resources
from pathlib import Path
from typing import Any

import numpy as np
import onnx
import onnxruntime as ort
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import HistGradientBoostingRegressor

from verigate.common.logging import get_logger
from verigate.ml.baseline import baseline_bp
from verigate.ml.data.sbom import Component, components_of
from verigate.ml.features.sbom_features import (
    FEATURE_NAMES,
    CorpusContext,
    VulnRecord,
    as_vector,
    sbom_features,
)
from verigate.ml.vulndb.epss import EpssSnapshot
from verigate.ml.vulndb.kev import KevCatalogue
from verigate.ml.vulndb.osv import OsvClient

log = get_logger(__name__)

MODEL_NAME = "sbom_risk"
HYPERPARAMS: dict[str, Any] = {
    "max_iter": 200,
    "learning_rate": 0.05,
    "max_depth": 4,
    "min_samples_leaf": 5,
    "l2_regularization": 1.0,
}


@dataclass(frozen=True)
class CorpusRow:
    """One release of the corpus with everything the trainer needs."""

    id: str
    release: str
    released_at: date
    components: tuple[Component, ...]


def load_corpus(data_dir: Path) -> list[CorpusRow]:
    """Read ``data/processed/index.json`` and the SBOM files it points at."""
    index = json.loads((data_dir / "processed" / "index.json").read_text())
    rows: list[CorpusRow] = []
    for item in index:
        sbom = json.loads((data_dir / item["sbom"]).read_text())
        rows.append(
            CorpusRow(
                item["id"],
                item["release"],
                date.fromisoformat(item["released_at"]),
                tuple(components_of(sbom)),
            )
        )
    return sorted(rows, key=lambda r: (r.released_at, r.id))


def corpus_context(rows: list[CorpusRow], as_of: date) -> CorpusContext:
    """Newest version per package and first-seen date per (name, version), from the corpus."""
    latest: dict[str, tuple[date, str]] = {}
    first_seen: dict[tuple[str, str], date] = {}
    for row in rows:
        for c in row.components:
            key = (c.name, c.version)
            if key not in first_seen or row.released_at < first_seen[key]:
                first_seen[key] = row.released_at
            if c.name not in latest or row.released_at > latest[c.name][0]:
                latest[c.name] = (row.released_at, c.version)
    return CorpusContext(as_of, {k: v[1] for k, v in latest.items()}, first_seen)


class VulnLookup:
    """Resolve components → ``VulnRecord`` lists as of a date (all sources cached on disk)."""

    def __init__(self, osv: OsvClient, epss: EpssSnapshot, kev: KevCatalogue, as_of: date) -> None:
        self.osv = osv
        self.epss = epss
        self.kev = kev
        self.as_of = as_of

    def records(
        self, components: list[Component] | tuple[Component, ...]
    ) -> dict[Component, list[VulnRecord]]:
        """CVE records per component (deduplicated inside each component)."""
        cves_by_component = self.osv.cves_for_many(list(components))
        out: dict[Component, list[VulnRecord]] = {}
        for c in components:
            records = []
            for cve in sorted(cves_by_component.get(c, ())):
                info = self.osv.vuln(cve)
                records.append(
                    VulnRecord(cve, info.cvss, self.epss.get(cve), self.kev.is_kev(cve, self.as_of))
                )
            out[c] = records
        return out


def kev_exposure(
    records: dict[Component, list[VulnRecord]], kev: KevCatalogue, as_of: date
) -> float:
    """Label: fraction of the release's unique CVEs that are in KEV as of ``as_of``."""
    cves = {r.cve for recs in records.values() for r in recs}
    if not cves:
        return 0.0
    return sum(1 for cve in cves if kev.is_kev(cve, as_of)) / len(cves)


def build_dataset(
    rows: list[CorpusRow], lookup_t0: VulnLookup, kev: KevCatalogue, t1: date
) -> list[dict[str, Any]]:
    """Feature rows with the T1 label and the T0 baseline score."""
    context = corpus_context(rows, lookup_t0.as_of)
    dataset: list[dict[str, Any]] = []
    for row in rows:
        records = lookup_t0.records(row.components)
        features = sbom_features(row.components, records, context)
        dataset.append(
            {
                "id": row.id,
                "release": row.release,
                "released_at": row.released_at.isoformat(),
                **features,
                "baseline_bp": baseline_bp([r for recs in records.values() for r in recs]),
                "label": kev_exposure(records, kev, t1),
            }
        )
    log.info("dataset.built", rows=len(dataset), t0=lookup_t0.as_of.isoformat(), t1=t1.isoformat())
    return dataset


def temporal_split(
    dataset: list[dict[str, Any]], test_fraction: float = 0.2
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Hold out the newest releases (by release date, whole releases) as the test set."""
    releases = sorted({(d["released_at"], d["release"]) for d in dataset})
    n_test = max(1, round(len(releases) * test_fraction))
    test_releases = {r for _, r in releases[-n_test:]}
    train = [d for d in dataset if d["release"] not in test_releases]
    test = [d for d in dataset if d["release"] in test_releases]
    return train, test


def matrix(dataset: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray]:
    """``(X, y)`` in :data:`FEATURE_NAMES` order."""
    x = np.array([as_vector(d) for d in dataset], dtype=np.float32)
    y = np.array([d["label"] for d in dataset], dtype=np.float64)
    return x, y


def train_model(x: np.ndarray, y: np.ndarray, seed: int) -> HistGradientBoostingRegressor:
    """Seeded HGBR (no early stopping, so the tree structure is a pure function of the data)."""
    model = HistGradientBoostingRegressor(random_state=seed, early_stopping=False, **HYPERPARAMS)
    model.fit(x, y)
    return model


@contextlib.contextmanager
def _bool_attribute_shim() -> Iterator[None]:
    """Coerce bools to ints inside ``onnx.helper.make_attribute`` during one conversion.

    skl2onnx emits Python bools in ``nodes_missing_value_tracks_true``; onnx's protobuf builder
    only accepts ints there.
    """
    original = onnx.helper.make_attribute

    def patched(key: str, value: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(value, list | tuple) and any(isinstance(v, bool | np.bool_) for v in value):
            value = [int(v) if isinstance(v, bool | np.bool_) else v for v in value]
        return original(key, value, *args, **kwargs)

    onnx.helper.make_attribute = patched
    try:
        yield
    finally:
        onnx.helper.make_attribute = original


def export_onnx(model: HistGradientBoostingRegressor, n_features: int) -> bytes:
    """Serialise to ONNX with a fixed opset/metadata so the bytes are reproducible."""
    with _bool_attribute_shim():
        onnx_model = convert_sklearn(
            model,
            initial_types=[("features", FloatTensorType([None, n_features]))],
            target_opset={"": 17, "ai.onnx.ml": 3},
        )
    onnx_model.graph.name = MODEL_NAME  # skl2onnx assigns a random uuid → non-reproducible bytes
    onnx_model.producer_name = "verigate-train"
    onnx_model.producer_version = "1"
    onnx_model.doc_string = f"{MODEL_NAME}: features={list(FEATURE_NAMES)}"
    onnx_model.model_version = 1
    return bytes(onnx_model.SerializeToString())


def onnx_predict(onnx_bytes: bytes, x: np.ndarray) -> np.ndarray:
    """Run the ONNX model with onnxruntime (what the gateway does)."""
    session = ort.InferenceSession(onnx_bytes, providers=["CPUExecutionProvider"])
    name = session.get_inputs()[0].name
    out = session.run(None, {name: x.astype(np.float32)})[0]
    return np.asarray(out, dtype=np.float64).reshape(-1)


def metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    """Regression + ranking metrics (median absolute error, Spearman, AUROC on any-KEV)."""
    from scipy.stats import spearmanr  # noqa: PLC0415
    from sklearn.metrics import roc_auc_score  # noqa: PLC0415

    out: dict[str, float] = {
        "mae": float(np.mean(np.abs(y_true - y_pred))),
        "median_ae": float(np.median(np.abs(y_true - y_pred))),
    }
    if len(y_true) > 2 and np.std(y_true) > 0 and np.std(y_pred) > 0:
        out["spearman"] = float(spearmanr(y_true, y_pred).statistic)
    binary = (y_true > 0).astype(int)
    if 0 < binary.sum() < len(binary):
        out["auroc_any_kev"] = float(roc_auc_score(binary, y_pred))
    return out


def git_sha() -> str:
    """Current commit (or "unknown")."""
    git = shutil.which("git")
    if git is None:
        return "unknown"
    try:
        result = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [git, "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return result.stdout.strip()


def write_card(path: Path, fields: dict[str, Any]) -> None:
    """Model card (Manual §11) from the package template; every number comes from this run."""
    template = resources.files("verigate.ml.train").joinpath("sbom_card.md.tmpl").read_text()
    path.write_text(template.format(**fields))


def card_fields(
    onnx_bytes: bytes,
    dataset: list[dict[str, Any]],
    train: list[dict[str, Any]],
    test: list[dict[str, Any]],
    seed: int,
    t0: date,
    t1: date,
    model_metrics: dict[str, float],
    baseline_metrics: dict[str, float],
    onnx_max_abs_diff: float,
    data_manifest_sha: str,
    epss_version: str,
    kev_released: str,
) -> dict[str, Any]:
    """Assemble the template fields."""
    units = {
        "n_components": "count",
        "n_vulnerable_components": "count",
        "n_cves": "count (unique CVEs)",
        "max_cvss_x10": "CVSS v3 base score × 10",
        "mean_cvss_x10": "CVSS v3 base score × 10",
        "sum_epss_x1e4": "Σ EPSS × 10 000",
        "max_epss_x1e4": "max EPSS × 10 000",
        "kev_count": "count (KEV as of T0)",
        "n_outdated": "components older than the corpus' newest version of that package",
        "mean_dep_age_days": "mean days since each shipped version was first seen in the corpus",
    }
    releases = sorted({d["release"] for d in dataset})
    keys = sorted(set(model_metrics) | set(baseline_metrics))

    def fmt(v: float | None) -> str:
        return "n/a" if v is None else f"{v:.4f}"

    return {
        "model_name": MODEL_NAME,
        "model_hash": hashlib.sha256(onnx_bytes).hexdigest(),
        "trained_on": date.today().isoformat(),  # noqa: DTZ011 — a date label, not a timestamp
        "git_sha": git_sha(),
        "seed": seed,
        "python_version": platform.python_version(),
        "n_rows": len(dataset),
        "n_releases": len(releases),
        "first_release": releases[0] if releases else "-",
        "last_release": releases[-1] if releases else "-",
        "data_manifest_sha": data_manifest_sha,
        "t0": t0.isoformat(),
        "t1": t1.isoformat(),
        "epss_version": epss_version,
        "kev_released": kev_released,
        "feature_rows": "\n".join(
            f"| {i + 1} | `{name}` | {units[name]} |" for i, name in enumerate(FEATURE_NAMES)
        ),
        "hyperparams": json.dumps(HYPERPARAMS, sort_keys=True),
        "onnx_max_abs_diff": onnx_max_abs_diff,
        "train_rows": len(train),
        "test_rows": len(test),
        "label_mean_train": float(np.mean([d["label"] for d in train])) if train else 0.0,
        "label_mean_test": float(np.mean([d["label"] for d in test])) if test else 0.0,
        "metric_rows": "\n".join(
            f"| {k} | {fmt(model_metrics.get(k))} | {fmt(baseline_metrics.get(k))} |" for k in keys
        ),
    }
