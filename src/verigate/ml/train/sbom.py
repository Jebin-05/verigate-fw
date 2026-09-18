"""Train the SBOM risk model (P5-04): corpus → features@T0 → label@T1 → HGBR → ONNX + card.

Target (stated exactly, Manual §11): **expected exploited-CVE count at T1** — ``Σ EPSS_T1(cve)``
over every CVE of the release published by T1, using FIRST's EPSS snapshot of T1 (each EPSS value
is the probability that the CVE is exploited within 30 days, so the sum is the expected number of
the release's vulnerabilities that are exploited). The additive form keeps a dynamic range that
the "at least one exploited" composition loses for firmware carrying 50–200 CVEs. Features are
computed as of an earlier T0: only CVEs published by T0, the EPSS snapshot of T0 and KEV
membership as of T0, so the model predicts *future* exposure (including vulnerabilities not yet
disclosed at T0) from data that was public at T0. Rows are whole releases; the train/test split is
by release date (the newest releases are held out). The label comes from an external, evidence-
driven scoring system, not from a hand-made severity formula; the baseline scorer
(``ml/baseline.py``) is evaluated on the same label. (CISA KEV was tried first as the label and is
degenerate for this corpus: no KEV entry matches OpenWrt userland packages, so it is kept only as
a feature.)

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
from datetime import UTC, date, datetime, time
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
        """CVE records per component, restricted to CVEs published by ``as_of``."""
        cves_by_component = self.osv.cves_for_many(list(components))
        cutoff = datetime.combine(self.as_of, time.max, tzinfo=UTC)
        out: dict[Component, list[VulnRecord]] = {}
        for c in components:
            records = []
            for cve in sorted(cves_by_component.get(c, ())):
                info = self.osv.vuln(cve)
                if info.published is not None and info.published > cutoff:
                    continue  # not yet public on the snapshot date
                records.append(
                    VulnRecord(cve, info.cvss, self.epss.get(cve), self.kev.is_kev(cve, self.as_of))
                )
            out[c] = records
        return out


R_SCALE = 6.0
"""``r_sbom = 1 − exp(−expected_exploited / R_SCALE)``: six expected exploited CVEs → 0.63."""


def expected_exploited(records: dict[Component, list[VulnRecord]]) -> float:
    """Label: ``Σ epss`` over the release's unique CVEs (unknown EPSS counts as 0)."""
    unique: dict[str, VulnRecord] = {}
    for recs in records.values():
        for r in recs:
            unique.setdefault(r.cve, r)
    return float(sum(r.epss or 0.0 for r in unique.values()))


def to_r_sbom(expected: np.ndarray | float, scale: float = R_SCALE) -> np.ndarray:
    """Map an expected exploited count (≥ 0) to ``r_sbom`` in [0, 1)."""
    return 1.0 - np.exp(-np.clip(np.asarray(expected, dtype=np.float64), 0.0, None) / scale)


def build_dataset(
    rows: list[CorpusRow], lookup_t0: VulnLookup, lookup_t1: VulnLookup
) -> list[dict[str, Any]]:
    """Feature rows (as of T0) with the T1 label and the T0 baseline score."""
    context = corpus_context(rows, lookup_t0.as_of)
    dataset: list[dict[str, Any]] = []
    for row in rows:
        records_t0 = lookup_t0.records(row.components)
        records_t1 = lookup_t1.records(row.components)
        features = sbom_features(row.components, records_t0, context)
        dataset.append(
            {
                "id": row.id,
                "release": row.release,
                "released_at": row.released_at.isoformat(),
                **features,
                "n_cves_t1": len({r.cve for recs in records_t1.values() for r in recs}),
                "baseline_bp": baseline_bp([r for recs in records_t0.values() for r in recs]),
                "label": expected_exploited(records_t1),
            }
        )
    log.info(
        "dataset.built",
        rows=len(dataset),
        t0=lookup_t0.as_of.isoformat(),
        t1=lookup_t1.as_of.isoformat(),
    )
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


SUM_EPSS_INDEX = FEATURE_NAMES.index("sum_epss_x1e4")
MIN_T0_EXPOSURE = 1e-3


def t0_exposure(x: np.ndarray) -> np.ndarray:
    """Σ EPSS at T0 (the feature ``sum_epss_x1e4`` back on the probability scale)."""
    exposure: np.ndarray = np.maximum(
        np.asarray(x, dtype=np.float64)[:, SUM_EPSS_INDEX] / 10_000, MIN_T0_EXPOSURE
    )
    return exposure


def matrix(dataset: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray]:
    """``(X, y)`` in :data:`FEATURE_NAMES` order; ``y`` is the expected exploited count at T1."""
    x = np.array([as_vector(d) for d in dataset], dtype=np.float32)
    y = np.array([d["label"] for d in dataset], dtype=np.float64)
    return x, y


def growth_ratio(x: np.ndarray, y: np.ndarray) -> np.ndarray:
    """The learning target: ``label / T0 exposure`` (how much exposure grows by T1)."""
    ratio: np.ndarray = np.asarray(y, dtype=np.float64) / t0_exposure(x)
    return ratio


def expected_from_ratio(x: np.ndarray, ratio: np.ndarray) -> np.ndarray:
    """Model output (ratio) → expected exploited count: ``T0 exposure × ratio``."""
    expected: np.ndarray = np.clip(t0_exposure(x) * np.asarray(ratio, dtype=np.float64), 0.0, None)
    return expected


def train_model(x: np.ndarray, y: np.ndarray, seed: int) -> HistGradientBoostingRegressor:
    """Seeded HGBR on the growth ratio (no early stopping: the trees are a function of the data).

    Trees cannot extrapolate: a direct regressor predicts a constant for releases with fewer CVEs
    than any training release (the newest ones). Learning the ratio to the T0 exposure keeps the
    ranking structure of the T0 data and lets the model learn how exposure grows.
    """
    model = HistGradientBoostingRegressor(random_state=seed, early_stopping=False, **HYPERPARAMS)
    model.fit(x, growth_ratio(x, y))
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
    return finalise_onnx(onnx_model, MODEL_NAME, list(FEATURE_NAMES))


def finalise_onnx(onnx_model: onnx.ModelProto, name: str, features: list[str]) -> bytes:
    """Make the serialised bytes reproducible: fixed graph name / metadata, sorted opset imports.

    skl2onnx assigns a random uuid as graph name and emits ``opset_import`` in dict order, which
    depends on Python's per-process string hashing.
    """
    onnx_model.graph.name = name
    onnx_model.producer_name = "verigate-train"
    onnx_model.producer_version = "1"
    onnx_model.doc_string = f"{name}: features={features}"
    onnx_model.model_version = 1
    opsets = sorted(onnx_model.opset_import, key=lambda o: o.domain)
    del onnx_model.opset_import[:]
    onnx_model.opset_import.extend(opsets)
    return bytes(onnx_model.SerializeToString())


_SESSIONS: dict[str, ort.InferenceSession] = {}


def onnx_session(onnx_bytes: bytes) -> ort.InferenceSession:
    """An onnxruntime session for these bytes (cached: session creation dominates)."""
    key = hashlib.sha256(onnx_bytes).hexdigest()
    if key not in _SESSIONS:
        _SESSIONS[key] = ort.InferenceSession(onnx_bytes, providers=["CPUExecutionProvider"])
    return _SESSIONS[key]


def onnx_predict(onnx_bytes: bytes, x: np.ndarray) -> np.ndarray:
    """Run the ONNX model with onnxruntime (what the gateway does)."""
    session = onnx_session(onnx_bytes)
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
    binary = (y_true >= R_SCALE / 2).astype(int)  # "≥ 3 expected exploited CVEs" vs the rest
    if 0 < binary.sum() < len(binary):
        out["auroc_high_exposure"] = float(roc_auc_score(binary, y_pred))
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
        "r_scale": R_SCALE,
        "onnx_max_abs_diff": onnx_max_abs_diff,
        "train_rows": len(train),
        "test_rows": len(test),
        "label_mean_train": float(np.mean([d["label"] for d in train])) if train else 0.0,
        "label_mean_test": float(np.mean([d["label"] for d in test])) if test else 0.0,
        "metric_rows": "\n".join(
            f"| {k} | {fmt(model_metrics.get(k))} | {fmt(baseline_metrics.get(k))} |" for k in keys
        ),
    }
