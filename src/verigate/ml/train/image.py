"""Train the image anomaly detector (P6-03): benign ELF corpus → features → IsolationForest → ONNX.

Training uses **benign releases only** (real OpenWrt package binaries that have a predecessor in
the corpus, so version deltas are defined). The tampered set — every catalogue mutation applied
to every benign sample with a fixed seed — is used only for evaluation and the model card.

``r_img`` calibration (documented, stored next to the model): the anomaly score ``s`` of a sample
is mapped linearly so that the benign training median → 0.0 and the benign 99th percentile →
0.5, clipped to [0, 1]. Anything scoring beyond every benign training sample is therefore
"more than half suspicious", which is where the policy thresholds start to bite.
"""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass
from datetime import date
from importlib import resources
from pathlib import Path
from typing import Any

import numpy as np
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import IsolationForest

from verigate.common.logging import get_logger
from verigate.ml.data.mutate import CATALOGUE
from verigate.ml.features.image_features import FEATURE_NAMES, as_vector, image_features
from verigate.ml.train.sbom import _bool_attribute_shim, finalise_onnx, git_sha, onnx_session

log = get_logger(__name__)

MODEL_NAME = "image_anomaly"
HYPERPARAMS: dict[str, Any] = {"n_estimators": 200, "max_samples": 128, "contamination": "auto"}


@dataclass(frozen=True)
class Sample:
    """One benign binary with its predecessor."""

    release: str
    package: str
    version: str
    image: bytes
    previous: bytes


def load_corpus(data_dir: Path) -> list[Sample]:
    """Benign samples that have a predecessor (``processed/images_index.json``)."""
    rows = json.loads((data_dir / "processed" / "images_index.json").read_text())
    samples: list[Sample] = []
    for r in rows:
        if not r["previous"]:
            continue
        samples.append(
            Sample(
                r["release"],
                r["package"],
                r["version"],
                Path(r["path"]).read_bytes(),
                Path(r["previous"]).read_bytes(),
            )
        )
    return samples


def benign_rows(samples: list[Sample]) -> list[dict[str, Any]]:
    """Feature rows for the benign set."""
    return [
        {
            "release": s.release,
            "package": s.package,
            "mutation": "benign",
            **image_features(s.image, s.previous),
        }
        for s in samples
    ]


def tampered_rows(samples: list[Sample], seed: int) -> list[dict[str, Any]]:
    """Every catalogue mutation applied to every sample (seed derived per sample and mutation)."""
    rows: list[dict[str, Any]] = []
    for i, s in enumerate(samples):
        for j, (name, mutation) in enumerate(CATALOGUE.items()):
            extra = {"old_image": s.previous} if name == "downgrade-relabel" else {}
            mutated = mutation.apply(s.image, seed * 100_003 + i * 7 + j, **extra)
            rows.append(
                {
                    "release": s.release,
                    "package": s.package,
                    "mutation": name,
                    **image_features(mutated, s.previous),
                }
            )
    return rows


def matrix(rows: list[dict[str, Any]]) -> np.ndarray:
    """Rows → float32 feature matrix in :data:`FEATURE_NAMES` order."""
    return np.array([as_vector(r) for r in rows], dtype=np.float32)


def train_model(x: np.ndarray, seed: int, **overrides: Any) -> IsolationForest:
    """Seeded IsolationForest on benign rows only (``overrides`` only for tests)."""
    model = IsolationForest(random_state=seed, **{**HYPERPARAMS, **overrides})
    model.fit(x)
    return model


def anomaly_scores(model: IsolationForest, x: np.ndarray) -> np.ndarray:
    """Sklearn's anomaly score (higher = more anomalous), i.e. ``-score_samples``."""
    return -np.asarray(model.score_samples(x), dtype=np.float64)


@dataclass(frozen=True)
class Calibration:
    """Linear map from anomaly score to ``r_img``."""

    s_median: float
    s_p99: float

    def r_img(self, s: np.ndarray) -> np.ndarray:
        """Benign median → 0, benign 99th percentile → 0.5, clipped to [0, 1]."""
        scale = max(self.s_p99 - self.s_median, 1e-9)
        return np.clip((s - self.s_median) / scale * 0.5, 0.0, 1.0)


def calibrate(train_scores: np.ndarray) -> Calibration:
    """Calibration constants from the benign training scores."""
    return Calibration(float(np.median(train_scores)), float(np.percentile(train_scores, 99)))


def export_onnx(model: IsolationForest, n_features: int) -> bytes:
    """ONNX with the ``scores`` output = sklearn ``decision_function`` (reproducible bytes)."""
    with _bool_attribute_shim():
        onnx_model = convert_sklearn(
            model,
            initial_types=[("features", FloatTensorType([None, n_features]))],
            target_opset={"": 17, "ai.onnx.ml": 3},
        )
    return finalise_onnx(onnx_model, MODEL_NAME, list(FEATURE_NAMES))


def onnx_anomaly_scores(onnx_bytes: bytes, x: np.ndarray, offset: float) -> np.ndarray:
    """Anomaly scores from the ONNX ``scores`` output (= decision_function; + offset → sklearn)."""
    session = onnx_session(onnx_bytes)
    outputs = {o.name: o for o in session.get_outputs()}
    name = session.get_inputs()[0].name
    result = session.run([n for n in outputs if n == "scores"], {name: x.astype(np.float32)})[0]
    decision = np.asarray(result, dtype=np.float64).reshape(-1)
    return -(decision + offset)


def per_class_metrics(
    benign_r: np.ndarray, tampered: list[dict[str, Any]], tampered_r: np.ndarray, threshold: float
) -> dict[str, dict[str, float]]:
    """Precision / recall / AUROC per mutation class at ``r_img >= threshold``."""
    from sklearn.metrics import roc_auc_score  # noqa: PLC0415

    out: dict[str, dict[str, float]] = {}
    benign_flagged = int((benign_r >= threshold).sum())
    out["benign"] = {
        "false_positive_rate": benign_flagged / max(len(benign_r), 1),
        "n": float(len(benign_r)),
    }
    for name in CATALOGUE:
        r = np.array(
            [v for row, v in zip(tampered, tampered_r, strict=True) if row["mutation"] == name]
        )
        if r.size == 0:
            continue
        tp = int((r >= threshold).sum())
        recall = tp / r.size
        precision = tp / (tp + benign_flagged) if tp + benign_flagged else 0.0
        y = np.concatenate([np.zeros(len(benign_r)), np.ones(r.size)])
        scores = np.concatenate([benign_r, r])
        auroc = float(roc_auc_score(y, scores)) if len(set(y)) == 2 else float("nan")
        out[name] = {"precision": precision, "recall": recall, "auroc": auroc, "n": float(r.size)}
    return out


def write_card(path: Path, fields: dict[str, Any]) -> None:
    """Model card from the package template."""
    template = resources.files("verigate.ml.train").joinpath("image_card.md.tmpl").read_text()
    path.write_text(template.format(**fields))


def card_fields(
    onnx_bytes: bytes,
    samples: list[Sample],
    benign: list[dict[str, Any]],
    tampered: list[dict[str, Any]],
    seed: int,
    calibration: Calibration,
    metrics: dict[str, dict[str, float]],
    onnx_max_abs_diff: float,
    data_manifest_sha: str,
) -> dict[str, Any]:
    """Assemble the template fields."""
    units = {
        "size_kb": "KiB",
        "entropy_mean_x1000": "bits/byte × 1000 over 1 KiB chunks",
        "entropy_std_x1000": "bits/byte × 1000",
        "entropy_max_x1000": "bits/byte × 1000",
        "high_entropy_chunks_pct": "% of chunks with entropy > 7.5",
        "printable_ratio_x1000": "fraction of printable bytes × 1000",
        "header_valid": "ELF header sane (0/1)",
        "n_sections": "section-table entries (0 for stripped binaries)",
        "n_segments": "program-header entries",
        "declared_size_kb": "highest byte covered by a PT_LOAD segment / section, KiB",
        "appended_kb": "bytes after the declared end, KiB",
        "size_delta_kb": "size − previous version, KiB",
        "entropy_delta_x1000": "mean entropy − previous, × 1000",
        "changed_chunks_pct": "% of 1 KiB chunks that differ from the previous version",
    }
    releases = sorted({s.release for s in samples})
    metric_rows = []
    for name, m in metrics.items():
        if name == "benign":
            fpr = m["false_positive_rate"]
            metric_rows.append(
                f"| benign (train) | false-positive rate {fpr:.3f} | – | – | {int(m['n'])} |"
            )
        else:
            p, r, a = m["precision"], m["recall"], m["auroc"]
            metric_rows.append(f"| `{name}` | {p:.3f} | {r:.3f} | {a:.3f} | {int(m['n'])} |")
    return {
        "model_name": MODEL_NAME,
        "model_hash": hashlib.sha256(onnx_bytes).hexdigest(),
        "trained_on": date.today().isoformat(),  # noqa: DTZ011 — a date label
        "git_sha": git_sha(),
        "seed": seed,
        "python_version": platform.python_version(),
        "n_benign": len(benign),
        "n_tampered": len(tampered),
        "n_packages": len({s.package for s in samples}),
        "n_releases": len(releases),
        "first_release": releases[0] if releases else "-",
        "last_release": releases[-1] if releases else "-",
        "data_manifest_sha": data_manifest_sha,
        "feature_rows": "\n".join(
            f"| {i + 1} | `{n}` | {units[n]} |" for i, n in enumerate(FEATURE_NAMES)
        ),
        "hyperparams": json.dumps(HYPERPARAMS, sort_keys=True),
        "s_median": calibration.s_median,
        "s_p99": calibration.s_p99,
        "onnx_max_abs_diff": onnx_max_abs_diff,
        "metric_rows": "\n".join(metric_rows),
        "mutations": "\n".join(
            f"| `{m.name}` | {m.description} | `{json.dumps(m.params)}` |"
            for m in CATALOGUE.values()
        ),
    }
