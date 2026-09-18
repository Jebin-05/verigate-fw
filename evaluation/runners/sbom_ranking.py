"""P5-07: model vs baseline on held-out releases — expected exploited CVEs (Spearman, MAE, AUROC).

Repetitions are bootstrap resamples of the held-out set (the model itself is deterministic), so
the summary reports median and IQR over ``repetitions`` resamples plus the point estimate.
"""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from typing import Any

import numpy as np
from common import ROOT, median_iqr, write_raw, write_summary
from scipy.stats import spearmanr
from sklearn.metrics import roc_auc_score

from verigate.ml.features.sbom_features import FEATURE_NAMES
from verigate.ml.train.sbom import expected_from_ratio, onnx_predict, temporal_split


def _metrics(y: np.ndarray, pred: np.ndarray) -> dict[str, float]:
    out: dict[str, float] = {}
    if np.std(y) > 0 and np.std(pred) > 0:
        out["spearman"] = float(spearmanr(y, pred).statistic)
    binary = (y >= 3.0).astype(int)  # "≥ 3 expected exploited CVEs" vs the rest
    if 0 < binary.sum() < len(binary):
        out["auroc_high_exposure"] = float(roc_auc_score(binary, pred))
    out["mae"] = float(np.mean(np.abs(y - pred)))
    return out


def run(config: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Read the training dataset CSV and the ONNX model, score the held-out releases."""
    model_path = ROOT / config["model"]
    dataset_path = ROOT / config["dataset"]
    seed = int(config.get("seed", 42))
    reps = int(config.get("repetitions", 200))
    onnx_bytes = model_path.read_bytes()
    with dataset_path.open() as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        for k in FEATURE_NAMES:
            r[k] = int(r[k])
        r["label"] = float(r["label"])
        r["baseline_bp"] = int(r["baseline_bp"])
    _, test = temporal_split(rows, float(config.get("test_fraction", 0.2)))
    x = np.array([[float(r[k]) for k in FEATURE_NAMES] for r in test], dtype=np.float32)
    y = np.array([r["label"] for r in test])
    model_pred = expected_from_ratio(x, onnx_predict(onnx_bytes, x))
    base_pred = -np.log1p(-np.array([r["baseline_bp"] / 10_000 for r in test]).clip(0, 0.9999))

    point = {"model": _metrics(y, model_pred), "baseline": _metrics(y, base_pred)}
    rng = np.random.default_rng(seed)
    raw: list[dict[str, Any]] = []
    for rep in range(reps):
        idx = rng.integers(0, len(y), size=len(y))
        for scorer, pred in (("model", model_pred), ("baseline", base_pred)):
            m = _metrics(y[idx], pred[idx])
            raw.append({"rep": rep, "scorer": scorer, **m})
    write_raw(out_dir, raw)
    summary: dict[str, Any] = {
        "experiment": "sbom_ranking",
        "held_out_rows": len(test),
        "held_out_releases": len({r["release"] for r in test}),
        "point_estimates": point,
        "bootstrap": {},
        "model_hash": "0x" + hashlib.sha256(onnx_bytes).hexdigest(),
    }
    for scorer in ("model", "baseline"):
        for metric in ("auroc_high_exposure", "spearman", "mae"):
            values = [r[metric] for r in raw if r["scorer"] == scorer and metric in r]
            if values:
                summary["bootstrap"][f"{scorer}.{metric}"] = median_iqr(values)
    write_summary(out_dir, summary)
    print(f"  held-out rows {len(test)} · model {point['model']} · baseline {point['baseline']}")
    return {"model_hash": summary["model_hash"], "dataset": str(dataset_path.relative_to(ROOT))}
