"""P6-04 / P7-01: image anomaly detector — precision / recall / F1 per mutation class.

Reads the dataset the trainer wrote (benign + tampered rows with calibrated ``r_img``), sweeps
the operating threshold, and bootstraps the per-class metrics at the policy-relevant threshold.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import numpy as np
from common import ROOT, median_iqr, write_raw, write_summary
from sklearn.metrics import roc_auc_score


def _prf(benign: np.ndarray, tampered: np.ndarray, threshold: float) -> dict[str, float]:
    fp = int((benign >= threshold).sum())
    tp = int((tampered >= threshold).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(tampered) if len(tampered) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fp / max(len(benign), 1)}


def run(config: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Per-class metrics at ``threshold`` plus a threshold sweep and bootstrap IQRs."""
    with (ROOT / config["dataset"]).open() as fh:
        rows = list(csv.DictReader(fh))
    threshold = float(config.get("threshold", 0.5))
    reps = int(config.get("repetitions", 200))
    rng = np.random.default_rng(int(config.get("seed", 42)))
    benign = np.array([float(r["r_img"]) for r in rows if r["mutation"] == "benign"])
    classes = sorted({r["mutation"] for r in rows} - {"benign"})
    by_class = {
        c: np.array([float(r["r_img"]) for r in rows if r["mutation"] == c]) for c in classes
    }

    raw: list[dict[str, Any]] = []
    point: dict[str, Any] = {}
    for c, scores in by_class.items():
        y = np.concatenate([np.zeros(len(benign)), np.ones(len(scores))])
        point[c] = {
            **_prf(benign, scores, threshold),
            "auroc": float(roc_auc_score(y, np.concatenate([benign, scores]))),
            "n": len(scores),
        }
        for rep in range(reps):
            b = benign[rng.integers(0, len(benign), len(benign))]
            t = scores[rng.integers(0, len(scores), len(scores))]
            raw.append({"rep": rep, "class": c, "threshold": threshold, **_prf(b, t, threshold)})
    sweep = []
    for thr in np.linspace(0.05, 1.0, 20):
        all_t = np.concatenate(list(by_class.values()))
        sweep.append({"threshold": round(float(thr), 3), **_prf(benign, all_t, float(thr))})
    write_raw(out_dir, raw)
    summary: dict[str, Any] = {
        "experiment": "detection_f1",
        "threshold": threshold,
        "benign_rows": len(benign),
        "point_estimates": point,
        "threshold_sweep_all_classes": sweep,
        "bootstrap": {
            f"{c}.{m}": median_iqr([r[m] for r in raw if r["class"] == c])
            for c in classes
            for m in ("precision", "recall", "f1")
        },
    }
    write_summary(out_dir, summary)
    for c, m in point.items():
        line = f"P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} AUROC={m['auroc']:.3f}"
        print(f"  {c:18} {line}")
    return {"dataset": config["dataset"]}
