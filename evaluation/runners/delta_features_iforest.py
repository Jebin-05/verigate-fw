"""Negative result: does the IsolationForest learn the release delta if it is given as features?

Same corpus, seeds, hyper-parameters and calibration as the shipped image model; the only change
is the feature set: ``changed_chunks_pct`` is replaced by three release-delta features computed by
Stage-1 check #9's own function (changed-block percentage, number of changed regions, reordered
runs). Recall at the operating point and AUROC per class, no-op mutations excluded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
from common import ROOT, write_raw, write_summary
from sklearn.metrics import roc_auc_score

from verigate.gateway.stage1.delta import release_delta
from verigate.ml.data.mutate import CATALOGUE
from verigate.ml.features.image_features import FEATURE_NAMES, image_features
from verigate.ml.train import image as trainer

DELTA_NAMES = ("changed_blocks_pct", "changed_regions", "reordered_runs")


def _row(image: bytes, previous: bytes) -> dict[str, float]:
    d = release_delta(image, previous)
    return {
        **image_features(image, previous),
        "changed_blocks_pct": round(100 * d.changed_blocks / max(d.blocks, 1)),
        "changed_regions": len(d.regions),
        "reordered_runs": d.reordered,
    }


def run(config: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Train both feature sets on benign rows only; score every mutation class."""
    seed = int(config.get("seed", 42))
    threshold = float(config.get("threshold", 0.5))
    samples = trainer.load_corpus(ROOT / "data")
    benign = [_row(s.image, s.previous) for s in samples]
    tampered: list[tuple[str, dict[str, float]]] = []
    for i, s in enumerate(samples):
        for j, (name, mutation) in enumerate(CATALOGUE.items()):
            extra = {"old_image": s.previous} if name == "downgrade-relabel" else {}
            mutated = mutation.apply(s.image, seed * 100_003 + i * 7 + j, **extra)
            if mutated != s.image:
                tampered.append((name, _row(mutated, s.previous)))
    sets = {
        "shipped": list(FEATURE_NAMES),
        "with_delta": [n for n in FEATURE_NAMES if n != "changed_chunks_pct"] + list(DELTA_NAMES),
    }
    raw: list[dict[str, Any]] = []
    table: dict[str, dict[str, Any]] = {}
    for label, names in sets.items():
        xb = np.array([[r[n] for n in names] for r in benign], dtype=np.float32)
        model = trainer.train_model(xb, seed)
        cal = trainer.calibrate(trainer.anomaly_scores(model, xb))
        rb = cal.r_img(trainer.anomaly_scores(model, xb))
        table[label] = {"benign_fpr": round(float(np.mean(rb >= threshold)), 4)}
        for name in CATALOGUE:
            rows = [r for c, r in tampered if c == name]
            x = np.array([[r[n] for n in names] for r in rows], dtype=np.float32)
            rt = cal.r_img(trainer.anomaly_scores(model, x))
            y = np.r_[np.zeros(len(rb)), np.ones(len(rt))]
            table[label][name] = {
                "n": len(rt),
                "recall": round(float(np.mean(rt >= threshold)), 4),
                "auroc": round(float(roc_auc_score(y, np.r_[rb, rt])), 4),
            }
            raw += [{"features": label, "class": name, "r_img": round(float(v), 4)} for v in rt]
    write_raw(out_dir, raw)
    write_summary(
        out_dir,
        {"experiment": "delta_features_iforest", "threshold": threshold, "seed": seed, **table},
    )
    for label, cells in table.items():
        print(f"  {label}: benign FPR {cells['benign_fpr']}")
        for name in CATALOGUE:
            c = cells[name]
            print(f"    {name:18} n={c['n']:3} recall={c['recall']:.3f} AUROC={c['auroc']:.3f}")
    return {}
