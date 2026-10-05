"""Stage-1 check #9 (release delta) on the OpenWrt corpus, alone and together with the image model.

Every benign release is compared with its predecessor; every catalogue mutation is applied with
the trainer's seeds (``ml/train/image.py``) and compared with the same predecessor. Mutations
that leave the image byte-identical (``downgrade-relabel`` when the predecessor *is* the image,
``section-swap`` of two identical regions) are not tampering and are counted separately, never
scored. Pairs are split by regime: *unchanged base* (the benign release is byte-identical to its
predecessor, i.e. the package was not rebuilt) and *rebuild*.
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Any

import numpy as np
from common import ROOT, write_raw, write_summary
from sklearn.metrics import roc_auc_score

from verigate.gateway.stage1.delta import PATCH_LIMIT_BLOCKS, release_delta
from verigate.gateway.stage2.image import ImageScorer
from verigate.ml.data.mutate import CATALOGUE
from verigate.ml.features.image_features import as_vector, image_features
from verigate.ml.train.image import load_corpus


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    """95 % Wilson score interval for k successes in n trials."""
    if n == 0:
        return [0.0, 0.0]
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def run(config: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Flag rate of check #9, the image model (r_img >= threshold) and either, per class."""
    seed = int(config.get("seed", 42))
    threshold = float(config.get("threshold", 0.5))
    model_path = ROOT / str(config["image_model"])
    scorer = ImageScorer(
        model_path, json.loads(model_path.with_suffix(".context.json").read_text())
    )
    samples = load_corpus(ROOT / "data")

    raw: list[dict[str, Any]] = []
    timings: list[float] = []
    noops: dict[str, int] = {}

    def score(name: str, regime: str, image: bytes, previous: bytes) -> None:
        start = time.perf_counter()
        delta = release_delta(image, previous)
        timings.append((time.perf_counter() - start) * 1000)
        x = np.array([as_vector(image_features(image, previous))], dtype=np.float32)
        r_img = float(scorer.predict(x)[0])
        raw.append(
            {
                "class": name,
                "regime": regime,
                "changed_blocks": delta.changed_blocks,
                "reordered": delta.reordered,
                "delta_flag": int(delta.patched),
                "r_img": round(r_img, 4),
                "model_flag": int(r_img >= threshold),
            }
        )

    for i, s in enumerate(samples):
        regime = "unchanged-base" if s.image == s.previous else "rebuild"
        score("benign", regime, s.image, s.previous)
        for j, (name, mutation) in enumerate(CATALOGUE.items()):
            extra = {"old_image": s.previous} if name == "downgrade-relabel" else {}
            mutated = mutation.apply(s.image, seed * 100_003 + i * 7 + j, **extra)
            if mutated == s.image:
                noops[name] = noops.get(name, 0) + 1
                continue
            score(name, regime, mutated, s.previous)

    table: dict[str, Any] = {}
    for name in ["benign", *CATALOGUE]:
        for regime in ("all", "unchanged-base", "rebuild"):
            rows = [r for r in raw if r["class"] == name and regime in ("all", r["regime"])]
            if not rows:
                continue
            n = len(rows)
            cell: dict[str, Any] = {"n": n}
            for key, flag in (
                ("check9", lambda r: r["delta_flag"]),
                ("model", lambda r: r["model_flag"]),
                ("either", lambda r: r["delta_flag"] or r["model_flag"]),
            ):
                k = sum(1 for r in rows if flag(r))
                cell[key] = {"flagged": k, "rate": round(k / n, 4), "wilson95": wilson(k, n)}
            benign_r = [
                r["r_img"] for r in raw if r["class"] == "benign" and regime in ("all", r["regime"])
            ]
            if name != "benign":
                y = [0] * len(benign_r) + [1] * n
                cell["model_auroc"] = round(
                    float(roc_auc_score(y, benign_r + [r["r_img"] for r in rows])), 4
                )
            table[f"{name}/{regime}"] = cell

    rebuild_changes = [
        r["changed_blocks"] for r in raw if r["class"] == "benign" and r["regime"] == "rebuild"
    ]
    patch_changes = [r["changed_blocks"] for r in raw if r["class"] == "byte-patch"]
    write_raw(out_dir, raw)
    summary: dict[str, Any] = {
        "experiment": "release_delta",
        "patch_limit_blocks": PATCH_LIMIT_BLOCKS,
        "image_model": str(config["image_model"]),
        "image_model_hash": scorer.model_hash,
        "threshold": threshold,
        "benign_pairs": sum(1 for r in raw if r["class"] == "benign"),
        "noop_mutations_excluded": noops,
        "margin": {
            "smallest_benign_rebuild_changed_blocks": min(rebuild_changes),
            "largest_byte_patch_changed_blocks_unchanged_base": max(
                r["changed_blocks"]
                for r in raw
                if r["class"] == "byte-patch" and r["regime"] == "unchanged-base"
            ),
            "byte_patch_changed_blocks_median": float(np.median(patch_changes)),
        },
        "delta_ms": {
            "median": round(float(np.median(timings)), 2),
            "p95": round(float(np.percentile(timings, 95)), 2),
            "max": round(float(np.max(timings)), 2),
        },
        "table": table,
    }
    write_summary(out_dir, summary)
    for key, cell in table.items():
        print(
            f"  {key:32} n={cell['n']:3}  #9={cell['check9']['rate']:.3f}  "
            f"model={cell['model']['rate']:.3f}  either={cell['either']['rate']:.3f}"
        )
    print(f"  noop mutations excluded: {noops}")
    return {"image_model_hash": scorer.model_hash}
