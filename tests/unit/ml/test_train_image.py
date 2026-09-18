"""Image trainer on a tiny synthetic corpus + the Stage-2 image scorer."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from verigate.common.settings import Settings
from verigate.gateway.stage2.image import ImageScorer, build_image_scorer
from verigate.gateway.stage2.scores import Stage2Scorer, build_scorer
from verigate.ml.data.mutate import CATALOGUE
from verigate.ml.features.image_features import FEATURE_NAMES
from verigate.ml.train import image as trainer

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "releases"


def make_corpus(tmp_path: Path) -> Path:
    """Synthetic 'releases' of a few packages: real fixture binaries with seeded byte noise."""
    data = tmp_path / "data"
    (data / "raw" / "elf").mkdir(parents=True)
    (data / "processed").mkdir()
    base = [(FIXTURES / f"v{v}" / "firmware.bin").read_bytes() for v in ("1.0.0", "1.1.0", "2.0.0")]
    rng = np.random.default_rng(0)
    rows = []
    for pkg in range(4):
        previous = None
        for rel in range(6):
            img = bytearray(base[pkg % 3])  # one lineage per package, small edits per release
            for _ in range(3):  # small benign-looking edits between releases
                off = int(rng.integers(4096, len(img) - 64))
                img[off : off + 8] = rng.integers(0, 256, 8, dtype=np.uint8).tobytes()
            path = data / "raw" / "elf" / f"p{pkg}-r{rel}.elf"
            path.write_bytes(bytes(img))
            rows.append(
                {
                    "release": f"r{rel}",
                    "package": f"p{pkg}",
                    "version": str(rel),
                    "path": str(path),
                    "sha256": "x",
                    "size": len(img),
                    "previous": previous,
                }
            )
            previous = str(path)
    (data / "processed" / "images_index.json").write_text(json.dumps(rows))
    (data / "MANIFEST.sha256").write_text("abc  x\n")
    return data


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_corpus(tmp_path_factory.mktemp("img"))


def test_train_export_calibrate_metrics(corpus: Path, tmp_path: Path) -> None:
    samples = trainer.load_corpus(corpus)
    assert len(samples) == 20  # 4 packages × 5 releases with a predecessor
    benign = trainer.benign_rows(samples)
    tampered = trainer.tampered_rows(samples, 42)
    assert len(tampered) == len(samples) * len(CATALOGUE)
    assert trainer.tampered_rows(samples, 42) == tampered  # seeded
    x_b, x_t = trainer.matrix(benign), trainer.matrix(tampered)
    model = trainer.train_model(x_b, 42, n_estimators=60, max_samples=20)
    onnx_a = trainer.export_onnx(model, x_b.shape[1])
    onnx_b = trainer.export_onnx(
        trainer.train_model(x_b, 42, n_estimators=60, max_samples=20), x_b.shape[1]
    )
    assert onnx_a == onnx_b
    x_all = np.vstack([x_b, x_t])
    sk = trainer.anomaly_scores(model, x_all)
    ox = trainer.onnx_anomaly_scores(onnx_a, x_all, float(model.offset_))
    assert np.max(np.abs(sk - ox)) < 1e-5
    cal = trainer.calibrate(ox[: len(benign)])
    r_b, r_t = cal.r_img(ox[: len(benign)]), cal.r_img(ox[len(benign) :])
    assert r_b.min() >= 0 and r_t.max() <= 1
    assert np.median(r_b) == 0.0
    metrics = trainer.per_class_metrics(r_b, tampered, r_t, 0.5)
    assert set(metrics) == {"benign", *CATALOGUE}
    assert metrics["append"]["auroc"] >= 0.9  # 200 KiB appended to a 320 KiB binary is obvious
    fields = trainer.card_fields(onnx_a, samples, benign, tampered, 42, cal, metrics, 1e-7, "sha")
    trainer.write_card(tmp_path / "card.md", fields)
    text = (tmp_path / "card.md").read_text()
    assert "image_anomaly.onnx" in text and "`append`" in text and "n_segments" in text


def test_image_scorer_and_composition(
    corpus: Path, tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    samples = trainer.load_corpus(corpus)
    x_b = trainer.matrix(trainer.benign_rows(samples))
    model = trainer.train_model(x_b, 42, n_estimators=60, max_samples=20)
    onnx_bytes = trainer.export_onnx(model, x_b.shape[1])
    cal = trainer.calibrate(trainer.onnx_anomaly_scores(onnx_bytes, x_b, float(model.offset_)))
    models = tmp_path / "models"
    models.mkdir()
    (models / "image_anomaly.onnx").write_bytes(onnx_bytes)
    (models / "image_anomaly.context.json").write_text(
        json.dumps(
            {
                "offset": float(model.offset_),
                "s_median": cal.s_median,
                "s_p99": cal.s_p99,
                "feature_names": list(FEATURE_NAMES),
                "background": [float(v) for v in np.median(x_b, axis=0)],
            }
        )
    )
    cfg = settings.model_copy(update={"models_dir": models, "image_model": "image_anomaly.onnx"})
    scorer = build_image_scorer(cfg)
    assert isinstance(scorer, ImageScorer)
    fw, prev = samples[0].image, samples[0].previous
    clean = scorer.score(fw, prev)
    assert clean.model_hash.startswith("0x") and len(clean.top_features) == 3
    assert scorer.score(fw, prev) is clean  # cached
    appended = scorer.score(CATALOGUE["append"].apply(fw, 1), prev)
    assert appended.r_img_bp > clean.r_img_bp and appended.features["appended_kb"] == 200
    without_previous = scorer.score(fw, None)
    assert without_previous.features["changed_chunks_pct"] == 0
    composed = build_scorer(cfg)
    assert isinstance(composed, Stage2Scorer) and composed.sbom is None
    scores = composed.score(fw, b"{}", prev)
    assert scores.r_img_bp == clean.r_img_bp and scores.r_sbom_bp == 0
    assert scores.model_hashes == (clean.model_hash,) and scores.features["img"]["previous"] is True
    assert build_image_scorer(settings) is None
