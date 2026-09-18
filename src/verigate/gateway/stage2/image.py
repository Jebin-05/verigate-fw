"""Stage-2 image anomaly inference (P6-04): firmware (+ previous version) → ONNX → ``r_img``.

ONNX-only at runtime; the model hash is the ``modelHash`` on the verdict. Calibration constants
come from ``<model>.context.json`` written by the trainer (see ``ml/train/image.py``).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort

from verigate.common.logging import get_logger
from verigate.ml.features.image_features import FEATURE_NAMES, as_vector, image_features

log = get_logger(__name__)


@dataclass(frozen=True)
class ImageScore:
    """Output of one inference."""

    r_img_bp: int
    features: dict[str, int]
    model_hash: str
    top_features: tuple[tuple[str, int], ...]
    anomaly_score: float


class ImageScorer:
    """ONNX IsolationForest with the trainer's calibration."""

    def __init__(self, model_path: Path, context: dict[str, Any]) -> None:
        self.model_bytes = model_path.read_bytes()
        self.model_hash = "0x" + hashlib.sha256(self.model_bytes).hexdigest()
        self.session = ort.InferenceSession(self.model_bytes, providers=["CPUExecutionProvider"])
        self.input_name = self.session.get_inputs()[0].name
        self.offset = float(context["offset"])
        self.s_median = float(context["s_median"])
        self.s_p99 = float(context["s_p99"])
        self.background = np.array([context["background"]], dtype=np.float32)
        self._cache: dict[str, ImageScore] = {}
        log.info("stage2.image_model_loaded", model=str(model_path), model_hash=self.model_hash)

    def anomaly(self, x: np.ndarray) -> np.ndarray:
        """sklearn-equivalent anomaly score (higher = more anomalous)."""
        outputs = [o.name for o in self.session.get_outputs() if o.name == "scores"]
        decision = self.session.run(outputs, {self.input_name: x.astype(np.float32)})[0]
        return -(np.asarray(decision, dtype=np.float64).reshape(-1) + self.offset)

    def predict(self, x: np.ndarray) -> np.ndarray:
        """``r_img`` in [0, 1] (calibrated: benign median → 0, benign p99 → 0.5)."""
        scale = max(self.s_p99 - self.s_median, 1e-9)
        return np.clip((self.anomaly(x) - self.s_median) / scale * 0.5, 0.0, 1.0)

    def _shap_top3(self, x: np.ndarray) -> tuple[tuple[str, int], ...]:
        import shap  # noqa: PLC0415

        explainer = shap.KernelExplainer(self.predict, self.background)
        values = np.asarray(explainer.shap_values(x, nsamples=200, silent=True)).reshape(-1)
        order = np.argsort(-np.abs(values))[:3]
        return tuple((FEATURE_NAMES[i], round(float(values[i]) * 10_000)) for i in order)

    def score(self, firmware: bytes, previous: bytes | None) -> ImageScore:
        """Score an image (cached by content hash of image + previous)."""
        key = hashlib.sha256(firmware + b"|" + (previous or b"")).hexdigest()
        if key in self._cache:
            return self._cache[key]
        features = image_features(firmware, previous)
        x = np.array([as_vector(features)], dtype=np.float32)
        r = float(self.predict(x)[0])
        result = ImageScore(
            r_img_bp=round(r * 10_000),
            features=features,
            model_hash=self.model_hash,
            top_features=self._shap_top3(x),
            anomaly_score=float(self.anomaly(x)[0]),
        )
        self._cache[key] = result
        log.info(
            "stage2.image",
            r_img_bp=result.r_img_bp,
            anomaly=round(result.anomaly_score, 4),
            top=list(result.top_features),
        )
        return result


def build_image_scorer(settings: Any) -> ImageScorer | None:  # noqa: ANN401 — Settings
    """Wire the scorer from settings; ``None`` when ``IMAGE_MODEL`` is unset."""
    if not settings.image_model:
        return None
    model_path = settings.models_dir / settings.image_model
    context = json.loads(model_path.with_suffix(".context.json").read_text())
    return ImageScorer(model_path, context)
