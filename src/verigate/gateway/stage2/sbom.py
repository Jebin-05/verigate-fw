"""Stage-2 SBOM risk inference (P5-06): SBOM → features → ONNX → ``r_sbom`` + SHAP top-3.

Runtime is ONNX-only (no pickles): the model file's SHA-256 is the ``modelHash`` that goes on
the verdict. Vulnerability lookups go through the same cached clients the trainer used, pinned
to one EPSS snapshot date (``STAGE2_EPSS_DATE``) so a score is reproducible from
``featureHash``. Results are cached per SBOM hash — Stage 2 runs once per release.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort

from verigate.common.errors import VerigateError
from verigate.common.logging import get_logger
from verigate.ml.data.sbom import components_of
from verigate.ml.features.sbom_features import (
    FEATURE_NAMES,
    CorpusContext,
    as_vector,
    sbom_features,
)
from verigate.ml.train.sbom import R_SCALE, VulnLookup, expected_from_ratio, to_r_sbom
from verigate.ml.vulndb.cache import OfflineMissError

log = get_logger(__name__)


@dataclass(frozen=True)
class SbomScore:
    """Output of one inference."""

    r_sbom_bp: int
    features: dict[str, int]
    model_hash: str
    top_features: tuple[tuple[str, int], ...]  # (feature, shap value in bp), |value| descending
    cves: int
    expected_exploited: float = 0.0


def load_context(path: Path, as_of: date) -> CorpusContext:
    """Read ``<model>.context.json`` written by the trainer (latest versions, first-seen dates)."""
    doc = json.loads(path.read_text())
    return CorpusContext(
        as_of,
        dict(doc["latest_version"]),
        {
            (k.rsplit("@", 1)[0], k.rsplit("@", 1)[1]): date.fromisoformat(v)
            for k, v in doc["first_seen"].items()
        },
    )


class SbomScorer:
    """ONNX SBOM risk model plus the vulnerability lookups it needs."""

    def __init__(
        self,
        model_path: Path,
        lookup: VulnLookup,
        context: CorpusContext,
        background: list[float],
        r_scale: float = R_SCALE,
    ) -> None:
        self.model_bytes = model_path.read_bytes()
        self.model_hash = "0x" + hashlib.sha256(self.model_bytes).hexdigest()
        self.session = ort.InferenceSession(self.model_bytes, providers=["CPUExecutionProvider"])
        self.input_name = self.session.get_inputs()[0].name
        self.lookup = lookup
        self.context = context
        self.background = np.array([background], dtype=np.float32)
        self.r_scale = r_scale
        self._cache: dict[str, SbomScore] = {}
        log.info("stage2.sbom_model_loaded", model=str(model_path), model_hash=self.model_hash)

    def expected(self, x: np.ndarray) -> np.ndarray:
        """Expected exploited-CVE count: T0 exposure × the model's growth ratio (≥ 0)."""
        out = self.session.run(None, {self.input_name: x.astype(np.float32)})[0]
        return expected_from_ratio(x, np.asarray(out, dtype=np.float64).reshape(-1))

    def predict(self, x: np.ndarray) -> np.ndarray:
        """``r_sbom`` in [0, 1): ``1 − exp(−expected / r_scale)``."""
        return to_r_sbom(self.expected(x), self.r_scale)

    def _shap_top3(self, x: np.ndarray) -> tuple[tuple[str, int], ...]:
        import shap  # noqa: PLC0415 — heavy import, only when a model is configured

        explainer = shap.KernelExplainer(self.predict, self.background)
        values = np.asarray(explainer.shap_values(x, nsamples=200, silent=True)).reshape(-1)
        order = np.argsort(-np.abs(values))[:3]
        return tuple((FEATURE_NAMES[i], round(float(values[i]) * 10_000)) for i in order)

    def score(self, sbom_bytes: bytes) -> SbomScore:
        """Score a CycloneDX SBOM (cached by content hash).

        Raises:
            VerigateError: If the SBOM is not JSON, or vulnerability data is missing offline.
        """
        key = hashlib.sha256(sbom_bytes).hexdigest()
        if key in self._cache:
            return self._cache[key]
        try:
            components = components_of(json.loads(sbom_bytes))
        except (ValueError, TypeError) as exc:
            raise VerigateError(f"SBOM is not valid CycloneDX JSON: {exc}") from exc
        try:
            records = self.lookup.records(components)
        except OfflineMissError as exc:
            raise VerigateError(str(exc)) from exc
        features = sbom_features(components, records, self.context)
        x = np.array([as_vector(features)], dtype=np.float32)
        expected = float(self.expected(x)[0])
        r = float(to_r_sbom(expected, self.r_scale))
        result = SbomScore(
            r_sbom_bp=round(r * 10_000),
            features=features,
            model_hash=self.model_hash,
            top_features=self._shap_top3(x),
            cves=features["n_cves"],
            expected_exploited=expected,
        )
        self._cache[key] = result
        log.info(
            "stage2.sbom",
            r_sbom_bp=result.r_sbom_bp,
            cves=result.cves,
            top=list(result.top_features),
        )
        return result


def build_sbom_scorer(settings: Any) -> SbomScorer | None:  # noqa: ANN401 — Settings (avoid import cycle in type)
    """Wire the scorer from settings; ``None`` when ``SBOM_MODEL`` is unset."""
    if not settings.sbom_model:
        return None
    from verigate.ml.vulndb.cache import DiskCache  # noqa: PLC0415
    from verigate.ml.vulndb.epss import EpssSnapshot  # noqa: PLC0415
    from verigate.ml.vulndb.kev import KevCatalogue  # noqa: PLC0415
    from verigate.ml.vulndb.osv import OsvClient  # noqa: PLC0415

    model_path = settings.models_dir / settings.sbom_model
    context_path = model_path.with_suffix(".context.json")
    cache = DiskCache(settings.vuln_cache_dir, offline=settings.vuln_cache_only)
    as_of = date.fromisoformat(settings.stage2_epss_date)
    epss = EpssSnapshot.load(settings.epss_url, as_of, cache)
    kev = KevCatalogue.load(settings.kev_url, cache)
    lookup = VulnLookup(OsvClient(settings.osv_api, cache), epss, kev, as_of)
    doc = json.loads(context_path.read_text())
    # ages are measured against the same fixed snapshot date, so a score is reproducible later
    context = load_context(context_path, as_of)
    return SbomScorer(
        model_path, lookup, context, doc["background"], float(doc.get("r_scale", R_SCALE))
    )
