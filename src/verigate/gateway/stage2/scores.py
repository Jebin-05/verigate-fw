"""Stage-2 risk scores for a release (Guide §6): the composition point for the model scorers.

``score(firmware, sbom, previous) -> Stage2Scores`` with basis-point scores, the quantised
feature vector (what ``featureHash`` commits to, one nested dict per model) and the model hashes
that produced them. Without any configured model the :class:`NullScorer` returns zero risk and
the decision rests on Stage 1 plus reputation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from verigate.common.settings import Settings
from verigate.gateway.stage2.image import ImageScorer, build_image_scorer
from verigate.gateway.stage2.sbom import SbomScorer, build_sbom_scorer
from verigate.gateway.verdicts.record import feature_hash


@dataclass(frozen=True)
class Stage2Scores:
    """Scores in basis points plus what produced them."""

    r_sbom_bp: int
    r_img_bp: int
    features: dict[str, Any] = field(default_factory=dict)
    model_hashes: tuple[str, ...] = ()
    rationale_cid: str | None = None
    expected_exploited: float | None = None
    cves: int | None = None

    def top(self, model: str) -> list[list[Any]]:
        """The ``[feature, shap_bp]`` attributions recorded for ``model`` (``sbom`` / ``img``)."""
        block = self.features.get(model, {})
        top3: list[list[Any]] = block.get("top3", []) if isinstance(block, dict) else []
        return top3

    @property
    def feature_hash(self) -> str:
        """``0x`` + SHA-256 of the canonical quantised feature vector."""
        return feature_hash(self.features)


class Scorer(Protocol):
    """What the service calls; implemented by ``NullScorer`` and ``Stage2Scorer``."""

    def score(self, firmware: bytes, sbom: bytes, previous: bytes | None = None) -> Stage2Scores:
        """Score one release."""


class NullScorer:
    """No models configured: zero risk from Stage 2, the decision rests on Stage 1 + reputation."""

    def score(
        self,
        firmware: bytes,  # noqa: ARG002
        sbom: bytes,  # noqa: ARG002
        previous: bytes | None = None,  # noqa: ARG002
    ) -> Stage2Scores:
        """Return zero scores with an empty feature vector."""
        return Stage2Scores(r_sbom_bp=0, r_img_bp=0)


class Stage2Scorer:
    """Composes the configured model scorers (SBOM in P5, image in P6)."""

    def __init__(self, sbom: SbomScorer | None, image: ImageScorer | None = None) -> None:
        self.sbom = sbom
        self.image = image

    def score(self, firmware: bytes, sbom: bytes, previous: bytes | None = None) -> Stage2Scores:
        """Run every configured model; the feature vector nests one dict per model."""
        features: dict[str, Any] = {}
        hashes: list[str] = []
        r_sbom = r_img = 0
        expected: float | None = None
        cves: int | None = None
        if self.sbom is not None:
            result = self.sbom.score(sbom)
            r_sbom = result.r_sbom_bp
            expected, cves = result.expected_exploited, result.cves
            features["sbom"] = {
                **result.features,
                "model": result.model_hash,
                "top3": [[name, value] for name, value in result.top_features],
            }
            hashes.append(result.model_hash)
        if self.image is not None:
            img = self.image.score(firmware, previous)
            r_img = img.r_img_bp
            features["img"] = {
                **img.features,
                "model": img.model_hash,
                "top3": [[name, value] for name, value in img.top_features],
                "previous": previous is not None,
            }
            hashes.append(img.model_hash)
        return Stage2Scores(
            r_sbom_bp=r_sbom,
            r_img_bp=r_img,
            features=features,
            model_hashes=tuple(hashes),
            expected_exploited=expected,
            cves=cves,
        )


def build_scorer(settings: Settings) -> Scorer:
    """The scorer for these settings (``NullScorer`` when no model is configured)."""
    sbom = build_sbom_scorer(settings)
    image = build_image_scorer(settings)
    if sbom is None and image is None:
        return NullScorer()
    return Stage2Scorer(sbom, image)


def find_model_file(models_dir: Path, model_hash: str) -> Path | None:
    """The ``.onnx`` under ``models_dir`` (recursively) whose SHA-256 is ``model_hash``."""
    want = model_hash.lower().removeprefix("0x")
    for path in sorted(models_dir.rglob("*.onnx")):
        if hashlib.sha256(path.read_bytes()).hexdigest() == want:
            return path
    return None


def swap_model(scorer: Scorer, settings: Settings, revoked: str, successor: str) -> Scorer | None:
    """A scorer with the slot that ran ``revoked`` replaced by ``successor`` (P6-06).

    The successor is located by hash under ``MODELS_DIR`` — the gateway never trusts a file
    name, only bytes whose hash the registry names. ``None`` when the revoked hash is not in use
    or no file with the successor's hash exists (the gate then stays fail-closed).
    """
    if not isinstance(scorer, Stage2Scorer):
        return None
    path = find_model_file(settings.models_dir, successor)
    if path is None:
        return None
    rel = str(path.relative_to(settings.models_dir))
    if scorer.sbom is not None and scorer.sbom.model_hash.lower() == revoked.lower():
        sbom = build_sbom_scorer(settings.model_copy(update={"sbom_model": rel}))
        return Stage2Scorer(sbom, scorer.image)
    if scorer.image is not None and scorer.image.model_hash.lower() == revoked.lower():
        image = build_image_scorer(settings.model_copy(update={"image_model": rel}))
        return Stage2Scorer(scorer.sbom, image)
    return None
