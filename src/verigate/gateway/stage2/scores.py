"""Stage-2 risk scores for a release (Guide §6). Until P5/P6 ship models this is the null scorer.

The interface is fixed now so the policy engine, verdict record and dashboard do not change when
the ONNX models land: ``score(bundle) -> Stage2Scores`` with basis-point scores, the quantised
feature vector (what ``featureHash`` commits to) and the model hashes that produced them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from verigate.common.settings import Settings
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

    @property
    def feature_hash(self) -> str:
        """``0x`` + SHA-256 of the canonical quantised feature vector."""
        return feature_hash(self.features)


class NullScorer:
    """No models configured: zero risk from Stage 2, the decision rests on Stage 1 + reputation."""

    def score(self, firmware: bytes, sbom: bytes) -> Stage2Scores:  # noqa: ARG002
        """Return zero scores with an empty feature vector."""
        return Stage2Scores(r_sbom_bp=0, r_img_bp=0)


class Stage2Scorer:
    """Composes the configured model scorers (SBOM in P5, image in P6)."""

    def __init__(self, sbom: SbomScorer | None) -> None:
        self.sbom = sbom

    def score(self, firmware: bytes, sbom: bytes) -> Stage2Scores:  # noqa: ARG002 — image scorer lands in P6
        """Run every configured model; the feature vector nests one dict per model."""
        features: dict[str, Any] = {}
        hashes: list[str] = []
        r_sbom = 0
        if self.sbom is not None:
            result = self.sbom.score(sbom)
            r_sbom = result.r_sbom_bp
            features["sbom"] = {
                **result.features,
                "model": result.model_hash,
                "top3": [[name, value] for name, value in result.top_features],
            }
            hashes.append(result.model_hash)
        return Stage2Scores(
            r_sbom_bp=r_sbom, r_img_bp=0, features=features, model_hashes=tuple(hashes)
        )


def build_scorer(settings: Settings) -> NullScorer | Stage2Scorer:
    """The scorer for these settings (``NullScorer`` when no model is configured)."""
    sbom = build_sbom_scorer(settings)
    return Stage2Scorer(sbom) if sbom is not None else NullScorer()
