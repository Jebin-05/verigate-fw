"""Stage-2 risk scores for a release (Guide §6). Until P5/P6 ship models this is the null scorer.

The interface is fixed now so the policy engine, verdict record and dashboard do not change when
the ONNX models land: ``score(bundle) -> Stage2Scores`` with basis-point scores, the quantised
feature vector (what ``featureHash`` commits to) and the model hashes that produced them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from verigate.gateway.verdicts.record import feature_hash


@dataclass(frozen=True)
class Stage2Scores:
    """Scores in basis points plus what produced them."""

    r_sbom_bp: int
    r_img_bp: int
    features: dict[str, int] = field(default_factory=dict)
    model_hashes: tuple[str, ...] = ()
    rationale_cid: str | None = None

    @property
    def feature_hash(self) -> str:
        """``0x`` + SHA-256 of the canonical quantised feature vector."""
        return feature_hash(self.features)


class NullScorer:
    """No models registered yet: zero risk from Stage 2, decision rests on Stage 1 + reputation."""

    def score(self, firmware: bytes, sbom: bytes) -> Stage2Scores:  # noqa: ARG002
        """Return zero scores with an empty feature vector."""
        return Stage2Scores(r_sbom_bp=0, r_img_bp=0)
