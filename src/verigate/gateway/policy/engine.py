"""Policy engine (Guide §7): on-chain weights and thresholds, off-chain decision.

``R = w_sbom·r_sbom + w_img·r_img + w_rep·(1 − reputation)`` with every term in basis points
(10 000 = 1.0), so the computation is exact integer arithmetic and reproducible bit-for-bit.

* ``R <  tau_approve`` → APPROVE
* ``R >= tau_reject``  → REJECT
* otherwise            → DEFER
* any dependency error (policy unreadable, score missing) → DEFER — never APPROVE by default.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from verigate.common.chain import ChainClient, PolicyRecord
from verigate.common.errors import ChainError
from verigate.common.logging import get_logger
from verigate.gateway.verdicts.types import Verdict

log = get_logger(__name__)

BASIS = 10_000


@dataclass(frozen=True)
class Decision:
    """Output of :func:`decide`."""

    r_bp: int
    verdict: Verdict
    policy_version: int
    reason: str


def decide(
    policy: PolicyRecord | None,
    r_sbom_bp: int | None,
    r_img_bp: int | None,
    reputation_bp: int | None,
) -> Decision:
    """Pure decision. ``None`` anywhere means a dependency failed → DEFER."""
    if policy is None:
        return Decision(BASIS, Verdict.DEFER, 0, "policy unavailable")
    if r_sbom_bp is None or r_img_bp is None or reputation_bp is None:
        missing = [
            n
            for n, v in (("r_sbom", r_sbom_bp), ("r_img", r_img_bp), ("reputation", reputation_bp))
            if v is None
        ]
        return Decision(BASIS, Verdict.DEFER, policy.version, "missing " + ", ".join(missing))
    for name, value in (("r_sbom", r_sbom_bp), ("r_img", r_img_bp), ("reputation", reputation_bp)):
        if not 0 <= value <= BASIS:
            return Decision(BASIS, Verdict.DEFER, policy.version, f"{name} out of range: {value}")
    weighted = (
        policy.w_sbom * r_sbom_bp + policy.w_img * r_img_bp + policy.w_rep * (BASIS - reputation_bp)
    )
    r_bp = (weighted + BASIS // 2) // BASIS  # round half up to the nearest basis point
    if r_bp < policy.tau_approve:
        verdict = Verdict.APPROVE
    elif r_bp >= policy.tau_reject:
        verdict = Verdict.REJECT
    else:
        verdict = Verdict.DEFER
    return Decision(
        r_bp,
        verdict,
        policy.version,
        f"R={r_bp / BASIS:.4f} vs tau_approve={policy.tau_approve / BASIS:.2f}, "
        f"tau_reject={policy.tau_reject / BASIS:.2f}",
    )


class PolicyEngine:
    """Reads ``PolicyContract.current()`` once per block and decides with :func:`decide`."""

    def __init__(self, chain: ChainClient) -> None:
        self.chain = chain
        self._cached: tuple[int, PolicyRecord] | None = None

    def policy(self) -> PolicyRecord | None:
        """The policy for the current block, or ``None`` if the chain is unreachable."""
        try:
            block = self.chain.block_number()
            if self._cached is None or self._cached[0] != block:
                self._cached = (block, self.chain.get_policy())
            return self._cached[1]
        except ChainError as exc:
            log.warning("policy.unavailable", error=str(exc))
            return None

    async def decide(
        self, r_sbom_bp: int | None, r_img_bp: int | None, reputation_bp: int | None
    ) -> Decision:
        """Fetch the policy (off the event loop) and decide."""
        policy = await asyncio.to_thread(self.policy)
        decision = decide(policy, r_sbom_bp, r_img_bp, reputation_bp)
        log.info(
            "policy.decision",
            verdict=decision.verdict.value,
            r_bp=decision.r_bp,
            policy_version=decision.policy_version,
            reason=decision.reason,
        )
        return decision
