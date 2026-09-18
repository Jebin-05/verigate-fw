"""Attack: policy tampering — a rogue operator tries to lower the thresholds.

Policy lives on-chain (Novelty 3). A funded account without ``ADMIN_ROLE`` calls
``PolicyContract.setPolicy`` with τ_approve = τ_reject − 1 ≈ "approve everything": the call
reverts with ``AccessControlUnauthorizedAccount`` and the policy version the gateway reads is
unchanged. Even the legitimate path is auditable: every change is a ``PolicyChanged`` event with
the old and new policy and the sender, which the report lists.
"""

from __future__ import annotations

from typing import Any

from verigate.attacks.common import AttackContext, AttackReport
from verigate.common.errors import ChainError

NAME = "policy-tamper"
EXPECTED = "BLOCKED"


def run(ctx: AttackContext) -> AttackReport:
    """Attempt the change from a non-admin account; show the policy and audit log unchanged."""
    before = ctx.get("/policy")["policy"]
    rogue = ctx.funded_account()
    error: str | None = None
    try:
        ctx.chain.send(
            ctx.chain.policy.functions.setPolicy(
                before["w_sbom"], before["w_img"], before["w_rep"], 9998, 9999
            ),
            rogue,
        )
    except ChainError as exc:
        error = str(exc)
    after = ctx.get("/policy")["policy"]
    events = ctx.chain.policy.events.PolicyChanged().get_logs(from_block=0)
    audit: list[dict[str, Any]] = [
        {
            "version": int(e["args"]["version"]),
            "changedBy": e["args"]["changedBy"],
            "block": int(e["blockNumber"]),
            "tauApprove": int(e["args"]["newPolicy"]["tauApprove"]),
            "tauReject": int(e["args"]["newPolicy"]["tauReject"]),
        }
        for e in events
    ]
    report = AttackReport(NAME, EXPECTED, device_id=None)
    blocked = error is not None and after["version"] == before["version"]
    report.observed = "BLOCKED" if blocked else "CHANGED"
    report.reason = error or "setPolicy succeeded from a non-admin account"
    report.details = {
        "rogue": rogue.address,
        "attempted": {"tauApprove": 9998, "tauReject": 9999},
        "policyVersionBefore": before["version"],
        "policyVersionAfter": after["version"],
        "auditLog": audit,
    }
    return report
