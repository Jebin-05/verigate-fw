"""e2e: 'policy-tamper' — a non-admin cannot change the policy; the audit log shows every change."""

from __future__ import annotations

import pytest

from verigate.attacks import policy_tamper
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_policy_tamper(ctx: AttackContext) -> None:
    report = policy_tamper.run(ctx)
    assert report.observed == "BLOCKED", report.to_dict()
    assert report.passed and "AccessControlUnauthorizedAccount" in (report.reason or "")
    d = report.details
    assert d["policyVersionBefore"] == d["policyVersionAfter"]
    assert d["auditLog"] and d["auditLog"][-1]["version"] == d["policyVersionAfter"]
    assert all(e["changedBy"] != d["rogue"] for e in d["auditLog"])
