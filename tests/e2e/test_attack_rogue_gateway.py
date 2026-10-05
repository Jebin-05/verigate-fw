"""e2e: 'rogue-gateway' — a compromised gateway pushes updates; the device checks the chain."""

from __future__ import annotations

import pytest

from verigate.attacks import rogue_gateway
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_rogue_gateway(ctx: AttackContext) -> None:
    report = rogue_gateway.run(ctx)
    pushes = report.details["pushes"]
    assert report.observed == "REFUSED" and report.passed, report.to_dict()
    assert "not registered" in pushes["forged-unregistered"]["refusal"]
    assert "withdrawn" in pushes["withdrawn-release"]["refusal"]
    assert "publisher not active" in pushes["revoked-publisher"]["refusal"]
    assert pushes["control-genuine"]["installed"]  # the gateway's (attacker's) key was ignored
