"""e2e: the 'freeze' scenario ends in DEFER with Stage-1 check 'expiry' named."""

from __future__ import annotations

import pytest

from conftest import verdict_log_entry
from verigate.attacks import freeze
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_freeze(ctx: AttackContext, gateway_url: str) -> None:
    report = freeze.run(ctx)
    assert report.observed == "DEFER", report.to_dict()
    assert report.check == "expiry"
    assert report.passed
    assert report.details["verdictBeforeExpiry"] == "APPROVE"
    entry = verdict_log_entry(gateway_url, report)
    assert entry["verdict"] == "DEFER"
    assert entry["stage1"]["failed"] == "expiry"
