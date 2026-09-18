"""e2e: the 'stolen_key' scenario ends in REJECT with Stage-1 check 'publisher_active' named."""

from __future__ import annotations

import pytest

from conftest import verdict_log_entry
from verigate.attacks import stolen_key
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_stolen_key(ctx: AttackContext, gateway_url: str) -> None:
    report = stolen_key.run(ctx)
    assert report.observed == "REJECT", report.to_dict()
    assert report.check == "publisher_active"
    assert report.passed
    assert report.details["verdictBeforeRevocation"] == "APPROVE"
    assert "NotPublisher" in report.details["newReleaseWithStolenKey"]
    entry = verdict_log_entry(gateway_url, report)
    assert entry["verdict"] == "REJECT"
    assert entry["stage1"]["failed"] == "publisher_active"
