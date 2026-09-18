"""e2e: the 'tamper' scenario ends in REJECT with Stage-1 check 'firmware_hash' named."""

from __future__ import annotations

import pytest

from conftest import verdict_log_entry
from verigate.attacks import tamper
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_tamper(ctx: AttackContext, gateway_url: str) -> None:
    report = tamper.run(ctx)
    assert report.observed == "REJECT", report.to_dict()
    assert report.check == "firmware_hash"
    assert report.passed
    entry = verdict_log_entry(gateway_url, report)
    assert entry["verdict"] == "REJECT"
    assert entry["stage1"]["failed"] == "firmware_hash"
