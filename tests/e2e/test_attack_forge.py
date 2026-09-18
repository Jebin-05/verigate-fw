"""e2e: the 'forge' scenario ends in REJECT with Stage-1 check 'signature' named."""

from __future__ import annotations

import pytest

from conftest import verdict_log_entry
from verigate.attacks import forge
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_forge(ctx: AttackContext, gateway_url: str) -> None:
    report = forge.run(ctx)
    assert report.observed == "REJECT", report.to_dict()
    assert report.check == "signature"
    assert report.passed
    entry = verdict_log_entry(gateway_url, report)
    assert entry["verdict"] == "REJECT"
    assert entry["stage1"]["failed"] == "signature"
