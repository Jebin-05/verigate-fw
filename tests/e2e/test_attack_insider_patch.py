"""e2e: 'insider-patch' — the trusted build with 256 bytes overwritten; check #9 → DEFER."""

from __future__ import annotations

import pytest

from conftest import verdict_log_entry
from verigate.attacks import insider_patch
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_insider_patch(ctx: AttackContext, gateway_url: str) -> None:
    report = insider_patch.run(ctx)
    assert report.observed == "DEFER", report.to_dict()
    assert report.details["clean"]["verdict"] == "APPROVE"  # the trusted reference
    assert report.check == "release_delta" and report.passed
    assert 0 < report.details["patchedBytes"] <= 256
    assert "blocks changed" in (report.reason or "")
    entry = verdict_log_entry(gateway_url, report)
    assert entry["verdict"] == "DEFER"
