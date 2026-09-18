"""e2e: the 'rollback' scenario ends in REJECT with Stage-1 check 'version_monotonic' named."""

from __future__ import annotations

import pytest

from conftest import verdict_log_entry
from verigate.attacks import rollback
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_rollback(ctx: AttackContext, gateway_url: str) -> None:
    report = rollback.run(ctx)
    assert report.observed == "REJECT", report.to_dict()
    assert report.check == "version_monotonic"
    assert report.passed
    assert (
        report.details["releaseLevelVerdict"] == "APPROVE"
    )  # genuine release, only the device counter stops it
    entry = verdict_log_entry(gateway_url, report)
    assert entry["deviceId"] == report.device_id
    assert entry["verdict"] == "REJECT"
    assert entry["stage1"]["failed"] == "version_monotonic"
