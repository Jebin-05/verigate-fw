"""e2e: 'vulnerable-genuine' passes Stage 1 and is held (or rejected) by Stage 2's r_sbom."""

from __future__ import annotations

import pytest

from conftest import verdict_log_entry
from verigate.attacks import vulnerable_genuine
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_vulnerable_genuine(ctx: AttackContext, gateway_url: str) -> None:
    if not ctx.settings.sbom_model:
        pytest.skip("SBOM_MODEL not configured")
    report = vulnerable_genuine.run(ctx)
    assert report.observed in ("DEFER", "REJECT"), report.to_dict()
    assert report.check is None  # Stage 1 passed; the policy decided
    assert report.passed
    assert report.details["rSbom"] > 5000  # measured 0.73 on the legacy fixture (ADR-0008 table)
    entry = verdict_log_entry(gateway_url, report)
    assert entry["verdict"] == report.observed and entry["stage1"]["ok"] is True
    assert entry["rSbom"] == report.details["rSbom"]
