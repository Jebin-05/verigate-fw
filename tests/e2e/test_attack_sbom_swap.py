"""e2e: the 'sbom_swap' scenario ends in REJECT with Stage-1 check 'sbom_hash' named."""

from __future__ import annotations

import pytest

from conftest import verdict_log_entry
from verigate.attacks import sbom_swap
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_sbom_swap(ctx: AttackContext, gateway_url: str) -> None:
    report = sbom_swap.run(ctx)
    assert report.observed == "REJECT", report.to_dict()
    assert report.check == "sbom_hash"
    assert report.passed
    entry = verdict_log_entry(gateway_url, report)
    assert entry["verdict"] == "REJECT"
    assert entry["stage1"]["failed"] == "sbom_hash"
