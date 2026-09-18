"""e2e: 'bad-history' — the same release: APPROVE for a neutral publisher, DEFER after rejects."""

from __future__ import annotations

import pytest

from conftest import verdict_log_entry
from verigate.attacks import bad_history
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_bad_history(ctx: AttackContext, gateway_url: str) -> None:
    if not ctx.settings.sbom_model:
        pytest.skip("SBOM_MODEL not configured")
    report = bad_history.run(ctx)
    assert report.observed == "DEFER", report.to_dict()
    assert report.check is None and report.passed
    honest, bad = report.details["honest"], report.details["badPublisher"]
    assert honest["verdict"] == "APPROVE" and honest["reputation"] == 5000
    assert bad["reputation"] < 4000  # ≥ 4 release-level rejects at α = 0.1 (ADR-0006)
    assert report.details["history"] == ["REJECT"] * bad_history.REJECTS
    assert report.details["R"] > honest["R"]  # only the reputation term differs
    entry = verdict_log_entry(gateway_url, report)
    assert (
        entry["verdict"] == "DEFER" and entry["reputation"] < 4000
    )  # listener signals may land in between
