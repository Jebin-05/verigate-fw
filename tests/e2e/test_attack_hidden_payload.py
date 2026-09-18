"""e2e: 'hidden-payload' — appended packed bytes lift r_img; Stage 1 passes; DEFER for review."""

from __future__ import annotations

import pytest

from conftest import verdict_log_entry
from verigate.attacks import hidden_payload
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_hidden_payload(ctx: AttackContext, gateway_url: str) -> None:
    if not ctx.settings.image_model:
        pytest.skip("IMAGE_MODEL not configured")
    report = hidden_payload.run(ctx)
    assert report.observed == "DEFER", report.to_dict()
    assert report.check is None and report.passed
    assert report.details["appendedBytes"] == 200 * 1024
    assert report.details["clean"]["rImg"] < report.details["rImg"]  # the payload raised r_img
    entry = verdict_log_entry(gateway_url, report)
    assert entry["verdict"] == "DEFER" and entry["rImg"] == report.details["rImg"]
