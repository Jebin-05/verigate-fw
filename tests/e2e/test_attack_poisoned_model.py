"""e2e: 'poisoned-model' — revoke the image model; the gateway replays the stale verdicts.

On a fresh stack the primary model is in use and the successor takes over (verdicts re-issued
under its hash). On a stack where that already happened the successor is revoked with no
replacement and every replayed pair fails closed. Both are asserted.
"""

from __future__ import annotations

import pytest

from verigate.attacks import poisoned_model
from verigate.attacks.common import AttackContext

pytestmark = pytest.mark.e2e


def test_attack_poisoned_model(ctx: AttackContext) -> None:
    if not ctx.settings.image_model:
        pytest.skip("IMAGE_MODEL not configured")
    report = poisoned_model.run(ctx)
    assert report.observed == "REPLAYED", report.to_dict()
    assert report.passed
    d = report.details
    assert d["staleBatches"] and d["pairsReplayed"] >= 1
    pair = d["replayed"]
    assert pair["releaseId"] == report.release_id and pair["deviceId"] == report.device_id
    assert pair["afterId"] != pair["beforeId"]
    if d["mode"] == "swap-to-successor":
        assert d["successor"] in d["after"]["models"] and d["revoked"] not in d["after"]["models"]
        assert d["after"]["verdict"] in ("APPROVE", "DEFER")
    else:
        assert d["after"]["verdict"] == "REJECT" and d["after"]["check"] == "model_active"
        assert pair["after"] == "REJECT"
    reports = ctx.get("/revocations")
    assert any(r["modelHash"] == d["revoked"] for r in reports)
