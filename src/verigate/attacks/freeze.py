"""Attack: freeze — the device is kept on a manifest whose expiry has passed.

A short-lived manifest is published and the gateway is asked to verify it after it expired.
Stage-1 #5 (``expiry``) fails; because the release is genuine but stale the gate answers
DEFER (+ alert), not REJECT (Guide §9).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

from verigate.attacks.common import AttackContext, AttackReport, fill

NAME = "freeze"
EXPECTED = "DEFER"
TTL_S = 6


def run(ctx: AttackContext) -> AttackReport:
    """Publish with expiry = chain-now + TTL, wait until the wall clock passes it, verify.

    ``FirmwareRegistry.register`` refuses ``expiry <= block.timestamp`` and the gateway compares
    against its wall clock, so the expiry is anchored to the chain and the wait to the wall.
    """
    ctx.ensure_demo_publisher()
    expiry = datetime.fromtimestamp(ctx.chain_now() + TTL_S, tz=UTC)
    manifest = ctx.build_manifest(
        ctx.fixture("1.1.0", "firmware.bin"),
        ctx.fixture("1.1.0", "sbom.json"),
        ctx.next_version(),
        expiry=expiry,
    )
    release_id = ctx.publish(manifest.sign(ctx.key), ctx.publisher_account)
    fresh = ctx.verify(release_id)["verdict"]
    time.sleep(max(0.0, expiry.timestamp() - time.time()) + 1)
    report = AttackReport(NAME, EXPECTED, release_id=release_id)
    report.details = {"expiry": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"), "verdictBeforeExpiry": fresh}
    return fill(report, ctx.verify(release_id))
