"""Attack: rollback — replay a genuine, still-valid older release to a device on a newer version.

Everything about the old release checks out (hash, signature, ACTIVE publisher, not revoked); only
the device's persistent version counter stops it. Stage-1 #4 (``version_monotonic``) → REJECT.
"""

from __future__ import annotations

from verigate.attacks.common import DEVICE_MODEL, AttackContext, AttackReport, fill
from verigate.common.manifest import SemVer

NAME = "rollback"
EXPECTED = "REJECT"


def run(ctx: AttackContext) -> AttackReport:
    """Publish v_old then v_new; put a device on v_new; ask the gateway to verify v_old for it."""
    ctx.ensure_demo_publisher()
    old_version = ctx.next_version()
    old = ctx.build_manifest(
        ctx.fixture("1.0.0", "firmware.bin"), ctx.fixture("1.0.0", "sbom.json"), old_version
    )
    old_id = ctx.publish(old.sign(ctx.key), ctx.publisher_account)
    new_version = ctx.next_version()
    new = ctx.build_manifest(
        ctx.fixture("1.1.0", "firmware.bin"), ctx.fixture("1.1.0", "sbom.json"), new_version
    )
    ctx.publish(new.sign(ctx.key), ctx.publisher_account)
    device_id = ctx.target_device(SemVer.parse(str(new_version)))
    report = AttackReport(NAME, EXPECTED, release_id=old_id)
    report.details = {
        "replayedVersion": str(old_version),
        "deviceInstalled": str(new_version),
        "deviceModel": DEVICE_MODEL,
        "releaseLevelVerdict": ctx.verify(old_id)["verdict"],  # genuine → APPROVE at release level
    }
    return fill(report, ctx.verify(old_id, device_id=device_id))
