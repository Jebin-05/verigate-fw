"""Attack: bad publisher history — many recent rejections, then a borderline release.

Two brand-new publishers ship the *same* genuine artefacts (the v1.0.0 fixture, OpenWrt 22.03.7,
borderline under ADR-0008). The honest one has a neutral reputation (0.5) → APPROVE. The other
first ships ``REJECTS`` tampered releases; each release-level REJECT lowers its reputation by the
EWMA of ADR-0006 (α = 0.1, and the listener's own verification counts too), so the identical
release now lands in DEFER through the ``w_rep · (1 − reputation)`` term alone.
"""

from __future__ import annotations

from verigate.attacks.common import DEVICE_MODEL, AttackContext, AttackReport, fill
from verigate.common.manifest import SemVer

NAME = "bad-history"
EXPECTED = "DEFER"
REJECTS = 4
BORDERLINE = "1.0.0"


def run(ctx: AttackContext) -> AttackReport:
    """Build a rejection history for one publisher, then compare the borderline release."""
    fw, sbom = ctx.fixture(BORDERLINE, "firmware.bin"), ctx.fixture(BORDERLINE, "sbom.json")
    honest_did, honest_key, honest_account = ctx.new_publisher("honest")
    bad_did, bad_key, bad_account = ctx.new_publisher("bad")

    # 1. The bad publisher earns its history: tampered images, each rejected at release level.
    history = []
    for i in range(REJECTS):
        patched = bytearray(fw)
        patched[0x3000 + i * 16 : 0x3010 + i * 16] = b"\xde\xad\xbe\xef" * 4
        manifest = ctx.build_manifest(
            fw,
            sbom,
            ctx.next_version(bad_did),
            did=bad_did,
            firmware_cid=ctx.ipfs.put(bytes(patched)),
        )
        rid = ctx.publish(manifest.sign(bad_key), bad_account)
        history.append(ctx.verify(rid)["verdict"])
    reputation_bad = ctx.reputation_bp(bad_did)

    # 2. Both publishers ship the identical genuine release.
    device = ctx.target_device(SemVer(0, 1, 0), name="bad-history-target")
    honest_id = ctx.publish(
        ctx.build_manifest(fw, sbom, ctx.next_version(honest_did), did=honest_did).sign(honest_key),
        honest_account,
    )
    honest = ctx.verify(honest_id, device)
    release_id = ctx.publish(
        ctx.build_manifest(fw, sbom, ctx.next_version(bad_did, DEVICE_MODEL), did=bad_did).sign(
            bad_key
        ),
        bad_account,
    )
    report = AttackReport(NAME, EXPECTED, release_id=release_id)
    report.details = {
        "artefacts": f"v{BORDERLINE} fixture (identical for both publishers)",
        "history": history,
        "honest": {
            "did": honest_did,
            "reputation": ctx.reputation_bp(honest_did),
            "verdict": honest["verdict"],
            "R": honest["R"],
        },
        "badPublisher": {"did": bad_did, "reputation": reputation_bad},
    }
    return fill(report, ctx.verify(release_id, device))
