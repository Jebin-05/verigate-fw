"""Attack: insider patch — the last good build with 256 bytes overwritten, signed with the real key.

The publisher ships a clean build, then the *same* build with the catalogue's ``byte-patch``
mutation (four 64-byte regions overwritten) under a newer version — what a compromised build
server or a malicious insider produces after the build. Every cryptographic check passes and the
image model scores it like the clean build (byte patches are at chance for it); Stage-1 check #9
sees the trusted image with a few blocks changed and holds the release for review (DEFER).
"""

from __future__ import annotations

from verigate.attacks.common import AttackContext, AttackReport, fill
from verigate.common.manifest import SemVer
from verigate.ml.data.mutate import CATALOGUE

NAME = "insider-patch"
EXPECTED = "DEFER"
BASE = "2.0.0"


def run(ctx: AttackContext) -> AttackReport:
    """Publish clean then patched builds; verify the latter for an up-to-date device.

    A fresh publisher (neutral reputation) so the clean build is approved and becomes the
    trusted reference, independent of what earlier scenarios did to the demo publisher.
    """
    did, key, account = ctx.new_publisher("insider")
    clean_fw, sbom = ctx.fixture(BASE, "firmware.bin"), ctx.fixture(BASE, "sbom.json")
    clean_version = ctx.next_version(did)
    clean_id = ctx.publish(
        ctx.build_manifest(clean_fw, sbom, clean_version, did=did).sign(key), account
    )
    device = ctx.target_device(SemVer(0, 1, 0), name="insider-patch-target")
    clean = ctx.verify(clean_id, device)  # approved: the reference for the next release
    patched_fw = CATALOGUE["byte-patch"].apply(clean_fw, 2025)
    version = SemVer(clean_version.major, clean_version.minor, clean_version.patch + 1)
    release_id = ctx.publish(
        ctx.build_manifest(patched_fw, sbom, version, did=did).sign(key), account
    )
    report = AttackReport(NAME, EXPECTED, release_id=release_id)
    report.details = {
        "cleanReleaseId": clean_id,
        "clean": {"verdict": clean["verdict"], "R": clean["R"], "rImg": clean["rImg"]},
        "patchedBytes": sum(a != b for a, b in zip(clean_fw, patched_fw, strict=True)),
        "mutation": CATALOGUE["byte-patch"].description,
    }
    return fill(report, ctx.verify(release_id, device))
