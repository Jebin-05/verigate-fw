"""Attack: hidden payload — a genuine-looking release with 200 KiB of packed code appended.

The publisher first ships a clean build (so the image model has a predecessor), then the same
build with the catalogue's ``append`` mutation (200 KiB of high-entropy bytes past the ELF's
declared end). Stage 1 passes — the manifest is consistent and genuinely signed — and Stage 2's
``r_img`` (appended bytes, size delta, entropy) lifts ``R`` into DEFER for review (Guide §9).
"""

from __future__ import annotations

from verigate.attacks.common import AttackContext, AttackReport, fill
from verigate.common.manifest import SemVer
from verigate.ml.data.mutate import CATALOGUE

NAME = "hidden-payload"
EXPECTED = "DEFER"
BASE = "2.0.0"


def run(ctx: AttackContext) -> AttackReport:
    """Publish clean then payload-carrying builds; verify the latter for an up-to-date device."""
    ctx.ensure_demo_publisher()
    clean_fw, sbom = ctx.fixture(BASE, "firmware.bin"), ctx.fixture(BASE, "sbom.json")
    clean_version = ctx.next_version()
    clean_id = ctx.publish(
        ctx.build_manifest(clean_fw, sbom, clean_version).sign(ctx.key), ctx.publisher_account
    )
    payload_fw = CATALOGUE["append"].apply(clean_fw, 2024)
    version = SemVer(clean_version.major, clean_version.minor, clean_version.patch + 1)
    release_id = ctx.publish(
        ctx.build_manifest(payload_fw, sbom, version).sign(ctx.key), ctx.publisher_account
    )
    device = ctx.target_device(SemVer(0, 1, 0), name="hidden-payload-target")
    clean = ctx.verify(clean_id, device)  # the same device judged the clean build first
    report = AttackReport(NAME, EXPECTED, release_id=release_id)
    report.details = {
        "cleanReleaseId": clean_id,
        "clean": {"verdict": clean["verdict"], "R": clean["R"], "rImg": clean["rImg"]},
        "appendedBytes": len(payload_fw) - len(clean_fw),
        "mutation": CATALOGUE["append"].description,
    }
    return fill(report, ctx.verify(release_id, device))
