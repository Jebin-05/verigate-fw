"""Attack: vulnerable-but-genuine — an honest publisher ships firmware built on an EOL base.

Nothing in Stage 1 is wrong: the demo publisher's real key signs a consistent manifest for a real
OpenWrt 19.07.10 busybox build with the SBOM of that release (72 CVEs against components with the
highest EPSS mass in the corpus; OpenWrt 19.07 reached end of life in 2022). Stage 2's ``r_sbom``
carries the decision → policy (ADR-0008): DEFER, or REJECT when the publisher's reputation is
already poor (Guide §9: "REJECT or DEFER").

No KEV-listed package could be found in the OpenWrt corpus with the current CISA catalogue
mapping, so this scenario demonstrates EPSS/CVSS-driven risk, not a KEV hit (model card).
"""

from __future__ import annotations

from verigate.attacks.common import AttackContext, AttackReport, fill
from verigate.common.manifest import SemVer

NAME = "vulnerable-genuine"
EXPECTED = "DEFER"
ACCEPTED = ("REJECT",)
FIXTURE = "legacy-19.07.10"


def run(ctx: AttackContext) -> AttackReport:
    """Publish the legacy build genuinely; verify it for a device on the previous version."""
    ctx.ensure_demo_publisher()
    version = ctx.next_version()
    manifest = ctx.build_manifest(
        ctx.fixture(FIXTURE, "firmware.bin"), ctx.fixture(FIXTURE, "sbom.json"), version
    )
    release_id = ctx.publish(manifest.sign(ctx.key), ctx.publisher_account)
    device = ctx.target_device(SemVer(version.major, version.minor, max(version.patch - 1, 0)))
    report = AttackReport(NAME, EXPECTED, ACCEPTED, release_id=release_id)
    report.details = {"base": "OpenWrt 19.07.10 (EOL 2022-04)", "stage1": "all checks pass"}
    return fill(report, ctx.verify(release_id, device))
