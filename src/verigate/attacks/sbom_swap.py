"""Attack: SBOM swap — a clean ingredients list is paired with a firmware full of old libraries.

The manifest carries the hash of the *clean* SBOM, but its ``cids.sbom`` points at the SBOM that
actually describes the image (the v1.0.0 one with OpenSSL 3.0.1). Stage-1 #6 (``sbom_hash``)
→ REJECT before Stage 2 could be fooled.
"""

from __future__ import annotations

from verigate.attacks.common import AttackContext, AttackReport, fill

NAME = "sbom-swap"
EXPECTED = "REJECT"


def run(ctx: AttackContext) -> AttackReport:
    """Hash the clean SBOM, point the CID at the dirty one."""
    ctx.ensure_demo_publisher()
    dirty_cid = ctx.ipfs.put(ctx.fixture("1.0.0", "sbom.json"))
    manifest = ctx.build_manifest(
        ctx.fixture("1.0.0", "firmware.bin"),
        ctx.fixture("2.0.0", "sbom.json"),  # the clean list that gets hashed
        ctx.next_version(),
        sbom_cid=dirty_cid,
    )
    release_id = ctx.publish(manifest.sign(ctx.key), ctx.publisher_account)
    report = AttackReport(NAME, EXPECTED, release_id=release_id)
    report.details = {"servedSbomCid": dirty_cid, "hashedSbom": "v2.0.0/sbom.json"}
    return fill(report, ctx.verify(release_id))
