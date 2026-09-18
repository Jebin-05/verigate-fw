"""Attack: tampering — the bytes behind the manifest firmware CID are not the hashed bytes.

Models a compromised release pipeline (or a poisoned IPFS pin) that swaps the image after the
manifest was signed. Caught by Stage-1 #1 (``firmware_hash``) → REJECT. The in-transit variant —
a node serving wrong bytes for a CID — is caught earlier by content addressing (``IpfsError`` →
DEFER, retry from another node).
"""

from __future__ import annotations

from verigate.attacks.common import AttackContext, AttackReport, fill

NAME = "tamper"
EXPECTED = "REJECT"


def run(ctx: AttackContext) -> AttackReport:
    """Publish a manifest for the genuine v1.1.0 bytes whose CID points at a patched image."""
    ctx.ensure_demo_publisher()
    genuine = ctx.fixture("1.1.0", "firmware.bin")
    tampered = bytearray(genuine)
    tampered[0x2000:0x2010] = b"BACKDOOR-JMP\x00\x00\x00\x00"  # one patched region
    tampered_cid = ctx.ipfs.put(bytes(tampered))
    manifest = ctx.build_manifest(
        genuine, ctx.fixture("1.1.0", "sbom.json"), ctx.next_version(), firmware_cid=tampered_cid
    )
    release_id = ctx.publish(manifest.sign(ctx.key), ctx.publisher_account)
    report = AttackReport(NAME, EXPECTED, release_id=release_id)
    report.details = {"tamperedCid": tampered_cid, "patchedBytes": 16}
    return fill(report, ctx.verify(release_id))
