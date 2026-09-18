"""Attack: forgery — an attacker signs a manifest with their own key and claims to be the publisher.

The attacker can only register under a DID they own, so the on-chain record belongs to them while
the manifest says ``publisherDid = <victim>``. Caught by Stage-1 #2 (``signature``): the signature
does not verify under the key registered for the DID the manifest names → REJECT.
"""

from __future__ import annotations

from datetime import UTC, datetime

from verigate.attacks.common import AttackContext, AttackReport, fill

NAME = "forge"
EXPECTED = "REJECT"


def run(ctx: AttackContext) -> AttackReport:
    """Register an attacker publisher, sign a manifest that claims the demo publisher's DID."""
    ctx.ensure_demo_publisher()
    attacker_did, attacker_key, attacker_account = ctx.new_publisher("attacker")
    manifest = ctx.build_manifest(
        ctx.fixture("2.0.0", "firmware.bin"),
        ctx.fixture("2.0.0", "sbom.json"),
        ctx.next_version(attacker_did),
        did=ctx.did,  # the lie
        # releaseId = hash of the manifest: a distinct expiry keeps the forgery from colliding
        # with a genuine release of the same fixture (first registrant owns the id).
        expiry=datetime(2031, 6, 1, tzinfo=UTC),
    )
    release_id = ctx.publish(manifest.sign(attacker_key), attacker_account)
    report = AttackReport(NAME, EXPECTED, release_id=release_id)
    report.details = {"attackerDid": attacker_did, "claimedDid": ctx.did}
    return fill(report, ctx.verify(release_id))
