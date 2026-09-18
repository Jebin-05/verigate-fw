"""Attack: stolen key — a release signed with a key the publisher has since reported stolen.

A separate victim publisher is created so the demo publisher stays usable. The victim publishes a
genuine release, the admin revokes the publisher, and the gateway is asked again: Stage-1 #3
(``publisher_active``) → REJECT. A second registration attempt with the stolen key is refused
on-chain (``NotPublisher``) and recorded in the report.
"""

from __future__ import annotations

from verigate.attacks.common import AttackContext, AttackReport, fill
from verigate.common.chain import publisher_id
from verigate.common.errors import VerificationError

NAME = "stolen-key"
EXPECTED = "REJECT"


def run(ctx: AttackContext) -> AttackReport:
    """Victim publishes, admin revokes the victim, verification of the release now fails."""
    victim_did, victim_key, victim_account = ctx.new_publisher("victim")
    manifest = ctx.build_manifest(
        ctx.fixture("1.0.0", "firmware.bin"),
        ctx.fixture("1.0.0", "sbom.json"),
        ctx.next_version(victim_did),
        did=victim_did,
    )
    release_id = ctx.publish(manifest.sign(victim_key), victim_account)
    before = ctx.verify(release_id)["verdict"]
    ctx.chain.send(
        ctx.chain.publishers.functions.revoke(publisher_id(victim_did)), ctx.admin_account
    )
    on_chain_refused = None
    try:
        again = ctx.build_manifest(
            ctx.fixture("1.1.0", "firmware.bin"),
            ctx.fixture("1.1.0", "sbom.json"),
            ctx.next_version(victim_did),
            did=victim_did,
        )
        ctx.publish(again.sign(victim_key), victim_account)
    except VerificationError as exc:
        on_chain_refused = str(exc)
    report = AttackReport(NAME, EXPECTED, release_id=release_id)
    report.details = {
        "victimDid": victim_did,
        "verdictBeforeRevocation": before,
        "newReleaseWithStolenKey": on_chain_refused or "unexpectedly accepted",
    }
    return fill(report, ctx.verify(release_id))
