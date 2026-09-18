"""Attack: poisoned model — the anomaly detector in use is found to have a blind spot.

The response is Novelty 2 (ADR-0009): the admin revokes the model's hash on ``ModelRegistry``
naming a successor; every batch that used it is STALE on-chain; the gateway swaps in the
successor (located by hash under ``MODELS_DIR``) and re-verifies every affected (release, device)
pair. The scenario runs against whichever image model the gateway is using:

* the primary model is in use → revoke it with ``models/successor/`` as successor → REPLAYED
  (verdicts re-issued under the successor's hash);
* the successor is already in use (a previous run) → revoke it with no successor → the gate fails
  closed and the replay shows every pair going to REJECT — also REPLAYED, honestly closed.
"""

from __future__ import annotations

import hashlib
from typing import Any

from verigate.attacks.common import AttackContext, AttackReport
from verigate.common.chain import STATUS_NONE
from verigate.common.errors import VerigateError
from verigate.common.manifest import SemVer

NAME = "poisoned-model"
EXPECTED = "REPLAYED"
ZERO = "0x" + "00" * 32


def _hash(ctx: AttackContext, relative: str) -> str:
    return "0x" + hashlib.sha256((ctx.settings.models_dir / relative).read_bytes()).hexdigest()


def run(ctx: AttackContext) -> AttackReport:
    """Make sure a device verdict used the image model, revoke it, trigger and read the replay."""
    ctx.ensure_demo_publisher()
    if not ctx.settings.image_model:
        raise VerigateError("IMAGE_MODEL is not configured; nothing to poison")
    primary = _hash(ctx, ctx.settings.image_model)
    successor = _hash(ctx, "successor/" + ctx.settings.image_model)

    # 1. A genuine release verified for a device — a verdict the model took part in.
    version = ctx.next_version()
    manifest = ctx.build_manifest(
        ctx.fixture("2.0.0", "firmware.bin"), ctx.fixture("2.0.0", "sbom.json"), version
    )
    release_id = ctx.publish(manifest.sign(ctx.key), ctx.publisher_account)
    device = ctx.target_device(SemVer(0, 1, 0), name="poisoned-model-target")
    before = ctx.verify(release_id, device)
    in_use = set(before.get("modelHashes") or [])
    if primary in in_use:
        revoked, next_hash, mode = primary, successor, "swap-to-successor"
    elif successor in in_use:
        revoked, next_hash, mode = successor, ZERO, "no-successor-fail-closed"
    else:
        raise VerigateError("the gateway's verdict names neither image model; nothing to revoke")
    ctx.post("/batches/flush")  # the verdict must be anchored to be STALE on-chain

    # 2. Admin action: register the successor (idempotent) and revoke the model in use.
    if next_hash != ZERO:
        record = ctx.chain.get_model(bytes.fromhex(next_hash[2:]))
        if record.status == STATUS_NONE:
            ctx.chain.send(
                ctx.chain.models.functions.register(
                    bytes.fromhex(next_hash[2:]), "image_anomaly (successor)"
                ),
                ctx.admin_account,
            )
    tx = ctx.chain.send(
        ctx.chain.models.functions.revoke(bytes.fromhex(revoked[2:]), bytes.fromhex(next_hash[2:])),
        ctx.admin_account,
    )

    # 3. The gateway job replays the stale verdicts (ask it now rather than waiting for the poll).
    reports: list[dict[str, Any]] = ctx.post("/revocations/check")
    if not reports:
        reports = [r for r in ctx.get("/revocations") if r["modelHash"] == revoked]
    report = AttackReport(NAME, EXPECTED, release_id=release_id, device_id=device)
    mine = next((r for r in reports if r["modelHash"] == revoked), None)
    pair = None
    if mine is not None:
        pair = next(
            (p for p in mine["pairs"] if p["releaseId"] == release_id and p["deviceId"] == device),
            None,
        )
    after = ctx.verify(release_id, device)
    report.details = {
        "mode": mode,
        "revoked": revoked,
        "successor": next_hash,
        "revokeTx": "0x" + bytes(tx["transactionHash"]).hex(),
        "staleBatches": mine["staleBatches"] if mine else None,
        "pairsReplayed": len(mine["pairs"]) if mine else 0,
        "changed": mine["changed"] if mine else None,
        "before": {"verdict": before["verdict"], "R": before["R"], "models": sorted(in_use)},
        "replayed": pair,
        "after": {
            "verdict": after["verdict"],
            "R": after["R"],
            "models": after.get("modelHashes"),
            "check": (after.get("stage1") or {}).get("failed"),
        },
    }
    replayed = pair is not None and revoked not in (after.get("modelHashes") or [])
    if mode == "no-successor-fail-closed":
        replayed = pair is not None and after["verdict"] == "REJECT"
    report.observed = "REPLAYED" if replayed else "NOT-REPLAYED"
    report.reason = (
        f"{mode}: {len(mine['pairs']) if mine else 0} stale verdicts re-verified"
        if mine
        else "gateway reported no revocation"
    )
    return report
