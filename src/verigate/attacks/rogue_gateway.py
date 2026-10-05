"""Attack: rogue gateway — the gateway itself is compromised and pushes updates to a device.

The rogue gateway answers every poll with APPROVE and hands the device whatever it likes: an
image signed with its own key under a real publisher's DID (never registered), a release the
publisher has withdrawn, and a release of a publisher the admin has revoked. The device reads the
publisher key and the release record from the chain itself (``Device(..., chain=…)``) and must
refuse all three. A genuine, registered release pushed the same way is the control: it installs.
Observed ``REFUSED`` iff every attack variant was refused and the control installed;
``INSTALLED`` if any attack variant installed; ``CONTROL-REFUSED`` if only the control failed.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from typing import Any

import httpx

from verigate.attacks.common import AttackContext, AttackReport
from verigate.common.chain import publisher_id
from verigate.common.crypto import KeyPair
from verigate.common.manifest import SignedManifest
from verigate.fleet.device import Device
from verigate.fleet.runner import DeviceAgent, FleetStats

NAME = "rogue-gateway"
EXPECTED = "REFUSED"


def _push(
    ctx: AttackContext, name: str, manifest: SignedManifest, firmware: bytes, key: str
) -> dict[str, Any]:
    """One device polls the rogue gateway once; returns whether it installed and why not."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/devices/poll":
            update = {
                "manifest": json.loads(manifest.model_dump_json()),
                "firmwareUrl": "/firmware.bin",
                "publisherKey": key,
            }
            return httpx.Response(200, json={"verdict": {"verdict": "APPROVE"}, "update": update})
        if request.url.path == "/firmware.bin":
            return httpx.Response(200, content=firmware)
        return httpx.Response(200, json={})

    # a factory-fresh device per push, so repeated runs do not inherit an installed version
    device_id = f"rogue-{name}-{secrets.token_hex(3)}"
    device = Device(ctx.workdir / "rogue-gateway", device_id, manifest.deviceModel)
    stats = FleetStats()

    async def once() -> None:
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(base_url="http://rogue", transport=transport) as client:
            await DeviceAgent(device, client, stats, ctx.chain).step()

    asyncio.run(once())
    return {
        "installed": stats.installs == 1,
        "refusal": stats.last_errors.get(device.device_id),
        "installedVersion": str(device.installed_version),
    }


def run(ctx: AttackContext) -> AttackReport:
    """Three pushes the device must refuse, one it must accept."""
    fw, sbom = ctx.fixture("1.0.0", "firmware.bin"), ctx.fixture("1.0.0", "sbom.json")
    did, key, account = ctx.new_publisher("rogue-victim")
    attacker = KeyPair.generate()
    results: dict[str, dict[str, Any]] = {}

    tampered = fw[:-64] + bytes(64)
    forged = ctx.build_manifest(tampered, sbom, ctx.next_version(did), did=did).sign(attacker)
    results["forged-unregistered"] = _push(ctx, "forged", forged, tampered, attacker.public_encoded)

    withdrawn = ctx.build_manifest(fw, sbom, ctx.next_version(did), did=did).sign(key)
    withdrawn_id = ctx.publish(withdrawn, account)
    ctx.chain.send(ctx.chain.firmware.functions.revoke(bytes.fromhex(withdrawn_id[2:])), account)
    results["withdrawn-release"] = _push(ctx, "withdrawn", withdrawn, fw, key.public_encoded)

    control = ctx.build_manifest(fw, sbom, ctx.next_version(did), did=did).sign(key)
    ctx.publish(control, account)
    results["control-genuine"] = _push(ctx, "control", control, fw, attacker.public_encoded)

    ctx.chain.send(ctx.chain.publishers.functions.revoke(publisher_id(did)), ctx.admin_account)
    # the same registered release, now from a publisher the admin has revoked (stolen key)
    results["revoked-publisher"] = _push(ctx, "revoked", control, fw, key.public_encoded)

    attacks = [v for k, v in results.items() if k != "control-genuine"]
    refused = all(not r["installed"] for r in attacks)
    report = AttackReport(NAME, EXPECTED)
    if not refused:
        report.observed = "INSTALLED"
    elif results["control-genuine"]["installed"]:
        report.observed = "REFUSED"
    else:
        report.observed = "CONTROL-REFUSED"
    report.reason = "; ".join(f"{k}: {v['refusal']}" for k, v in results.items() if v["refusal"])
    report.details = {"pushes": results}
    return report
