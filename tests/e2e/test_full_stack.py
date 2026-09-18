"""P4-07 e2e: publish → verify → device installs → receipt → reputation ↑ → proof on-chain."""

from __future__ import annotations

import secrets
from pathlib import Path

import httpx
import pytest

from verigate.attacks.common import AttackContext
from verigate.common.chain import publisher_id
from verigate.common.manifest import SemVer
from verigate.fleet.device import Device
from verigate.fleet.runner import DeviceAgent, FleetStats

pytestmark = pytest.mark.e2e


async def test_publish_verify_install_receipt_reputation(
    ctx: AttackContext, gateway_url: str, tmp_path: Path
) -> None:
    ctx.ensure_demo_publisher()
    pid = publisher_id(ctx.did)
    version = ctx.next_version()
    manifest = ctx.build_manifest(
        ctx.fixture("2.0.0", "firmware.bin"), ctx.fixture("2.0.0", "sbom.json"), version
    )
    release_id = ctx.publish(manifest.sign(ctx.key), ctx.publisher_account)
    reputation_before = ctx.chain.get_publisher(pid).reputation_bp

    verdict = ctx.verify(release_id)
    assert verdict["verdict"] == "APPROVE", verdict
    assert verdict["verdictId"] is not None

    device = Device(tmp_path, f"e2e-{secrets.token_hex(3)}", "demo-device")
    stats = FleetStats()
    async with httpx.AsyncClient(base_url=gateway_url, timeout=60) as client:
        agent = DeviceAgent(device, client, stats)
        await agent.hello()
        seen = await agent.step()
    assert seen == "APPROVE" and stats.installs == 1 and stats.receipts == 1, stats.to_dict()
    assert device.installed_version == SemVer.parse(str(version))
    assert device.state.installed_release_id == release_id

    devices = {d["device_id"]: d for d in httpx.get(f"{gateway_url}/devices", timeout=30).json()}
    assert devices[device.device_id]["installed_version"] == str(version)
    assert devices[device.device_id]["receipts"] == 1

    reputation_after = ctx.chain.get_publisher(pid).reputation_bp
    assert reputation_after > reputation_before

    httpx.post(f"{gateway_url}/batches/flush", timeout=60).raise_for_status()
    proof = httpx.get(f"{gateway_url}/verdicts/{verdict['verdictId']}/proof", timeout=30).json()
    assert proof["status"] == "committed"
    ok = ctx.chain.call(
        ctx.chain.verdicts.functions.verifyLeaf(
            proof["batchId"],
            bytes.fromhex(proof["verdictId"][2:]),
            [bytes.fromhex(p[2:]) for p in proof["proof"]],
        )
    )
    assert ok is True
    assert proof["record"]["verdict"] == "APPROVE" and proof["record"]["releaseId"] == release_id
