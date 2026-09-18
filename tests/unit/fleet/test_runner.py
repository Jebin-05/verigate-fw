"""Fleet runner against an in-process gateway (ASGI transport): hello → poll → install → receipt."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fake_chain import FIXTURES, FakeChain, publish
from typer.testing import CliRunner

from verigate.common.crypto import KeyPair
from verigate.common.ipfs import LocalCidBackend
from verigate.common.manifest import SemVer
from verigate.common.settings import Settings
from verigate.fleet import cli
from verigate.fleet.device import Device
from verigate.fleet.runner import DeviceAgent, FleetStats, run_fleet
from verigate.gateway.api.main import create_app
from verigate.gateway.service import GatewayService

FW1 = (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()
FW2 = (FIXTURES / "v1.1.0" / "firmware.bin").read_bytes()
DID = "did:verigate:fleet"


@pytest.fixture
def world(tmp_path: Path, settings: Settings) -> dict[str, Any]:
    chain = FakeChain()
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    key = KeyPair.generate()
    chain.add_publisher(DID, key)
    rid, _ = publish(chain, ipfs, key, DID, "1.0.0", FW1)
    service = GatewayService(
        settings=settings, chain=chain, ipfs=ipfs, state_dir=tmp_path / "state"
    )  # type: ignore[arg-type]
    app = create_app(service, start_listener=False)
    return {"chain": chain, "ipfs": ipfs, "key": key, "rid": rid, "service": service, "app": app}


async def test_run_fleet_installs_and_reports(
    world: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = httpx.ASGITransport(app=world["app"])
    real_client = httpx.AsyncClient

    def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched)
    async with world["app"].router.lifespan_context(world["app"]):
        stats = await run_fleet(
            "http://gateway", tmp_path / "fleet", count=3, interval_s=0.01, rounds=2, prefix="t"
        )
    assert stats.installs == 3 and stats.receipts == 3 and stats.errors == 0 and stats.polls == 6
    assert stats.last_verdicts == {"t-000": "APPROVE", "t-001": "APPROVE", "t-002": "APPROVE"}
    for i in range(3):
        d = Device(tmp_path / "fleet", f"t-{i:03d}", "demo-device")
        assert d.installed_version == SemVer(1, 0, 0) and d.active_image() == FW1
    devices = world["service"].devices.all()
    assert [d.installed_version for d in devices] == ["1.0.0"] * 3
    assert all(d.receipts == 1 for d in devices)
    assert stats.to_dict()["installs"] == 3


async def test_agent_blocked_when_gateway_rejects(world: dict[str, Any], tmp_path: Path) -> None:
    # a rollback candidate: device already on 2.0.0, only 1.0.0 exists → no update
    device = Device(tmp_path / "fleet", "old", "demo-device")
    fw_new = FW2
    from fake_chain import publish as _publish  # noqa: PLC0415

    _publish(world["chain"], world["ipfs"], world["key"], DID, "3.0.0", fw_new)
    await world["service"].refresh_releases()
    world["chain"].revoke_release(
        world["service"].latest_for("demo-device", SemVer(0, 0, 0)).release_id
    )
    stats = FleetStats()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=world["app"]), base_url="http://g"
    ) as client:
        agent = DeviceAgent(device, client, stats)
        await agent.hello()
        verdict = await agent.step()
    # the cached candidate was revoked on-chain after the last refresh: verification re-reads
    # the record and rejects (fail closed), the device is told why and installs nothing
    assert verdict == "REJECT"
    assert stats.rejected == 1 and stats.installs == 0
    await world["service"].refresh_releases()  # picks up the revocation → 1.0.0 is best again
    best = world["service"].latest_for("demo-device", SemVer(0, 0, 0))
    assert best is not None and best.version == (1, 0, 0)


async def test_agent_self_check_failure_counts_as_error(
    world: dict[str, Any], tmp_path: Path
) -> None:
    # the gateway serves a manifest for FW1 but the firmware endpoint returns other bytes
    device = Device(tmp_path / "fleet", "sc", "demo-device")
    stats = FleetStats()
    await world["service"].refresh_releases()

    async def other_firmware(_rid: bytes) -> bytes:
        return FW2

    world["service"].firmware = other_firmware  # type: ignore[method-assign]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=world["app"]), base_url="http://g"
    ) as client:
        agent = DeviceAgent(device, client, stats)
        await agent.hello()
        await agent.step()
    assert stats.errors == 1 and stats.installs == 0
    assert device.installed_version == SemVer(0, 0, 0)


def test_cli_prints_stats(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def fake_run(*_a: Any, **_k: Any) -> FleetStats:
        return FleetStats(polls=2, installs=1, receipts=1)

    monkeypatch.setattr(cli, "run_fleet", fake_run)
    result = CliRunner().invoke(
        cli.app, ["run", "--count", "2", "--rounds", "1", "--state-dir", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["installs"] == 1
