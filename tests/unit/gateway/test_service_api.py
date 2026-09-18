"""Gateway service + API on in-memory chain/IPFS: verdicts, DEFER on outage, device protocol."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fake_chain import FIXTURES, FakeChain, publish
from fastapi.testclient import TestClient

from verigate.common.chain import STATUS_REVOKED
from verigate.common.crypto import KeyPair
from verigate.common.errors import VerificationError, VerigateError
from verigate.common.ipfs import LocalCidBackend, compute_cid
from verigate.common.manifest import SemVer
from verigate.common.settings import Settings
from verigate.fleet.device import Device
from verigate.gateway.api.main import create_app
from verigate.gateway.service import GatewayService
from verigate.gateway.stage1.inputs import DeviceView

DID = "did:verigate:svc"
FW1 = (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()
FW2 = (FIXTURES / "v1.1.0" / "firmware.bin").read_bytes()
SBOM1 = (FIXTURES / "v1.0.0" / "sbom.json").read_bytes()


@pytest.fixture
def world(tmp_path: Path, settings: Settings) -> dict[str, Any]:
    chain = FakeChain()
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    key = KeyPair.generate()
    pid = chain.add_publisher(DID, key)
    rid1, m1 = publish(chain, ipfs, key, DID, "1.0.0", FW1, SBOM1)
    service = GatewayService(
        settings=settings, chain=chain, ipfs=ipfs, state_dir=tmp_path / "state"
    )  # type: ignore[arg-type]
    return {
        "chain": chain,
        "ipfs": ipfs,
        "key": key,
        "pid": pid,
        "rid1": rid1,
        "m1": m1,
        "service": service,
    }


@pytest.fixture
def client(world: dict[str, Any]) -> TestClient:
    app = create_app(world["service"], start_listener=False)
    with TestClient(app) as c:
        yield c


async def test_verify_release_level_approves_clean_release(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    result = await service.verify(world["rid1"])
    assert result.verdict.value == "APPROVE"
    assert result.stage1 is not None and result.stage1.ok
    assert result.version == "1.0.0" and result.device_model == "demo-device"
    assert service.verdicts.recent(1)[0]["verdict"] == "APPROVE"


async def test_verify_unknown_release_rejects(world: dict[str, Any]) -> None:
    result = await world["service"].verify(b"\x77" * 32)
    assert result.verdict.value == "REJECT"
    assert result.reason == "manifest unavailable"


async def test_chain_outage_defers(world: dict[str, Any]) -> None:
    world["chain"].down = True
    result = await world["service"].verify(world["rid1"])
    assert result.verdict.value == "DEFER"
    assert result.stage1 is None and "chain:" in (result.reason or "")
    health = await world["service"].health()
    assert health["chain"] is False and health["status"] == "ok"


async def test_ipfs_missing_artefact_defers(world: dict[str, Any], tmp_path: Path) -> None:
    (tmp_path / "ipfs" / world["m1"].cids.firmware).unlink()
    result = await world["service"].verify(world["rid1"])
    assert result.verdict.value == "DEFER"
    assert any(e.startswith("firmware:") for e in result.errors)


async def test_tampered_bytes_at_cid_reject(world: dict[str, Any]) -> None:
    # attacker publishes a manifest whose firmware CID points at other bytes
    rid, _ = publish(
        world["chain"],
        world["ipfs"],
        world["key"],
        DID,
        "1.0.1",
        FW1,
        firmware_cid=compute_cid(FW2),
    )
    world["ipfs"].put(FW2)
    result = await world["service"].verify(rid)
    assert result.verdict.value == "REJECT" and result.stage1 is not None
    assert result.stage1.failed == "firmware_hash"


async def test_revoked_publisher_rejects(world: dict[str, Any]) -> None:
    world["chain"].set_publisher_status(world["pid"], STATUS_REVOKED)
    result = await world["service"].verify(world["rid1"])
    assert result.stage1 is not None and result.stage1.failed == "publisher_active"


async def test_expired_manifest_defers(world: dict[str, Any]) -> None:
    rid, _ = publish(
        world["chain"],
        world["ipfs"],
        world["key"],
        DID,
        "1.0.2",
        FW1,
        expiry=datetime.now(UTC) + timedelta(seconds=1),
    )
    service: GatewayService = world["service"]
    service.now = lambda: datetime.now(UTC) + timedelta(minutes=5)  # type: ignore[method-assign]
    result = await service.verify(rid)
    assert result.verdict.value == "DEFER" and result.stage1 is not None
    assert result.stage1.failed == "expiry"


async def test_models_are_checked_when_configured(
    world: dict[str, Any], settings: Settings
) -> None:
    h = b"\x0c" * 32
    world["chain"].add_model(h, STATUS_REVOKED)
    service = GatewayService(
        settings=settings.model_copy(update={"stage2_model_hashes": "0x" + h.hex()}),
        chain=world["chain"],
        ipfs=world["ipfs"],
        state_dir=world["service"].state_dir,
    )
    result = await service.verify(world["rid1"])
    assert result.stage1 is not None and result.stage1.failed == "model_active"
    world["chain"].down = True
    assert (await service.verify(world["rid1"])).verdict.value == "DEFER"


async def test_device_version_counts(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    result = await service.verify(world["rid1"], DeviceView("d1", "demo-device", SemVer(1, 0, 0)))
    assert result.stage1 is not None and result.stage1.failed == "version_monotonic"
    assert result.device_id == "d1"


async def test_latest_for_and_refresh(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    assert await service.refresh_releases() == 1
    rid2, _ = publish(world["chain"], world["ipfs"], world["key"], DID, "1.1.0", FW2)
    publish(world["chain"], world["ipfs"], world["key"], DID, "2.0.0", FW2, model="other-model")
    publish(world["chain"], world["ipfs"], world["key"], DID, "1.2.0", FW2, revoked=True)
    await service.refresh_releases()
    best = service.latest_for("demo-device", SemVer(0, 0, 0))
    assert best is not None and best.release_id == rid2
    assert service.latest_for("demo-device", SemVer(1, 1, 0)) is None
    assert service.latest_for("unknown", SemVer(0, 0, 0)) is None
    assert [r.version for r in service.known_releases()] == [
        (1, 0, 0),
        (1, 1, 0),
        (2, 0, 0),
        (1, 2, 0),
    ]
    assert (await service.note_release(rid2)).release_id == rid2


# ------------------------------------------------------------------ HTTP API


def test_health_releases_and_verify_endpoints(client: TestClient, world: dict[str, Any]) -> None:
    assert client.get("/health").json()["status"] == "ok"
    releases = client.get("/releases?refresh=true").json()
    assert (
        len(releases) == 1
        and releases[0]["version"] == "1.0.0"
        and releases[0]["lastVerdict"] is None
    )
    rid = "0x" + world["rid1"].hex()
    body = client.post(f"/verify/{rid}").json()
    assert body["verdict"] == "APPROVE" and body["stage1"]["ok"] is True
    assert client.get("/releases").json()[0]["lastVerdict"] == "APPROVE"
    one = client.get(f"/releases/{rid}").json()
    assert one["manifest"]["version"] == "1.0.0"
    assert client.get(f"/releases/{rid}/manifest").json()["publisherDid"] == DID
    assert client.get(f"/releases/{rid}/firmware").content == FW1
    assert client.get("/verdicts?limit=5").json()[-1]["verdict"] == "APPROVE"
    assert client.post("/verify/0x1234").status_code == 400
    assert client.post("/verify/zz").status_code == 400
    assert client.get("/releases/0x" + "99" * 32).status_code == 404
    assert client.get("/releases/0x" + "99" * 32 + "/manifest").status_code == 404
    assert client.get("/releases/0x" + "99" * 32 + "/firmware").status_code == 503
    assert client.post(f"/verify/{rid}?device_id=ghost").status_code == 404


def test_device_protocol_happy_path(
    client: TestClient, world: dict[str, Any], tmp_path: Path
) -> None:
    device = Device(tmp_path / "fleet", "dev-1", "demo-device")
    hello = device.sign(device.hello_payload(), int(time.time()))
    assert client.post("/devices/hello", json=hello.model_dump()).status_code == 200
    assert client.get("/devices").json()[0]["device_id"] == "dev-1"

    poll = client.post(
        "/devices/poll", json=device.sign(device.hello_payload(), int(time.time())).model_dump()
    )
    assert poll.status_code == 200, poll.text
    update = poll.json()["update"]
    assert update["releaseId"] == "0x" + world["rid1"].hex()
    firmware = client.get(update["firmwareUrl"]).content
    from verigate.common.manifest import SignedManifest  # noqa: PLC0415

    receipt = device.install(
        firmware, SignedManifest.model_validate(update["manifest"]), update["publisherKey"]
    )
    resp = client.post(
        "/devices/receipt",
        json=device.sign({"receipt": receipt.model_dump()}, int(time.time())).model_dump(),
    )
    assert resp.status_code == 200
    assert resp.json()["installed_version"] == "1.0.0" and resp.json()["receipts"] == 1
    # nothing newer now
    again = client.post(
        "/devices/poll", json=device.sign(device.hello_payload(), int(time.time())).model_dump()
    )
    assert again.json()["update"] is None
    # /verify with device_id uses the recorded installed version → rollback rejected
    body = client.post(f"/verify/{update['releaseId']}?device_id=dev-1").json()
    assert body["verdict"] == "REJECT" and body["stage1"]["failed"] == "version_monotonic"


def test_device_protocol_rejections(client: TestClient, tmp_path: Path) -> None:
    device = Device(tmp_path / "fleet", "dev-2", "demo-device")
    now = int(time.time())
    # poll before hello
    assert (
        client.post(
            "/devices/poll", json=device.sign(device.hello_payload(), now).model_dump()
        ).status_code
        == 403
    )
    # hello without public key
    assert (
        client.post(
            "/devices/hello", json=device.sign({"deviceModel": "demo-device"}, now).model_dump()
        ).status_code
        == 403
    )
    hello = device.sign(device.hello_payload(), now)
    assert client.post("/devices/hello", json=hello.model_dump()).status_code == 200
    # replay of the same hello
    assert client.post("/devices/hello", json=hello.model_dump()).status_code == 403
    # a different key claiming the same id
    impostor = Device(tmp_path / "other", "dev-2", "demo-device")
    assert (
        client.post(
            "/devices/poll", json=impostor.sign(impostor.hello_payload(), now).model_dump()
        ).status_code
        == 403
    )
    # stale timestamp
    assert (
        client.post(
            "/devices/poll", json=device.sign(device.hello_payload(), now - 10_000).model_dump()
        ).status_code
        == 403
    )
    # malformed receipt / wrong device / bad receipt signature
    assert (
        client.post(
            "/devices/receipt", json=device.sign({"receipt": {"x": 1}}, now).model_dump()
        ).status_code
        == 403
    )
    bad = {
        "deviceId": "dev-9",
        "releaseId": "0x00",
        "version": "1.0.0",
        "installedAt": "x",
        "signature": "ed25519:" + "00" * 64,
    }
    assert (
        client.post(
            "/devices/receipt", json=device.sign({"receipt": bad}, now).model_dump()
        ).status_code
        == 403
    )
    bad["deviceId"] = "dev-2"
    assert (
        client.post(
            "/devices/receipt", json=device.sign({"receipt": bad}, now).model_dump()
        ).status_code
        == 403
    )
    # malformed envelope
    assert client.post("/devices/hello", json={"deviceId": "x"}).status_code == 422


async def test_service_error_types(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    with pytest.raises(VerigateError):
        await service.firmware(b"\x55" * 32)
    from verigate.common.protocol import sign_message  # noqa: PLC0415

    key = KeyPair.generate()
    msg = sign_message(key, "dev-x", 1, int(time.time()), {"publicKey": "ed25519:zz"})
    with pytest.raises(VerificationError):
        await service.device_hello(msg)


def test_websocket_streams_log_events(client: TestClient, world: dict[str, Any]) -> None:
    from verigate.common.logging import configure_logging, get_logger  # noqa: PLC0415
    from verigate.gateway.api.logs import hub  # noqa: PLC0415

    configure_logging(world["service"].settings, extra_processors=[hub.processor])
    with client.websocket_connect("/logs") as ws:
        get_logger("t").info("ws.probe", k=1)
        event = ws.receive_json()
        assert event["event"] == "ws.probe" and event["k"] == 1
    import structlog  # noqa: PLC0415

    structlog.reset_defaults()
