"""Service with a gateway key: signed records, batching, reputation signals, registry endpoints."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
from eth_account import Account
from fake_chain import FIXTURES, FakeChain, publish
from fastapi.testclient import TestClient

from verigate.common.chain import publisher_id
from verigate.common.crypto import KeyPair
from verigate.common.ipfs import LocalCidBackend, compute_cid
from verigate.common.manifest import SignedManifest
from verigate.common.merkle import verify_proof
from verigate.common.settings import Settings
from verigate.fleet.device import Device
from verigate.gateway.api.main import create_app
from verigate.gateway.service import GatewayService
from verigate.gateway.verdicts.record import VerdictRecord

DID = "did:verigate:v4"
FW1 = (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()
FW2 = (FIXTURES / "v1.1.0" / "firmware.bin").read_bytes()
GATEWAY_KEY = "0x" + "33" * 32


@pytest.fixture
def world(tmp_path: Path, settings: Settings) -> dict[str, Any]:
    chain = FakeChain()
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    key = KeyPair.generate()
    pid = chain.add_publisher(DID, key)
    rid, _ = publish(chain, ipfs, key, DID, "1.0.0", FW1)
    cfg = settings.model_copy(
        update={"gateway_private_key": GATEWAY_KEY, "batch_max_size": 2, "batch_max_wait_s": 60}
    )
    service = GatewayService(settings=cfg, chain=chain, ipfs=ipfs, state_dir=tmp_path / "state")  # type: ignore[arg-type]
    return {"chain": chain, "ipfs": ipfs, "key": key, "pid": pid, "rid": rid, "service": service}


@pytest.fixture
def client(world: dict[str, Any]) -> TestClient:
    with TestClient(create_app(world["service"], start_listener=False)) as c:
        yield c


async def test_approve_produces_signed_record_and_batch(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    chain: FakeChain = world["chain"]
    assert service.batcher is not None and service.gateway_account is not None
    first = await service.verify(world["rid"])
    assert first.verdict.value == "APPROVE" and first.r_bp == 1000 and first.policy_version == 1
    assert first.verdict_id is not None and service.batcher.pending == 1
    assert service.batcher.proof(first.verdict_id) == {
        "verdictId": first.verdict_id,
        "status": "pending",
    }
    second = await service.verify(world["rid"])  # batch_max_size=2 → commit
    assert service.batcher.pending == 0 and len(chain.committed) == 1
    proof = service.batcher.proof(second.verdict_id or "")
    assert proof is not None and proof["status"] == "committed"
    record = VerdictRecord.model_validate(proof["record"])
    assert record.signer() == Account.from_key(GATEWAY_KEY).address
    assert record.verdict.value == "APPROVE" and record.R == 1000 and record.reputation == 5000
    assert verify_proof(
        chain.committed[0]["root"], record.leaf(), [bytes.fromhex(p[2:]) for p in proof["proof"]]
    )
    assert chain.reputations == []  # approvals do not touch reputation


async def test_release_level_reject_lowers_reputation(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    chain: FakeChain = world["chain"]
    rid, _ = publish(
        chain, world["ipfs"], world["key"], DID, "1.0.1", FW1, firmware_cid=compute_cid(FW2)
    )
    world["ipfs"].put(FW2)
    result = await service.verify(rid)
    assert (
        result.verdict.value == "REJECT" and result.r_bp == 10_000 and result.policy_version is None
    )
    assert chain.reputations == [(world["pid"], 4500)]
    # device-level rejections (rollback) do not
    from verigate.common.manifest import SemVer  # noqa: PLC0415
    from verigate.gateway.stage1.inputs import DeviceView  # noqa: PLC0415

    await service.verify(world["rid"], DeviceView("d", "demo-device", SemVer(9, 0, 0)))
    assert len(chain.reputations) == 1
    # Stage-1 failure records carry the failing check in the feature hash and no models
    entry = service.verdicts.recent(5)[0]
    assert entry["verdict"] == "REJECT" and entry["modelHashes"] == [] and entry["R"] == 10_000


async def test_policy_reject_lowers_reputation(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    chain: FakeChain = world["chain"]
    chain.publisher_records[world["pid"]] = chain.get_publisher(world["pid"]).__class__(
        **{**chain.get_publisher(world["pid"]).__dict__, "reputation_bp": 100}
    )
    chain.policy_record = chain.policy_record.__class__(
        0, 0, 10_000, 3000, 6000, 2, "0x" + "0" * 40, 1
    )
    result = await service.verify(world["rid"])
    assert result.verdict.value == "REJECT" and result.r_bp == 9900 and result.stage1 is not None
    assert result.stage1.ok  # Stage 1 passed; the policy rejected on reputation alone
    assert chain.reputations[-1][1] == 90


def test_receipt_raises_reputation_and_endpoints(
    client: TestClient, world: dict[str, Any], tmp_path: Path
) -> None:
    chain: FakeChain = world["chain"]
    device = Device(tmp_path / "fleet", "dev-r", "demo-device")
    now = int(time.time())
    client.post("/devices/hello", json=device.sign(device.hello_payload(), now).model_dump())
    poll = client.post(
        "/devices/poll", json=device.sign(device.hello_payload(), now).model_dump()
    ).json()
    update = poll["update"]
    firmware = client.get(update["firmwareUrl"]).content
    receipt = device.install(
        firmware, SignedManifest.model_validate(update["manifest"]), update["publisherKey"]
    )
    resp = client.post(
        "/devices/receipt", json=device.sign({"receipt": receipt.model_dump()}, now).model_dump()
    )
    assert resp.status_code == 200
    assert chain.reputations[-1] == (publisher_id(DID), 5500)

    assert client.get("/health").json()["gateway"] is not None
    assert client.get("/policy").json()["policy"]["version"] == 1
    pubs = client.get("/publishers").json()
    assert pubs[0]["did"] == DID and pubs[0]["reputation"] == 5500
    chain.add_model(b"\x0d" * 32)
    models = client.get("/models").json()
    assert models[0]["modelHash"] == "0x" + "0d" * 32 and models[0]["status"] == 1

    vid = poll["verdict"]["verdictId"]
    assert client.get(f"/verdicts/{vid}/proof").json()["status"] == "pending"
    flushed = client.post("/batches/flush").json()
    assert flushed["committed"]["count"] == 1 and flushed["pending"] == 0
    assert client.get(f"/verdicts/{vid}/proof").json()["status"] == "committed"
    assert client.get("/batches").json()[0]["count"] == 1
    assert client.get("/verdicts/0x" + "00" * 32 + "/proof").status_code == 404
    chain.down = True
    assert client.get("/publishers").json() == [] and client.get("/models").json() == []
    assert client.get("/policy").json()["policy"] is None


def test_endpoints_without_gateway_key(tmp_path: Path, settings: Settings) -> None:
    service = GatewayService(
        settings=settings,
        chain=FakeChain(),
        ipfs=LocalCidBackend(tmp_path / "i"),
        state_dir=tmp_path / "s",
    )  # type: ignore[arg-type]
    with TestClient(create_app(service, start_listener=False)) as client:
        assert client.get("/verdicts/0x" + "00" * 32 + "/proof").status_code == 503
        assert client.post("/batches/flush").status_code == 503
        assert client.get("/batches").json() == []
