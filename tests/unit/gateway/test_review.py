"""Human review: a person resolves a DEFER, anchored, applied to later verdicts."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fake_chain import FIXTURES, FakeChain, publish
from fastapi.testclient import TestClient

from verigate.common.crypto import KeyPair
from verigate.common.ipfs import LocalCidBackend
from verigate.common.manifest import SemVer
from verigate.common.settings import Settings
from verigate.gateway.api.main import create_app
from verigate.gateway.service import REVIEW_DEVICE_ID, GatewayService, ReviewError
from verigate.gateway.stage1.inputs import DeviceView
from verigate.gateway.verdicts.record import VerdictRecord
from verigate.gateway.verdicts.types import Verdict
from verigate.ml.data.mutate import CATALOGUE

DID = "did:verigate:review"
FW = (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()
GATEWAY_KEY = "0x" + "55" * 32
DEVICE = DeviceView("dev-1", "demo-device", SemVer(0, 9, 0))


@pytest.fixture
async def world(tmp_path: Path, settings: Settings) -> dict[str, Any]:
    """An approved build, then the same build with 256 bytes patched: held by check #9."""
    chain = FakeChain()
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    key = KeyPair.generate()
    pid = chain.add_publisher(DID, key)
    cfg = settings.model_copy(
        update={"gateway_private_key": GATEWAY_KEY, "batch_max_size": 1, "batch_max_wait_s": 60}
    )
    service = GatewayService(settings=cfg, chain=chain, ipfs=ipfs, state_dir=tmp_path / "state")  # type: ignore[arg-type]
    clean, _ = publish(chain, ipfs, key, DID, "1.0.0", FW)
    await service.refresh_releases()
    assert (await service.verify(clean)).verdict is Verdict.APPROVE
    held, _ = publish(chain, ipfs, key, DID, "1.0.1", CATALOGUE["byte-patch"].apply(FW, 3))
    await service.refresh_releases()
    first = await service.verify(held)
    assert first.verdict is Verdict.DEFER and first.stage1 is not None
    assert first.stage1.failed == "release_delta"
    return {"chain": chain, "ipfs": ipfs, "key": key, "pid": pid, "held": held, "service": service}


async def test_accept_turns_the_hold_into_approve_for_devices_too(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    chain: FakeChain = world["chain"]
    out = await service.review(world["held"], Verdict.APPROVE, "Asha", "vendor hot-fix, confirmed")
    assert out["review"]["decision"] == "APPROVE" and out["review"]["reviewer"] == "Asha"
    assert "previous trusted image" in (out["review"]["heldBecause"] or "")
    assert out["verdict"]["verdict"] == "APPROVE"
    assert out["verdict"]["reason"] == "accepted by reviewer Asha: vendor hot-fix, confirmed"
    device = await service.verify(world["held"], DEVICE)
    assert device.verdict is Verdict.APPROVE and device.reason is not None
    # the decision itself is a signed, anchored record that commits to who decided what
    records = [VerdictRecord.model_validate(b.records[0]) for b in service.batcher.batches()]  # type: ignore[union-attr]
    decision = next(r for r in records if r.deviceId == REVIEW_DEVICE_ID)
    assert decision.verdict is Verdict.APPROVE and decision.gatewaySig is not None
    assert "0x" + decision.leaf().hex() == out["review"]["reviewVerdictId"]
    assert chain.reputations == []


async def test_reject_blocks_and_lowers_reputation_once(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    chain: FakeChain = world["chain"]
    out = await service.review(world["held"], Verdict.REJECT, "Asha", "")
    assert out["verdict"]["verdict"] == "REJECT"
    assert out["verdict"]["reason"] == "rejected by reviewer Asha"
    assert (await service.verify(world["held"], DEVICE)).verdict is Verdict.REJECT
    await service.verify(world["held"])
    assert len(chain.reputations) == 1  # the reviewer's rejection, not every later verification


async def test_one_decision_per_release_and_only_for_holds(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    await service.review(world["held"], Verdict.APPROVE, "Asha")
    with pytest.raises(ReviewError, match="already been reviewed") as again:
        await service.review(world["held"], Verdict.REJECT, "Ben")
    assert again.value.status == 409
    approved, _ = publish(
        world["chain"], world["ipfs"], world["key"], DID, "2.0.0", FW + b"x" * 8192
    )
    await service.refresh_releases()
    with pytest.raises(ReviewError, match="the gate says") as not_held:
        await service.review(approved, Verdict.APPROVE, "Asha")
    assert not_held.value.status == 409
    with pytest.raises(ReviewError, match="APPROVE or REJECT"):
        await service.review(world["held"], Verdict.DEFER, "Asha")


async def test_an_expired_release_cannot_be_accepted(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    stale, _ = publish(
        world["chain"],
        world["ipfs"],
        world["key"],
        DID,
        "3.0.0",
        FW,
        expiry=datetime(2020, 1, 1, tzinfo=UTC),
    )
    await service.refresh_releases()
    assert (await service.verify(stale)).verdict is Verdict.DEFER
    with pytest.raises(ReviewError, match="expired"):
        await service.review(stale, Verdict.APPROVE, "Asha")


async def test_review_survives_a_restart(world: dict[str, Any], settings: Settings) -> None:
    service: GatewayService = world["service"]
    await service.review(world["held"], Verdict.APPROVE, "Asha")
    reborn = GatewayService(
        settings=service.settings,
        chain=world["chain"],
        ipfs=world["ipfs"],
        state_dir=service.state_dir,
    )
    await reborn.refresh_releases()
    assert (await reborn.verify(world["held"])).verdict is Verdict.APPROVE


def test_review_endpoints(world: dict[str, Any]) -> None:
    with TestClient(create_app(world["service"], start_listener=False)) as client:
        rid = "0x" + world["held"].hex()
        bad = client.post(f"/releases/{rid}/review", json={"decision": "DEFER", "reviewer": "x"})
        assert bad.status_code == 422
        empty = client.post(f"/releases/{rid}/review", json={"decision": "APPROVE", "reviewer": ""})
        assert empty.status_code == 422
        ok = client.post(
            f"/releases/{rid}/review",
            json={"decision": "APPROVE", "reviewer": " Asha ", "note": "ok"},
        )
        assert ok.status_code == 200 and ok.json()["review"]["reviewer"] == "Asha"
        again = client.post(f"/releases/{rid}/review", json={"decision": "REJECT", "reviewer": "B"})
        assert again.status_code == 409
        listed = {r["releaseId"]: r for r in client.get("/releases").json()}
        assert listed[rid]["review"]["decision"] == "APPROVE"
        assert [r["releaseId"] for r in client.get("/reviews").json()] == [rid]
