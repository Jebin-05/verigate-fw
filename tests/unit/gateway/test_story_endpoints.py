"""Demonstration endpoints: fixture publish, one-device round, model cards, explanation status."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fake_chain import FIXTURES, FakeChain, publish
from fastapi.testclient import TestClient

from verigate.common.crypto import KeyPair
from verigate.common.ipfs import LocalCidBackend
from verigate.common.settings import Settings
from verigate.gateway.api import main
from verigate.gateway.api.main import create_app
from verigate.gateway.service import GatewayService

DID = "did:verigate:story"


@pytest.fixture
def world(tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    chain = FakeChain()
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    key = KeyPair.generate()
    chain.add_publisher(DID, key)
    rid, _ = publish(
        chain, ipfs, key, DID, "1.0.0", (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()
    )
    models = tmp_path / "models"
    models.mkdir()
    (models / "sbom_risk.onnx").write_bytes(b"onnx-bytes")
    (models / "sbom_risk.metrics.json").write_text(json.dumps({"test": {"mae": 0.17}}))
    (models / "sbom_risk.card.md").write_text("# Model card\nlimitations…\n")
    cfg = settings.model_copy(
        update={"publisher_did": DID, "models_dir": models, "sbom_model": "sbom_risk.onnx"}
    )
    service = GatewayService(settings=cfg, chain=chain, ipfs=ipfs, state_dir=tmp_path / "state")  # type: ignore[arg-type]
    calls: list[tuple[str, list[str]]] = []

    async def fake_cli(name: str, args: list[str]) -> dict[str, Any]:
        calls.append((name, args))
        if name == "verigate-publish":
            return {"releaseId": "0x" + rid.hex(), "version": args[args.index("--version") + 1]}
        return {"polls": 1, "installs": 1, "receipts": 1, "rejected": 0, "errors": 0}

    monkeypatch.setattr(main, "_run_cli", fake_cli)
    monkeypatch.setattr(chain, "call", lambda _fn: (2 << 64) | (0 << 32) | 3, raising=False)
    return {"service": service, "calls": calls, "rid": rid, "chain": chain}


@pytest.fixture
def client(world: dict[str, Any]) -> TestClient:
    with TestClient(create_app(world["service"], start_listener=False)) as c:
        yield c


def test_story_publish_uses_the_fixture_and_the_next_version(
    client: TestClient, world: dict[str, Any]
) -> None:
    resp = client.post("/story/publish", params={"fixture": "legacy-19.07.10"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["fixture"] == "legacy-19.07.10" and resp.json()["version"] == "2.0.4"
    (name, args), *_ = world["calls"]
    assert name == "verigate-publish" and args[0] == "release"
    assert args[args.index("--fw") + 1].endswith("legacy-19.07.10/firmware.bin")
    assert args[args.index("--model") + 1] == "demo-device"
    assert client.post("/story/publish", params={"fixture": "../../etc"}).status_code == 400


def test_simulate_device_runs_one_panel_device(client: TestClient, world: dict[str, Any]) -> None:
    stats = client.post("/simulate/device").json()
    assert stats["installs"] == 1
    (name, args) = world["calls"][-1]
    assert name == "verigate-fleet" and args[:5] == ["run", "--count", "1", "--rounds", "1"]
    assert args[args.index("--prefix") + 1] == "panel"


def test_model_cards_expose_metrics_and_card(client: TestClient) -> None:
    cards = client.get("/models/cards").json()
    assert len(cards) == 1
    card = cards[0]
    assert card["name"] == "sbom_risk" and card["modelHash"].startswith("0x")
    assert card["metrics"] == {"test": {"mae": 0.17}} and "limitations" in card["card"]


def test_rationale_status_when_the_explainer_is_off(
    client: TestClient, world: dict[str, Any]
) -> None:
    rid = "0x" + world["rid"].hex()
    assert client.get(f"/releases/{rid}/rationale").json() == {"status": "off"}
    assert client.get("/releases/nothex/rationale").status_code == 400
