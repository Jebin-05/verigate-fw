"""Publisher-portal endpoints: identity, input validation, CLI hand-off, ownership on withdraw."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fake_chain import FIXTURES, FakeChain, publish
from fastapi.testclient import TestClient

from verigate.common.chain import publisher_id
from verigate.common.crypto import KeyPair
from verigate.common.ipfs import LocalCidBackend
from verigate.common.settings import Settings
from verigate.gateway.api import main
from verigate.gateway.api.main import create_app
from verigate.gateway.service import GatewayService

DID = "did:verigate:portal"
FW = (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()
SBOM = (FIXTURES / "v1.0.0" / "sbom.json").read_bytes()
GOOD = {"version": "1.0.0", "device_model": "demo-device", "expiry": "2030-01-01T00:00:00Z"}


@pytest.fixture
def world(tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    chain = FakeChain()
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    key = KeyPair.generate()
    chain.add_publisher(DID, key)
    other_key = KeyPair.generate()
    chain.add_publisher("did:verigate:someone-else", other_key)
    own, _ = publish(chain, ipfs, key, DID, "1.0.0", FW)
    theirs, _ = publish(chain, ipfs, other_key, "did:verigate:someone-else", "1.0.0", FW)
    cfg = settings.model_copy(update={"publisher_did": DID})
    service = GatewayService(settings=cfg, chain=chain, ipfs=ipfs, state_dir=tmp_path / "state")  # type: ignore[arg-type]
    calls: list[tuple[str, list[str]]] = []

    async def fake_cli(name: str, args: list[str]) -> dict[str, Any]:
        calls.append((name, args))
        if args[0] == "release":
            return {"releaseId": "0x" + own.hex(), "version": args[args.index("--version") + 1]}
        return {"releaseId": args[1], "status": "revoked"}

    monkeypatch.setattr(main, "_run_cli", fake_cli)
    return {"service": service, "calls": calls, "own": own, "theirs": theirs, "chain": chain}


@pytest.fixture
def client(world: dict[str, Any]) -> TestClient:
    with TestClient(create_app(world["service"], start_listener=False)) as c:
        yield c


def test_me_reports_the_configured_publisher(client: TestClient, world: dict[str, Any]) -> None:
    me = client.get("/publisher/me").json()
    assert me["did"] == DID and me["registered"] is True
    assert me["publisherId"] == "0x" + publisher_id(DID).hex()
    assert me["reputation"] == 5000 and me["publicKey"].startswith("ed25519:")


def test_publish_hands_the_files_to_the_cli(client: TestClient, world: dict[str, Any]) -> None:
    resp = client.post(
        "/publisher/releases",
        files={"firmware": ("fw.bin", FW), "sbom": ("sbom.json", SBOM)},
        data={**GOOD, "version": "1.2.3", "expiry": "2031-06-01"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["version"] == "1.2.3"
    (name, args), *_ = world["calls"]
    assert name == "verigate-publish" and args[0] == "release"
    assert args[args.index("--version") + 1] == "1.2.3"
    assert args[args.index("--model") + 1] == "demo-device"
    assert args[args.index("--expiry") + 1] == "2031-06-01T00:00:00Z"
    fw_path = Path(args[args.index("--fw") + 1])
    assert fw_path.name == "firmware.bin" and not fw_path.exists()  # temp dir cleaned up


@pytest.mark.parametrize(
    ("data", "files", "fragment"),
    [
        ({**GOOD, "version": "v1"}, None, "MAJOR.MINOR.PATCH"),
        ({**GOOD, "expiry": "next year"}, None, "ISO-8601"),
        ({**GOOD, "expiry": "2000-01-01"}, None, "future"),
        ({**GOOD, "device_model": "bad model!"}, None, "device model"),
        (GOOD, {"firmware": ("fw.bin", b""), "sbom": ("s.json", SBOM)}, "empty"),
        (GOOD, {"firmware": ("fw.bin", FW), "sbom": ("s.json", b"not json")}, "CycloneDX"),
    ],
)
def test_publish_rejects_bad_input_before_touching_the_cli(
    client: TestClient,
    world: dict[str, Any],
    data: dict[str, str],
    files: dict[str, tuple[str, bytes]] | None,
    fragment: str,
) -> None:
    resp = client.post(
        "/publisher/releases",
        files=files or {"firmware": ("fw.bin", FW), "sbom": ("sbom.json", SBOM)},
        data=data,
    )
    assert resp.status_code == 400 and fragment in resp.json()["detail"]
    assert world["calls"] == []


def test_withdraw_only_own_releases(client: TestClient, world: dict[str, Any]) -> None:
    own = "0x" + world["own"].hex()
    assert client.post(f"/publisher/releases/{own}/withdraw").json()["status"] == "revoked"
    assert world["calls"][-1] == ("verigate-publish", ["revoke", own])
    theirs = "0x" + world["theirs"].hex()
    assert client.post(f"/publisher/releases/{theirs}/withdraw").status_code == 403
    assert client.post("/publisher/releases/0x" + "00" * 32 + "/withdraw").status_code == 404
    assert client.post("/publisher/releases/nothex/withdraw").status_code == 400
    assert len(world["calls"]) == 1  # the refused ones never reached the CLI
