"""verigate-admin: every command prints JSON and sends the right transaction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from fake_chain import FakeChain
from typer.testing import CliRunner

from verigate.common.chain import publisher_id
from verigate.common.crypto import KeyPair
from verigate.common.settings import Settings
from verigate.gateway import admin

runner = CliRunner()


class AdminChain(FakeChain):
    """FakeChain that also accepts register/revoke/setPolicy/grantRole."""

    def send(self, call: Any, account: Any) -> dict[str, Any]:  # noqa: ANN401
        if call.name in ("register", "revoke", "setPolicy", "grantRole"):
            self.block += 1
            self.sent.append((call.name, call.args))
            if call.name == "register":
                self.add_model(call.args[0])
            return {"transactionHash": b"\xaa" * 32, "blockNumber": self.block, "status": 1}
        return super().send(call, account)


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> AdminChain:
    chain = AdminChain()
    chain.sent = []  # type: ignore[attr-defined]
    cfg = settings.model_copy(update={"deployer_private_key": "0x" + "ab" * 32})
    monkeypatch.setattr(admin, "get_settings", lambda: cfg)
    monkeypatch.setattr(admin, "ChainClient", lambda _s: chain)
    return chain


def run(*args: str) -> tuple[int, dict[str, Any]]:
    result = runner.invoke(admin.app, list(args))
    return result.exit_code, json.loads(result.stdout)


def test_register_and_revoke_model(env: AdminChain, tmp_path: Path) -> None:
    f = tmp_path / "m.onnx"
    f.write_bytes(b"onnx")
    code, out = run("register-model", "--file", str(f))
    assert code == 0 and out["status"] == "registered" and out["name"] == "m"
    assert out["modelHash"] == "0x" + hashlib.sha256(b"onnx").hexdigest()
    code, out = run("register-model", "--file", str(f))
    assert code == 0 and out["status"] == "unchanged"
    code, out = run("register-model", "--hash", "0x" + "11" * 32, "--name", "v2")
    assert code == 0 and out["status"] == "registered"
    code, out = run("register-model")
    assert code == 1 and "--file" in out["error"]
    code, out = run("revoke-model", "0x" + "11" * 32, "--successor", "0x" + "22" * 32)
    assert code == 0 and out["status"] == "revoked" and env.sent[-1][0] == "revoke"  # type: ignore[attr-defined]
    code, out = run("revoke-model", "0x12")
    assert code == 1


def test_policy_publisher_gateway(env: AdminChain) -> None:
    code, out = run(
        "set-policy",
        "--w-sbom",
        "5000",
        "--w-img",
        "3000",
        "--w-rep",
        "2000",
        "--tau-approve",
        "2500",
        "--tau-reject",
        "7000",
    )
    assert (
        code == 0
        and out["policy"]["version"] == 1
        and env.sent[-1][1] == (5000, 3000, 2000, 2500, 7000)
    )  # type: ignore[attr-defined]
    env.add_publisher("did:verigate:x", KeyPair.generate())
    code, out = run("revoke-publisher", "did:verigate:x")
    assert code == 0 and env.sent[-1][1] == (publisher_id("did:verigate:x"),)  # type: ignore[attr-defined]
    code, out = run("grant-gateway", "0x" + "cd" * 20)
    assert code == 0 and len(out["txHashes"]) == 2


def test_missing_admin_key(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    monkeypatch.setattr(
        admin, "get_settings", lambda: settings.model_copy(update={"deployer_private_key": ""})
    )
    code, out = run("revoke-publisher", "did:verigate:x")
    assert code == 1 and "DEPLOYER_PRIVATE_KEY" in out["error"]


def test_register_models_from_manifest(env: AdminChain, tmp_path: Path) -> None:
    manifest = tmp_path / "MANIFEST.sha256"
    manifest.write_text(
        f"{'11' * 32}  sbom_risk.onnx\n{'22' * 32}  successor/image_anomaly.onnx\n\n"
    )
    code, out = run("register-models", "--manifest", str(manifest))
    assert code == 0
    assert [m["status"] for m in out["models"]] == ["registered", "registered"]
    assert out["models"][1]["name"] == "successor/image_anomaly.onnx"
    code, out = run("register-models", "--manifest", str(manifest))
    assert code == 0 and [m["status"] for m in out["models"]] == ["unchanged", "unchanged"]
    manifest.write_text("zz  bad.onnx\n")
    code, out = run("register-models", "--manifest", str(manifest))
    assert code == 1 and "error" in out
