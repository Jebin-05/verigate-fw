"""verigate-publish: every command prints one JSON object; failures exit 1 with {"error": ...}."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from verigate.common.settings import Settings
from verigate.publisher import cli

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "releases"
runner = CliRunner()


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fake_chain: Any) -> Settings:
    settings = Settings(
        _env_file=None,
        verigate_env="ci",
        ipfs_backend="local",
        local_ipfs_dir=tmp_path / "ipfs",
        keys_dir=tmp_path / "keys",
        publisher_private_key="0x" + "ab" * 32,
    )
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "ChainClient", lambda _settings: fake_chain)
    return settings


def run(*args: str) -> tuple[int, dict[str, Any]]:
    result = runner.invoke(cli.app, list(args))
    return result.exit_code, json.loads(result.stdout)


def test_keygen_and_register(env: Settings) -> None:
    code, out = run("keygen")
    assert code == 0
    assert out["publicKey"].startswith("ed25519:")
    assert Path(out["privateKeyFile"]).is_file()
    code, out = run("register")
    assert code == 0 and out["status"] == "registered" and out["did"] == env.publisher_did
    code, out = run("register", "--did", env.publisher_did)
    assert code == 0 and out["status"] == "unchanged"


def test_release_and_revoke(env: Settings) -> None:
    code, out = run(
        "release",
        "--fw",
        str(FIXTURES / "v1.0.0" / "firmware.bin"),
        "--sbom",
        str(FIXTURES / "v1.0.0" / "sbom.json"),
        "--version",
        "1.0.0",
        "--model",
        "demo-device",
        "--expiry",
        "2030-01-01T00:00:00Z",
        "--json",
    )
    assert code == 0, out
    assert out["status"] == "registered" and out["releaseId"].startswith("0x")
    assert set(out["cids"]) == {"firmware", "sbom", "manifest"}
    code, out2 = run("revoke", out["releaseId"])
    assert code == 0 and out2["status"] == "revoked"
    code, out3 = run("revoke", out["releaseId"])
    assert code == 0 and out3["status"] == "unchanged"


@pytest.mark.parametrize(
    ("args", "match"),
    [
        (["revoke", "0x1234"], "32 bytes"),
        (["revoke", "zz"], "hex"),
        (
            [
                "release",
                "--fw",
                "tests/fixtures/releases/v1.0.0/firmware.bin",
                "--sbom",
                "tests/fixtures/releases/v1.0.0/sbom.json",
                "--version",
                "1.0",
                "--model",
                "demo-device",
                "--expiry",
                "2030-01-01T00:00:00Z",
            ],
            "MAJOR.MINOR.PATCH",
        ),
        (
            [
                "release",
                "--fw",
                "tests/fixtures/releases/v1.0.0/firmware.bin",
                "--sbom",
                "tests/fixtures/releases/v1.0.0/sbom.json",
                "--version",
                "1.0.0",
                "--model",
                "demo-device",
                "--expiry",
                "2030-01-01T00:00:00",
            ],
            "timezone",
        ),
    ],
)
def test_errors_are_json(env: Settings, args: list[str], match: str) -> None:
    code, out = run(*args)
    assert code == 1
    assert match in out["error"]


def test_missing_publisher_key(env: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli, "get_settings", lambda: env.model_copy(update={"publisher_private_key": ""})
    )
    code, out = run("register")
    assert code == 1 and "PUBLISHER_PRIVATE_KEY" in out["error"]


def test_missing_file_is_a_usage_error(env: Settings) -> None:
    result = runner.invoke(
        cli.app,
        [
            "release",
            "--fw",
            "nope.bin",
            "--sbom",
            "x",
            "--version",
            "1.0.0",
            "--model",
            "m",
            "--expiry",
            "2030-01-01T00:00:00Z",
        ],
    )
    assert result.exit_code == 2
