"""Settings: env parsing, empty-address normalisation, derived paths, logging setup."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import structlog

from verigate.common.logging import configure_logging, get_logger
from verigate.common.settings import Settings, get_settings


def test_defaults_without_env_file() -> None:
    s = Settings(_env_file=None)
    assert s.chain_id == 31337
    assert s.deployment_name == "localhost"
    assert s.addresses_file == Path("contracts/deployments/localhost/addresses.json")
    assert s.is_dev is True
    assert s.publisher_registry_addr is None


def test_empty_string_addresses_become_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PUBLISHER_REGISTRY_ADDR", "")
    monkeypatch.setenv("VERDICT_REGISTRY_ADDR", "0x" + "1" * 40)
    monkeypatch.setenv("ARB_SEPOLIA_RPC_URL", "   ")
    s = Settings(_env_file=None)
    assert s.publisher_registry_addr is None
    assert s.verdict_registry_addr == "0x" + "1" * 40
    assert s.arb_sepolia_rpc_url is None


def test_env_file_is_read(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("CHAIN_ID=421614\nIPFS_BACKEND=local   # inline comment\nLLM_ENABLED=false\n")
    s = Settings(_env_file=env)
    assert s.chain_id == 421614
    assert s.deployment_name == "arbitrumSepolia"
    assert s.ipfs_backend == "local"
    assert s.llm_enabled is False
    assert Settings(_env_file=None, chain_id=5).deployment_name == "chain-5"


def test_invalid_values_rejected() -> None:
    with pytest.raises(ValueError, match="ipfs_backend"):
        Settings(_env_file=None, ipfs_backend="s3")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="fleet_size"):
        Settings(_env_file=None, fleet_size=0)


def test_get_settings_is_cached() -> None:
    get_settings.cache_clear()
    assert get_settings() is get_settings()
    get_settings.cache_clear()


def test_logging_json_in_ci(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(Settings(_env_file=None, verigate_env="ci", log_level="INFO"))
    log = get_logger("t")
    log.debug("hidden.event")
    log.info("visible.event", ok=False, release_id="r1")
    err = capsys.readouterr().err
    lines = [json.loads(line) for line in err.strip().splitlines()]
    assert len(lines) == 1
    assert lines[0]["event"] == "visible.event"
    assert lines[0]["ok"] is False
    assert lines[0]["module"] == "t"
    assert lines[0]["level"] == "info"


def test_logging_console_in_dev(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(Settings(_env_file=None, verigate_env="local", log_level="bogus"))
    get_logger("t").info("dev.event", k=1)
    assert "dev.event" in capsys.readouterr().err
    structlog.reset_defaults()


def test_module_level_logger_follows_later_configuration(
    capsys: pytest.CaptureFixture[str],
) -> None:
    structlog.reset_defaults()
    log = get_logger("early")  # created before configure_logging, like a module-level logger
    configure_logging(Settings(_env_file=None, verigate_env="ci"))
    log.info("late.event")
    captured = capsys.readouterr()
    assert captured.out == ""  # never on stdout (CLI JSON lives there)
    assert json.loads(captured.err.strip())["event"] == "late.event"
    structlog.reset_defaults()
