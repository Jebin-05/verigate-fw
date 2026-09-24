"""All configuration, read once from ``.env`` / the environment (pydantic-settings).

This is the **only** module that reads environment variables. Everything else receives a
:class:`Settings` instance (or the specific values it needs) as an argument, so pure functions
stay pure and tests can construct settings explicitly with ``Settings(_env_file=None, ...)``.

Every field is documented in ``.env.example``; add new fields there in the same PR.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEPLOYMENT_NAMES: dict[int, str] = {31337: "localhost", 421614: "arbitrumSepolia"}


class Settings(BaseSettings):
    """Typed view of ``.env``. Field names are the lower-case form of the variable names."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", frozen=True
    )

    verigate_env: Literal["local", "ci", "docker", "sepolia"] = "local"

    # --- blockchain
    rpc_url: str = "http://127.0.0.1:8545"
    chain_id: int = 31337
    deployer_private_key: str = ""
    gateway_private_key: str = ""
    publisher_registry_addr: str | None = None
    firmware_registry_addr: str | None = None
    model_registry_addr: str | None = None
    policy_contract_addr: str | None = None
    verdict_registry_addr: str | None = None
    deployments_dir: Path = Path("contracts/deployments")

    # --- publisher CLI
    publisher_did: str = "did:verigate:demo-publisher"
    publisher_private_key: str = ""  # Ethereum account that pays for register/release txs
    keys_dir: Path = Path("keys")  # Ed25519 signing keys (git-ignored)

    # --- IPFS
    ipfs_api: str = "http://127.0.0.1:5001"
    ipfs_backend: Literal["kubo", "local"] = "kubo"
    local_ipfs_dir: Path = Path(".verigate/ipfs-local")

    # --- LLM explainer
    ollama_url: str = "http://127.0.0.1:11434"
    llm_model: str = "qwen2.5:3b-instruct"
    llm_enabled: bool = True
    llm_timeout_s: float = 120.0  # per attempt (manual §P6); raise on slow CPU-only hosts
    llm_auto_explain: bool = (
        True  # write after every release-level verdict; false = on request only
    )

    # --- vulnerability data
    osv_api: str = "https://api.osv.dev/v1"
    epss_url: str = "https://epss.empiricalsecurity.com"
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    vuln_cache_only: bool = False
    vuln_cache_dir: Path = Path("data/processed/vulndb")

    # --- ports (host side; containers always listen on the defaults)
    hardhat_port: int = 8545
    ipfs_api_port: int = 5001
    ipfs_gateway_port: int = 8080
    ollama_port: int = 11434
    gateway_port: int = 8000
    dashboard_port: int = 5173
    fleet_size: int = Field(default=20, ge=1)

    # --- gateway
    gateway_host: str = "0.0.0.0"  # noqa: S104 — container-friendly default (ADR-0004)
    log_level: str = "INFO"
    state_dir: Path = Path(".verigate/state")  # devices, verdict log, listener cursor
    listener_poll_s: float = Field(default=2.0, gt=0)
    protocol_window_s: int = Field(default=120, ge=1)
    stage2_model_hashes: str = ""  # comma-separated hex; empty until P5 registers a model
    models_dir: Path = Path("models")
    sbom_model: str = ""  # e.g. sbom_risk.onnx — empty disables the SBOM scorer
    image_model: str = ""  # e.g. image_anomaly.onnx — empty disables the image scorer
    stage2_epss_date: str = "2025-09-18"  # EPSS snapshot used at inference (recorded in results)
    batch_max_size: int = Field(default=50, ge=1)  # ADR-0005
    batch_max_wait_s: float = Field(default=10.0, gt=0)  # ADR-0005
    reputation_alpha_bp: int = Field(default=1000, ge=1, le=10_000)  # ADR-0006

    # --- Arbitrum Sepolia (evaluation only; never set in .env.example)
    arb_sepolia_rpc_url: str | None = None
    arb_sepolia_deployer_key: str | None = None

    @field_validator(
        "publisher_registry_addr",
        "firmware_registry_addr",
        "model_registry_addr",
        "policy_contract_addr",
        "verdict_registry_addr",
        "arb_sepolia_rpc_url",
        "arb_sepolia_deployer_key",
        mode="before",
    )
    @classmethod
    def _empty_is_none(cls, value: object) -> object:
        """``.env.example`` ships these as ``KEY=`` — treat an empty string as unset."""
        return None if isinstance(value, str) and value.strip() == "" else value

    @property
    def deployment_name(self) -> str:
        """Sub-directory of ``deployments_dir`` for this chain (e.g. ``localhost``)."""
        return DEPLOYMENT_NAMES.get(self.chain_id, f"chain-{self.chain_id}")

    @property
    def addresses_file(self) -> Path:
        """Path of ``addresses.json`` written by ``contracts/scripts/deploy.ts`` for this chain."""
        return self.deployments_dir / self.deployment_name / "addresses.json"

    @property
    def is_dev(self) -> bool:
        """True for a developer laptop (pretty logs); False in CI/containers (JSON logs)."""
        return self.verigate_env == "local"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings, loaded once. Entry points call this; libraries take ``Settings``."""
    return Settings()
