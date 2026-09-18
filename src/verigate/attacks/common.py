"""Shared plumbing for the attack scenarios (Guide §9): context, publishing helpers, reports.

Every attack is ``run(ctx) -> AttackReport``. It publishes something malicious with the powers the
scenario assumes (the demo publisher's key, a stolen key, an attacker's own key…), asks the
gateway to verify it, and reports the expected vs observed verdict. Attacks only ever touch the
local emulated fleet and the configured test chain (SECURITY.md).
"""

from __future__ import annotations

import secrets
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from eth_account.signers.local import LocalAccount

from verigate.common.chain import ChainClient, device_model_id, publisher_id
from verigate.common.crypto import KeyPair, sha256_hex
from verigate.common.errors import VerigateError
from verigate.common.ipfs import IpfsBackend, make_backend
from verigate.common.logging import get_logger
from verigate.common.manifest import Cids, Manifest, SemVer, SignedManifest
from verigate.common.settings import Settings
from verigate.fleet.device import Device
from verigate.publisher.release import ensure_key, ensure_registered, register_on_chain

log = get_logger(__name__)

FIXTURES_DIRS = (Path("tests/fixtures/releases"), Path("/app/fixtures/releases"))
DEVICE_MODEL = "demo-device"


@dataclass
class AttackReport:
    """What every attack returns and the e2e tests assert on."""

    name: str
    expected: str
    accepted: tuple[str, ...] = ()  # other outcomes the scenario also counts as caught
    observed: str | None = None
    check: str | None = None
    reason: str | None = None
    release_id: str | None = None
    device_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """True iff the gateway produced the verdict the scenario predicts."""
        return self.observed is not None and self.observed in (self.expected, *self.accepted)

    def to_dict(self) -> dict[str, Any]:
        """JSON form (includes ``passed``)."""
        return {**asdict(self), "passed": self.passed}


@dataclass
class AttackContext:
    """Clients and identities an attack may use."""

    settings: Settings
    chain: ChainClient
    ipfs: IpfsBackend
    gateway_url: str
    did: str
    key: KeyPair
    publisher_account: LocalAccount
    admin_account: LocalAccount
    fixtures: Path
    workdir: Path

    @classmethod
    def from_settings(cls, settings: Settings, gateway_url: str | None = None) -> AttackContext:
        """Wire real clients; the demo publisher identity comes from ``.env`` / ``KEYS_DIR``."""
        chain = ChainClient(settings)
        fixtures = next((d for d in FIXTURES_DIRS if d.is_dir()), None)
        if fixtures is None:
            raise VerigateError("release fixtures not found (tests/fixtures/releases)")
        if not settings.publisher_private_key or not settings.deployer_private_key:
            raise VerigateError("PUBLISHER_PRIVATE_KEY and DEPLOYER_PRIVATE_KEY must be set")
        return cls(
            settings=settings,
            chain=chain,
            ipfs=make_backend(settings),
            gateway_url=gateway_url or f"http://127.0.0.1:{settings.gateway_port}",
            did=settings.publisher_did,
            key=ensure_key(settings.keys_dir, settings.publisher_did.replace(":", "_")),
            publisher_account=chain.account(settings.publisher_private_key),
            admin_account=chain.account(settings.deployer_private_key),
            fixtures=fixtures,
            workdir=settings.state_dir / "attacks",
        )

    # ------------------------------------------------------------------ helpers

    def fixture(self, version: str, name: str) -> bytes:
        """Bytes of ``tests/fixtures/releases/v<version>/<name>`` (or ``<dir>/<name>``)."""
        directory = version if (self.fixtures / version).is_dir() else f"v{version}"
        return (self.fixtures / directory / name).read_bytes()

    def get(self, path: str, timeout: float = 60) -> Any:  # noqa: ANN401 — JSON
        """``GET`` on the gateway."""
        resp = httpx.get(f"{self.gateway_url}{path}", timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    def post(self, path: str, timeout: float = 300) -> Any:  # noqa: ANN401 — JSON
        """``POST`` on the gateway (no body)."""
        resp = httpx.post(f"{self.gateway_url}{path}", timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    def reputation_bp(self, did: str) -> int:
        """Current on-chain reputation of a publisher."""
        return self.chain.get_publisher(publisher_id(did)).reputation_bp

    def next_version(self, did: str | None = None, model: str = DEVICE_MODEL) -> SemVer:
        """A version strictly above the publisher's last on-chain version for ``model``."""
        pid = publisher_id(did or self.did)
        packed = int(
            self.chain.call(self.chain.firmware.functions.lastVersion(pid, device_model_id(model)))
        )
        major, minor, patch = packed >> 64, (packed >> 32) & 0xFFFFFFFF, packed & 0xFFFFFFFF
        return SemVer(major, minor, patch + 1) if packed else SemVer(1, 0, 0)

    def build_manifest(
        self,
        firmware: bytes,
        sbom: bytes,
        version: SemVer,
        did: str | None = None,
        expiry: datetime | None = None,
        firmware_cid: str | None = None,
        sbom_cid: str | None = None,
    ) -> Manifest:
        """Put artefacts on IPFS and build a manifest; CID overrides are the attack surface."""
        real_fw = self.ipfs.put(firmware)
        real_sbom = self.ipfs.put(sbom)
        return Manifest(
            firmwareHash=sha256_hex(firmware),
            sbomHash=sha256_hex(sbom),
            version=version,
            deviceModel=DEVICE_MODEL,
            expiry=expiry or datetime(2030, 1, 1, tzinfo=UTC),
            cids=Cids(firmware=firmware_cid or real_fw, sbom=sbom_cid or real_sbom),
            publisherDid=did or self.did,
        )

    def publish(self, signed: SignedManifest, account: LocalAccount) -> str:
        """Put the signed manifest on IPFS and register it on-chain; returns ``0x…releaseId``."""
        manifest_cid = self.ipfs.put(signed.model_dump_json().encode())
        status, tx = register_on_chain(self.chain, account, signed, manifest_cid)
        rid = "0x" + signed.manifest_hash().hex()
        log.info("attack.published", release_id=rid, status=status, tx=tx)
        return rid

    def ensure_demo_publisher(self) -> None:
        """Make sure the demo publisher is registered with the local key (idempotent)."""
        ensure_registered(self.chain, self.publisher_account, self.did, self.key)

    def funded_account(self, eth: float = 1.0) -> LocalAccount:
        """A fresh account funded by the admin (attackers need gas too)."""
        account = self.chain.account("0x" + secrets.token_hex(32))
        w3 = self.chain.w3
        tx = {
            "from": self.admin_account.address,
            "to": account.address,
            "value": w3.to_wei(eth, "ether"),
            "nonce": w3.eth.get_transaction_count(self.admin_account.address),
            "chainId": self.settings.chain_id,
            "gas": 21_000,
            "gasPrice": w3.eth.gas_price,
        }
        signed = w3.eth.account.sign_transaction(tx, self.admin_account.key)
        w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed.raw_transaction))
        return account

    def chain_now(self) -> int:
        """The chain's notion of "now": mine a block (a 0-value transfer) and read its timestamp.

        A local Hardhat node's clock drifts ahead of the wall clock; contracts compare against
        ``block.timestamp``, so expiries must be anchored here.
        """
        w3 = self.chain.w3
        tx = {
            "from": self.admin_account.address,
            "to": self.admin_account.address,
            "value": 0,
            "nonce": w3.eth.get_transaction_count(self.admin_account.address),
            "chainId": self.settings.chain_id,
            "gas": 21_000,
            "gasPrice": w3.eth.gas_price,
        }
        signed = w3.eth.account.sign_transaction(tx, self.admin_account.key)
        receipt = w3.eth.wait_for_transaction_receipt(
            w3.eth.send_raw_transaction(signed.raw_transaction)
        )
        return int(w3.eth.get_block(receipt["blockNumber"])["timestamp"])

    def new_publisher(self, prefix: str) -> tuple[str, KeyPair, LocalAccount]:
        """Register a brand-new publisher (its own DID, key and funded account)."""
        did = f"did:verigate:{prefix}-{secrets.token_hex(3)}"
        key = KeyPair.generate()
        account = self.funded_account()
        ensure_registered(self.chain, account, did, key)
        return did, key, account

    # ------------------------------------------------------------------ gateway

    def verify(self, release_id: str, device_id: str | None = None) -> dict[str, Any]:
        """``POST /verify/{releaseId}`` on the gateway."""
        params = {"device_id": device_id} if device_id else None
        # Release-level verification waits for the LLM rationale (ADR-0002) — allow for a CPU host.
        resp = httpx.post(f"{self.gateway_url}/verify/{release_id}", params=params, timeout=300)
        resp.raise_for_status()
        body: dict[str, Any] = resp.json()
        return body

    def target_device(self, installed_version: SemVer, name: str = "attack-target") -> str:
        """Register (or update) an emulated device at ``installed_version`` on the gateway."""
        device = Device(self.workdir / "devices", name, DEVICE_MODEL)
        payload = {**device.hello_payload(), "installedVersion": str(installed_version)}
        msg = device.sign(payload, int(time.time()))
        resp = httpx.post(f"{self.gateway_url}/devices/hello", json=msg.model_dump(), timeout=30)
        resp.raise_for_status()
        return device.device_id


def fill(report: AttackReport, verdict: dict[str, Any]) -> AttackReport:
    """Copy the gateway's answer into the report."""
    stage1 = verdict.get("stage1") or {}
    report.observed = verdict.get("verdict")
    report.check = stage1.get("failed")
    report.reason = verdict.get("reason")
    report.device_id = verdict.get("deviceId")
    report.details = {
        **report.details,
        "R": verdict.get("R"),
        "rSbom": verdict.get("rSbom"),
        "rImg": verdict.get("rImg"),
        "reputation": verdict.get("reputation"),
        "modelHashes": verdict.get("modelHashes"),
    }
    return report
