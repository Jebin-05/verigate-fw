"""One emulated IoT device (P3-05): identity, NVS, A/B slots, self-verification, receipts.

Persistent state under ``<state_dir>/<device_id>/``: ``device.key`` (Ed25519), ``nvs.json``
(installed version, active slot, nonce counter, …), ``slot_a.bin`` / ``slot_b.bin``.

Defence in depth (Guide §5): even though the gateway already ran Stage 1, :meth:`Device.install`
re-checks the firmware hash, the manifest signature, the device model and the version before
touching a slot. Given a :class:`ChainView`, the device also reads the publisher key and the
release record from the chain itself instead of trusting what the gateway hands it, so a
compromised gateway cannot make it install code that is unsigned, unregistered, withdrawn, signed
by a revoked key or downgraded. (It can still approve a registered release the gate would have
held; that verdict is anchored on-chain with its feature hash, so the lie is auditable.)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from verigate.common.canonical import canonical_json
from verigate.common.chain import PublisherRecord, ReleaseRecord, publisher_id
from verigate.common.crypto import KeyPair, parse_hash, sha256
from verigate.common.errors import VerificationError
from verigate.common.logging import get_logger
from verigate.common.manifest import SemVer, SignedManifest
from verigate.common.protocol import InstallReceipt, SignedMessage, sign_message

log = get_logger(__name__)

SLOTS = ("a", "b")


class ChainView(Protocol):
    """The two registry reads a device needs (``ChainClient`` satisfies it)."""

    def get_publisher(self, publisher_id: bytes) -> PublisherRecord:
        """PublisherRegistry record."""
        ...

    def get_release(self, release_id: bytes) -> ReleaseRecord:
        """FirmwareRegistry record."""
        ...


@dataclass(frozen=True)
class NvsState:
    """Contents of ``nvs.json``."""

    device_id: str
    device_model: str
    installed_version: str
    active_slot: str
    installed_release_id: str | None
    nonce: int

    def to_json(self) -> str:
        """Serialise for ``nvs.json``."""
        return json.dumps(self.__dict__, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> NvsState:
        """Parse ``nvs.json``."""
        data = json.loads(text)
        return cls(**{k: data[k] for k in cls.__dataclass_fields__})


class Device:
    """A device with persistent identity and firmware state."""

    def __init__(self, state_dir: Path, device_id: str, device_model: str) -> None:
        self.dir = state_dir / device_id
        self.dir.mkdir(parents=True, exist_ok=True)
        key_path = self.dir / "device.key"
        self.key = KeyPair.load(key_path) if key_path.is_file() else KeyPair.generate()
        if not key_path.is_file():
            self.key.save(self.dir, "device")
        nvs_path = self.dir / "nvs.json"
        if nvs_path.is_file():
            self._nvs = NvsState.from_json(nvs_path.read_text())
        else:
            self._nvs = NvsState(device_id, device_model, "0.0.0", "a", None, 0)
            self._persist()
        for slot in SLOTS:
            (self.dir / f"slot_{slot}.bin").touch()

    # ------------------------------------------------------------------ state

    @property
    def device_id(self) -> str:
        """Stable identifier (directory name)."""
        return self._nvs.device_id

    @property
    def device_model(self) -> str:
        """Hardware model string the manifest must match."""
        return self._nvs.device_model

    @property
    def installed_version(self) -> SemVer:
        """Persistent monotonic counter used by Stage-1 check #4."""
        return SemVer.parse(self._nvs.installed_version)

    @property
    def state(self) -> NvsState:
        """A snapshot of ``nvs.json``."""
        return self._nvs

    @property
    def public_key(self) -> str:
        """``"ed25519:<hex>"`` — sent in ``hello`` and pinned by the gateway."""
        return self.key.public_encoded

    def _persist(self) -> None:
        tmp = self.dir / "nvs.json.tmp"
        tmp.write_text(self._nvs.to_json())
        tmp.replace(self.dir / "nvs.json")

    # ------------------------------------------------------------------ protocol

    def sign(self, payload: dict[str, Any], now: int) -> SignedMessage:
        """Sign ``payload`` with the next nonce (persisted first so a crash cannot reuse it)."""
        self._nvs = NvsState(**{**self._nvs.__dict__, "nonce": self._nvs.nonce + 1})
        self._persist()
        return sign_message(self.key, self.device_id, self._nvs.nonce, now, payload)

    def hello_payload(self) -> dict[str, Any]:
        """Body of the ``hello`` / ``poll`` messages."""
        return {
            "deviceModel": self.device_model,
            "installedVersion": str(self.installed_version),
            "publicKey": self.public_key,
        }

    # ------------------------------------------------------------------ install

    def install(
        self,
        firmware: bytes,
        manifest: SignedManifest,
        publisher_key: bytes | str,
        now: datetime | None = None,
        chain: ChainView | None = None,
    ) -> InstallReceipt:
        """Self-verify, write the inactive slot, switch, bump the version, sign a receipt.

        With ``chain``, the signature is checked under the *on-chain* key (``publisher_key`` from
        the gateway is ignored) and the release must be registered, current and match.

        Raises:
            VerificationError: On any failed self-check; the slots are untouched.
        """
        if chain is not None:
            publisher_key = self._check_chain(firmware, manifest, chain)
        if not manifest.verify(publisher_key):
            raise VerificationError("device self-check: manifest signature invalid")
        if sha256(firmware) != parse_hash(manifest.firmwareHash):
            raise VerificationError("device self-check: firmware hash mismatch")
        if manifest.deviceModel != self.device_model:
            raise VerificationError("device self-check: wrong device model")
        if manifest.version <= self.installed_version:
            raise VerificationError(
                f"device self-check: {manifest.version} <= installed {self.installed_version}"
            )
        inactive = "b" if self._nvs.active_slot == "a" else "a"
        slot_path = self.dir / f"slot_{inactive}.bin"
        tmp = slot_path.with_suffix(".tmp")
        tmp.write_bytes(firmware)
        tmp.replace(slot_path)
        installed_at = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
        release_id = "0x" + manifest.manifest_hash().hex()
        self._nvs = NvsState(
            device_id=self.device_id,
            device_model=self.device_model,
            installed_version=str(manifest.version),
            active_slot=inactive,
            installed_release_id=release_id,
            nonce=self._nvs.nonce,
        )
        self._persist()
        body = {
            "deviceId": self.device_id,
            "releaseId": release_id,
            "version": str(manifest.version),
            "installedAt": installed_at,
        }
        receipt = InstallReceipt(**body, signature=self.key.sign_encoded(canonical_json(body)))
        log.info(
            "device.installed",
            device_id=self.device_id,
            release_id=release_id,
            version=str(manifest.version),
            slot=inactive,
        )
        return receipt

    @staticmethod
    def _check_chain(firmware: bytes, manifest: SignedManifest, chain: ChainView) -> bytes:
        """Registry checks the device runs itself; returns the on-chain publisher key."""
        publisher = chain.get_publisher(publisher_id(manifest.publisherDid))
        if not publisher.is_active:
            raise VerificationError("device self-check: publisher not active on-chain")
        release = chain.get_release(manifest.manifest_hash())
        if not release.exists:
            raise VerificationError("device self-check: release not registered on-chain")
        if release.revoked:
            raise VerificationError("device self-check: release withdrawn on-chain")
        if release.publisher_id != publisher.publisher_id:
            raise VerificationError("device self-check: on-chain publisher mismatch")
        if release.firmware_hash != sha256(firmware):
            raise VerificationError("device self-check: firmware is not the registered image")
        return publisher.pub_key

    def active_image(self) -> bytes:
        """Bytes of the active slot."""
        return (self.dir / f"slot_{self._nvs.active_slot}.bin").read_bytes()
