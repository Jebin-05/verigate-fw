"""One emulated IoT device (P3-05): identity, NVS, A/B slots, self-verification, receipts.

Persistent state under ``<state_dir>/<device_id>/``: ``device.key`` (Ed25519), ``nvs.json``
(installed version, active slot, nonce counter, …), ``slot_a.bin`` / ``slot_b.bin``.

Defence in depth (Guide §5): even though the gateway already ran Stage 1, :meth:`Device.install`
re-checks the firmware hash, the manifest signature under the publisher key it is given, the
device model and the version before touching a slot. A compromised gateway cannot make a device
install unsigned or downgraded code.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from verigate.common.canonical import canonical_json
from verigate.common.crypto import KeyPair, parse_hash, sha256
from verigate.common.errors import VerificationError
from verigate.common.logging import get_logger
from verigate.common.manifest import SemVer, SignedManifest
from verigate.common.protocol import SignedMessage, sign_message

log = get_logger(__name__)

SLOTS = ("a", "b")


class InstallReceipt(BaseModel):
    """Signed proof that a device switched to a release (raises publisher reputation in P4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    deviceId: str  # noqa: N815 — wire format
    releaseId: str  # noqa: N815
    version: str
    installedAt: str  # noqa: N815
    signature: str

    def signed_bytes(self) -> bytes:
        """Canonical JSON of the receipt body (everything but the signature)."""
        return canonical_json(
            {
                "deviceId": self.deviceId,
                "releaseId": self.releaseId,
                "version": self.version,
                "installedAt": self.installedAt,
            }
        )


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
    ) -> InstallReceipt:
        """Self-verify, write the inactive slot, switch, bump the version, sign a receipt.

        Raises:
            VerificationError: On any failed self-check; the slots are untouched.
        """
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

    def active_image(self) -> bytes:
        """Bytes of the active slot."""
        return (self.dir / f"slot_{self._nvs.active_slot}.bin").read_bytes()
