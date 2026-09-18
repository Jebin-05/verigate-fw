"""Release builder: hash → IPFS → manifest → sign → IPFS → on-chain (Guide §4, Phase A).

Every function takes its clients as arguments (no global settings, no ``os.environ``) and every
step is idempotent: re-running with the same inputs re-uses the same CIDs and, if the release is
already registered under the same manifest hash, reports ``"unchanged"`` instead of failing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from eth_account.signers.local import LocalAccount
from web3.types import TxReceipt

from verigate.common.chain import (
    STATUS_ACTIVE,
    STATUS_NONE,
    ChainClient,
    ContractRevertError,
    publisher_id,
)
from verigate.common.crypto import KeyPair, parse_hash, parse_signature, sha256_hex
from verigate.common.errors import VerificationError
from verigate.common.ipfs import IpfsBackend
from verigate.common.logging import get_logger
from verigate.common.manifest import Cids, Manifest, SemVer, SignedManifest

log = get_logger(__name__)


@dataclass(frozen=True)
class PublisherStatus:
    """Result of :func:`ensure_registered`."""

    did: str
    publisher_id: str
    owner: str
    public_key: str
    status: str  # "registered" | "unchanged" | "key-rotated"
    tx_hash: str | None


@dataclass(frozen=True)
class ReleaseResult:
    """Everything the CLI prints after ``release`` (machine-readable for tests and the demo)."""

    releaseId: str  # noqa: N815 — JSON output uses camelCase like the manifest
    manifestHash: str  # noqa: N815
    firmwareHash: str  # noqa: N815
    sbomHash: str  # noqa: N815
    version: str
    deviceModel: str  # noqa: N815
    expiry: str
    publisherDid: str  # noqa: N815
    cids: dict[str, str]
    txHash: str | None  # noqa: N815
    status: str  # "registered" | "unchanged"

    def to_dict(self) -> dict[str, Any]:
        """Plain dict for JSON output."""
        return asdict(self)


def tx_hex(receipt: TxReceipt) -> str:
    """``0x``-prefixed transaction hash of ``receipt``."""
    return "0x" + bytes(receipt["transactionHash"]).hex()


def ensure_key(keys_dir: Path, name: str) -> KeyPair:
    """Load ``keys_dir/<name>.key`` or generate it (idempotent)."""
    path = keys_dir / f"{name}.key"
    if path.is_file():
        return KeyPair.load(path)
    key = KeyPair.generate()
    key.save(keys_dir, name)
    log.info("publisher.keygen", path=str(path), public_key=key.public_encoded)
    return key


def ensure_registered(
    chain: ChainClient, account: LocalAccount, did: str, key: KeyPair
) -> PublisherStatus:
    """Register ``did`` with ``key`` if needed; rotate the key if the owner's key changed.

    Raises:
        VerificationError: If the DID is owned by another address or has been revoked.
    """
    pid = publisher_id(did)
    record = chain.get_publisher(pid)
    if record.status == STATUS_NONE:
        receipt = chain.send(chain.publishers.functions.register(did, key.public), account)
        log.info("publisher.registered", did=did, tx=tx_hex(receipt))
        return PublisherStatus(
            did,
            pid.hex(),
            account.address,
            key.public_encoded,
            "registered",
            tx_hex(receipt),
        )
    if record.owner != account.address:
        raise VerificationError(f"{did} is owned by {record.owner}, not {account.address}")
    if record.status != STATUS_ACTIVE:
        raise VerificationError(f"{did} has been revoked; register a new DID")
    if record.pub_key != key.public:
        receipt = chain.send(chain.publishers.functions.rotateKey(key.public), account)
        log.info("publisher.key_rotated", did=did, tx=tx_hex(receipt))
        return PublisherStatus(
            did,
            pid.hex(),
            account.address,
            key.public_encoded,
            "key-rotated",
            tx_hex(receipt),
        )
    return PublisherStatus(did, pid.hex(), account.address, key.public_encoded, "unchanged", None)


def build_manifest(
    ipfs: IpfsBackend,
    firmware: bytes,
    sbom: bytes,
    version: str,
    device_model: str,
    expiry: datetime,
    did: str,
) -> Manifest:
    """Hash both artefacts, put them on IPFS, and assemble the (unsigned) manifest."""
    firmware_cid = ipfs.put(firmware)
    sbom_cid = ipfs.put(sbom)
    return Manifest(
        firmwareHash=sha256_hex(firmware),
        sbomHash=sha256_hex(sbom),
        version=SemVer.parse(version),
        deviceModel=device_model,
        expiry=expiry,
        cids=Cids(firmware=firmware_cid, sbom=sbom_cid),
        publisherDid=did,
    )


def register_on_chain(
    chain: ChainClient, account: LocalAccount, signed: SignedManifest, manifest_cid: str
) -> tuple[str, str]:
    """``FirmwareRegistry.register`` for ``signed``; returns ``(status, tx_hash)``.

    ``status`` is ``"unchanged"`` when the same manifest hash is already registered.
    """
    release_id = signed.manifest_hash()
    existing = chain.get_release(release_id)
    if existing.exists:
        log.info("release.unchanged", release_id=release_id.hex())
        return "unchanged", ""
    version = signed.version
    record = {
        "deviceModel": signed.deviceModel,
        "major": version.major,
        "minor": version.minor,
        "patch": version.patch,
        "manifestHash": release_id,
        "firmwareHash": parse_hash(signed.firmwareHash),
        "sbomHash": parse_hash(signed.sbomHash),
        "expiry": int(signed.expiry.timestamp()),
        "manifestCid": manifest_cid,
        "firmwareCid": signed.cids.firmware,
        "sbomCid": signed.cids.sbom,
        "signature": parse_signature(signed.signature),
    }
    try:
        receipt = chain.send(chain.firmware.functions.register(record), account)
    except ContractRevertError as exc:
        raise VerificationError(
            f"FirmwareRegistry rejected the release: {exc.name or exc}"
        ) from exc
    tx = tx_hex(receipt)
    log.info("release.registered", release_id=release_id.hex(), tx=tx, version=str(version))
    return "registered", tx


def publish_release(
    chain: ChainClient,
    ipfs: IpfsBackend,
    account: LocalAccount,
    key: KeyPair,
    did: str,
    firmware_path: Path,
    sbom_path: Path,
    version: str,
    device_model: str,
    expiry: datetime,
) -> ReleaseResult:
    """The whole Phase-A flow for one release (idempotent end to end)."""
    ensure_registered(chain, account, did, key)
    firmware = firmware_path.read_bytes()
    sbom = sbom_path.read_bytes()
    manifest = build_manifest(ipfs, firmware, sbom, version, device_model, expiry, did)
    signed = manifest.sign(key)
    manifest_cid = ipfs.put(signed.model_dump_json().encode("utf-8"))
    status, tx = register_on_chain(chain, account, signed, manifest_cid)
    return ReleaseResult(
        releaseId="0x" + signed.manifest_hash().hex(),
        manifestHash="0x" + signed.manifest_hash().hex(),
        firmwareHash=signed.firmwareHash,
        sbomHash=signed.sbomHash,
        version=str(signed.version),
        deviceModel=signed.deviceModel,
        expiry=signed.model_dump(mode="json")["expiry"],
        publisherDid=did,
        cids={"firmware": signed.cids.firmware, "sbom": signed.cids.sbom, "manifest": manifest_cid},
        txHash=tx or None,
        status=status,
    )


def revoke_release(chain: ChainClient, account: LocalAccount, release_id: bytes) -> dict[str, Any]:
    """``FirmwareRegistry.revoke``; idempotent (already revoked → ``"unchanged"``)."""
    record = chain.get_release(release_id)
    if not record.exists:
        raise VerificationError(f"unknown release {release_id.hex()}")
    if record.revoked:
        return {"releaseId": "0x" + release_id.hex(), "status": "unchanged", "txHash": None}
    try:
        receipt = chain.send(chain.firmware.functions.revoke(release_id), account)
    except ContractRevertError as exc:
        raise VerificationError(f"revoke rejected: {exc.name or exc}") from exc
    tx = tx_hex(receipt)
    log.info("release.revoked", release_id=release_id.hex(), tx=tx)
    return {"releaseId": "0x" + release_id.hex(), "status": "revoked", "txHash": tx}
