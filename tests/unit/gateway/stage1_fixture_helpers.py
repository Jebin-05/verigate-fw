"""A fully valid Stage-1 input built from the fixture release, for mutation in tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from verigate.common.chain import (
    STATUS_ACTIVE,
    ModelRecord,
    PublisherRecord,
    ReleaseRecord,
    device_model_id,
    publisher_id,
)
from verigate.common.crypto import KeyPair, parse_hash, parse_signature, sha256_hex
from verigate.common.ipfs import compute_cid
from verigate.common.manifest import Cids, Manifest, SemVer, SignedManifest
from verigate.gateway.stage1.inputs import DeviceView, Stage1Input

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "releases"
DID = "did:verigate:unit-publisher"
NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
EXPIRY = datetime(2030, 1, 1, tzinfo=UTC)
MODEL_HASH = b"\x0a" * 32


@pytest.fixture(scope="session")
def publisher_key() -> KeyPair:
    return KeyPair.generate()


@pytest.fixture(scope="session")
def firmware() -> bytes:
    return (FIXTURES / "v1.1.0" / "firmware.bin").read_bytes()


@pytest.fixture(scope="session")
def sbom() -> bytes:
    return (FIXTURES / "v1.1.0" / "sbom.json").read_bytes()


@pytest.fixture(scope="session")
def signed_manifest(publisher_key: KeyPair, firmware: bytes, sbom: bytes) -> SignedManifest:
    return Manifest(
        firmwareHash=sha256_hex(firmware),
        sbomHash=sha256_hex(sbom),
        version=SemVer(1, 1, 0),
        deviceModel="demo-device",
        expiry=EXPIRY,
        cids=Cids(firmware=compute_cid(firmware), sbom=compute_cid(sbom)),
        publisherDid=DID,
    ).sign(publisher_key)


def publisher_record(key: KeyPair, status: int = STATUS_ACTIVE, did: str = DID) -> PublisherRecord:
    return PublisherRecord(
        publisher_id(did), did, "0x" + "ab" * 20, key.public, status, 5000, 0, 3, 0
    )


def release_record(signed: SignedManifest, **overrides: object) -> ReleaseRecord:
    base = ReleaseRecord(
        release_id=signed.manifest_hash(),
        publisher_id=publisher_id(signed.publisherDid),
        device_model_id=device_model_id(signed.deviceModel),
        major=signed.version.major,
        minor=signed.version.minor,
        patch=signed.version.patch,
        manifest_hash=signed.manifest_hash(),
        firmware_hash=parse_hash(signed.firmwareHash),
        sbom_hash=parse_hash(signed.sbomHash),
        expiry=int(signed.expiry.timestamp()),
        registered_at=7,
        revoked=False,
        device_model=signed.deviceModel,
        manifest_cid=compute_cid(signed.model_dump_json().encode()),
        firmware_cid=signed.cids.firmware,
        sbom_cid=signed.cids.sbom,
        signature=parse_signature(signed.signature),
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


def model_record(status: int = STATUS_ACTIVE) -> ModelRecord:
    return ModelRecord(MODEL_HASH, "sbom_risk_v1", status, b"\x00" * 32, 2, 0)


@pytest.fixture
def valid_input(
    signed_manifest: SignedManifest, firmware: bytes, sbom: bytes, publisher_key: KeyPair
) -> Stage1Input:
    return Stage1Input(
        manifest=signed_manifest,
        firmware=firmware,
        sbom=sbom,
        release=release_record(signed_manifest),
        publisher=publisher_record(publisher_key),
        device=DeviceView("dev-01", "demo-device", SemVer(1, 0, 0)),
        models=(model_record(),),
        now=NOW,
    )
