"""Device emulator: persistence, nonces, A/B install with self-verification, receipts."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from stage1_fixture_helpers import FIXTURES

from verigate.common.crypto import KeyPair, parse_signature, sha256_hex, verify
from verigate.common.errors import VerificationError
from verigate.common.ipfs import compute_cid
from verigate.common.manifest import Cids, Manifest, SemVer, SignedManifest
from verigate.common.protocol import InstallReceipt, verify_message
from verigate.fleet.device import Device, NvsState

PUB = KeyPair.generate()
Mutator = Callable[[bytes, SignedManifest], tuple[bytes, SignedManifest]]


def make_manifest(version: str, firmware: bytes, model: str = "demo-device") -> SignedManifest:
    sbom = b"{}"
    return Manifest(
        firmwareHash=sha256_hex(firmware),
        sbomHash=sha256_hex(sbom),
        version=SemVer.parse(version),
        deviceModel=model,
        expiry=datetime(2030, 1, 1, tzinfo=UTC),
        cids=Cids(firmware=compute_cid(firmware), sbom=compute_cid(sbom)),
        publisherDid="did:verigate:acme",
    ).sign(PUB)


@pytest.fixture
def fw() -> bytes:
    return (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()


def test_identity_and_nvs_persist(tmp_path: Path) -> None:
    d1 = Device(tmp_path, "dev-01", "demo-device")
    assert d1.installed_version == SemVer(0, 0, 0)
    assert d1.state.active_slot == "a"
    assert (tmp_path / "dev-01" / "device.key").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "dev-01" / "slot_a.bin").exists()
    assert (tmp_path / "dev-01" / "slot_b.bin").exists()
    msg = d1.sign({"x": 1}, now=100)
    assert msg.nonce == 1
    d2 = Device(tmp_path, "dev-01", "demo-device")
    assert d2.public_key == d1.public_key
    assert d2.sign({"x": 2}, now=101).nonce == 2  # nonce survived the restart
    assert NvsState.from_json((tmp_path / "dev-01" / "nvs.json").read_text()).nonce == 2


def test_signed_messages_verify_and_hello_payload(tmp_path: Path) -> None:
    d = Device(tmp_path, "dev-02", "demo-device")
    msg = d.sign(d.hello_payload(), now=1_000)
    assert verify_message(msg, d.public_key, 1_000, 0).ok
    assert msg.payload == {
        "deviceModel": "demo-device",
        "installedVersion": "0.0.0",
        "publicKey": d.public_key,
    }


def test_install_switches_slot_and_signs_receipt(tmp_path: Path, fw: bytes) -> None:
    d = Device(tmp_path, "dev-03", "demo-device")
    manifest = make_manifest("1.0.0", fw)
    receipt = d.install(fw, manifest, PUB.public, now=datetime(2026, 9, 18, 12, 0, tzinfo=UTC))
    assert isinstance(receipt, InstallReceipt)
    assert receipt.deviceId == "dev-03" and receipt.version == "1.0.0"
    assert receipt.releaseId == "0x" + manifest.manifest_hash().hex()
    assert receipt.installedAt == "2026-09-18T12:00:00Z"
    assert verify(d.key.public, receipt.signed_bytes(), parse_signature(receipt.signature))
    assert d.installed_version == SemVer(1, 0, 0)
    assert d.state.active_slot == "b" and d.active_image() == fw
    assert d.state.installed_release_id == receipt.releaseId
    # second install goes to slot a
    fw2 = fw[:-4] + b"v110"
    d.install(fw2, make_manifest("1.1.0", fw2), PUB.public_encoded)
    assert d.state.active_slot == "a" and d.active_image() == fw2
    # persisted
    assert Device(tmp_path, "dev-03", "demo-device").installed_version == SemVer(1, 1, 0)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda fw, m: (fw[:-1] + bytes([fw[-1] ^ 0xFF]), m), "hash mismatch"),
        (
            lambda fw, m: (fw, m.model_copy(update={"version": SemVer(9, 9, 9)})),
            "signature invalid",
        ),
        (lambda fw, m: (fw, make_manifest("1.0.0", fw, model="acme-lock")), "wrong device model"),
        (lambda fw, m: (fw, make_manifest("0.0.0", fw)), "<= installed"),
    ],
)
def test_install_self_checks_fail_closed(
    tmp_path: Path, fw: bytes, mutate: Mutator, match: str
) -> None:
    d = Device(tmp_path, "dev-04", "demo-device")
    firmware, manifest = mutate(fw, make_manifest("1.0.0", fw))
    with pytest.raises(VerificationError, match=match):
        d.install(firmware, manifest, PUB.public)
    assert d.installed_version == SemVer(0, 0, 0)
    assert d.active_image() == b""


def test_install_rejects_wrong_publisher_key(tmp_path: Path, fw: bytes) -> None:
    d = Device(tmp_path, "dev-05", "demo-device")
    with pytest.raises(VerificationError, match="signature invalid"):
        d.install(fw, make_manifest("1.0.0", fw), KeyPair.generate().public)
