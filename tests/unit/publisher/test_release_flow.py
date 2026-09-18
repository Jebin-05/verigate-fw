"""publisher/release.py: every branch of ensure_registered, register_on_chain, revoke, publish."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from verigate.common.chain import publisher_id
from verigate.common.crypto import KeyPair, sha256_hex
from verigate.common.errors import VerificationError
from verigate.common.ipfs import LocalCidBackend
from verigate.common.manifest import SignedManifest
from verigate.publisher.release import (
    build_manifest,
    ensure_key,
    ensure_registered,
    publish_release,
    register_on_chain,
    revoke_release,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "releases"
DID = "did:verigate:unit"
EXPIRY = datetime(2030, 1, 1, tzinfo=UTC)


def test_ensure_key_is_idempotent(tmp_path: Path) -> None:
    first = ensure_key(tmp_path / "keys", "acme")
    second = ensure_key(tmp_path / "keys", "acme")
    assert first == second
    assert (tmp_path / "keys" / "acme.key").stat().st_mode & 0o777 == 0o600


def test_ensure_registered_branches(fake_chain: Any) -> None:
    key = KeyPair.generate()
    acct = fake_chain.account("0x" + "ab" * 32)
    first = ensure_registered(fake_chain, acct, DID, key)
    assert first.status == "registered"
    assert first.tx_hash is not None and first.tx_hash.startswith("0x")
    assert first.publisher_id == publisher_id(DID).hex()
    assert ensure_registered(fake_chain, acct, DID, key).status == "unchanged"
    rotated = ensure_registered(fake_chain, acct, DID, KeyPair.generate())
    assert rotated.status == "key-rotated"
    assert fake_chain.sent[-1].name == "rotateKey"
    with pytest.raises(VerificationError, match="owned by"):
        ensure_registered(fake_chain, fake_chain.account("0x" + "cd" * 32), DID, key)
    fake_chain.revoke_publisher(publisher_id(DID))
    with pytest.raises(VerificationError, match="revoked"):
        ensure_registered(fake_chain, acct, DID, key)


def test_build_manifest_uses_ipfs_and_hashes(tmp_path: Path) -> None:
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    fw = (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()
    sbom = (FIXTURES / "v1.0.0" / "sbom.json").read_bytes()
    m = build_manifest(ipfs, fw, sbom, "1.0.0", "demo-device", EXPIRY, DID)
    assert ipfs.get(m.cids.firmware) == fw
    assert ipfs.get(m.cids.sbom) == sbom
    assert m.firmwareHash == sha256_hex(fw)
    assert str(m.version) == "1.0.0"


def test_publish_release_registers_then_is_unchanged(fake_chain: Any, tmp_path: Path) -> None:
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    key = KeyPair.generate()
    acct = fake_chain.account("0x" + "ab" * 32)
    args = {
        "chain": fake_chain,
        "ipfs": ipfs,
        "account": acct,
        "key": key,
        "did": DID,
        "firmware_path": FIXTURES / "v1.0.0" / "firmware.bin",
        "sbom_path": FIXTURES / "v1.0.0" / "sbom.json",
        "version": "1.0.0",
        "device_model": "demo-device",
        "expiry": EXPIRY,
    }
    result = publish_release(**args)  # type: ignore[arg-type]
    assert result.status == "registered"
    assert result.txHash is not None and result.txHash.startswith("0x")
    assert result.releaseId == result.manifestHash and result.releaseId.startswith("0x")
    signed = SignedManifest.model_validate_json(ipfs.get(result.cids["manifest"]))
    assert signed.verify(key.public)
    assert "0x" + signed.manifest_hash().hex() == result.releaseId
    on_chain = fake_chain.get_release(signed.manifest_hash())
    assert on_chain.exists and on_chain.manifest_cid == result.cids["manifest"]
    assert on_chain.signature == bytes.fromhex(signed.signature.removeprefix("ed25519:"))

    again = publish_release(**args)  # type: ignore[arg-type]
    assert again.status == "unchanged" and again.txHash is None
    assert again.releaseId == result.releaseId
    assert result.to_dict()["cids"]["firmware"] == again.cids["firmware"]


def test_register_on_chain_translates_reverts(fake_chain: Any, tmp_path: Path) -> None:
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    key = KeyPair.generate()
    m = build_manifest(ipfs, b"fw", b"sbom", "0.9.0", "demo-device", EXPIRY, DID).sign(key)
    fake_chain.revert_next = "VersionNotMonotonic"
    with pytest.raises(VerificationError, match="VersionNotMonotonic"):
        register_on_chain(fake_chain, fake_chain.account("0x" + "ab" * 32), m, "bafkreiaaa")


def test_revoke_release_branches(fake_chain: Any, tmp_path: Path) -> None:
    acct = fake_chain.account("0x" + "ab" * 32)
    with pytest.raises(VerificationError, match="unknown release"):
        revoke_release(fake_chain, acct, b"\x09" * 32)
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    signed = build_manifest(ipfs, b"fw", b"sbom", "1.0.0", "demo-device", EXPIRY, DID).sign(
        KeyPair.generate()
    )
    register_on_chain(fake_chain, acct, signed, "bafkreiaaa")
    rid = signed.manifest_hash()
    first = revoke_release(fake_chain, acct, rid)
    assert first["status"] == "revoked" and first["txHash"].startswith("0x")
    assert revoke_release(fake_chain, acct, rid)["status"] == "unchanged"
    fake_chain.releases[rid] = fake_chain.releases[rid].__class__(
        **{**fake_chain.releases[rid].__dict__, "revoked": False}
    )
    fake_chain.revert_next = "NotAuthorised"
    with pytest.raises(VerificationError, match="NotAuthorised"):
        revoke_release(fake_chain, acct, rid)
