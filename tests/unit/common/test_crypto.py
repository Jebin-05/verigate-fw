"""Ed25519 + SHA-256 wrappers: golden vector, round-trips, malformed input branches."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from verigate.common.crypto import (
    KeyPair,
    parse_hash,
    parse_public_key,
    parse_signature,
    sha256,
    sha256_file,
    sha256_hex,
    verify,
)
from verigate.common.errors import VerificationError


def test_golden_signature(load_fixture: Any) -> None:
    vec = load_fixture("crypto/signed_manifest.json")
    key = KeyPair.from_private(hashlib.sha256(b"verigate-fixture-key").digest())
    assert key.public.hex() == vec["public_key_hex"]
    message = vec["canonical"].encode()
    assert key.sign(message).hex() == vec["signature_hex"]
    assert verify(key.public, message, bytes.fromhex(vec["signature_hex"]))


def test_sha256_helpers(tmp_path: Path) -> None:
    assert (
        sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert sha256_hex(b"abc") == "sha256:" + sha256(b"abc").hex()
    f = tmp_path / "blob.bin"
    f.write_bytes(b"x" * (3 * 1024 * 1024 + 7))
    assert sha256_file(f, chunk_size=1 << 20) == sha256_hex(f.read_bytes())
    assert parse_hash(sha256_hex(b"abc")) == sha256(b"abc")


@pytest.mark.parametrize(
    ("value", "match"),
    [("md5:" + "0" * 64, "start with"), ("sha256:zz", "not hex"), ("sha256:abcd", "32 bytes")],
)
def test_parse_hash_rejects(value: str, match: str) -> None:
    with pytest.raises(VerificationError, match=match):
        parse_hash(value)


@pytest.mark.parametrize(
    ("value", "match"),
    [("rsa:" + "0" * 64, "start with"), ("ed25519:zz", "not hex"), ("ed25519:abcd", "32 bytes")],
)
def test_parse_public_key_rejects(value: str, match: str) -> None:
    with pytest.raises(VerificationError, match=match):
        parse_public_key(value)


@pytest.mark.parametrize(
    ("value", "match"),
    [("rsa:" + "0" * 128, "start with"), ("ed25519:zz", "not hex"), ("ed25519:abcd", "64 bytes")],
)
def test_parse_signature_rejects(value: str, match: str) -> None:
    with pytest.raises(VerificationError, match=match):
        parse_signature(value)


def test_from_private_rejects_wrong_length() -> None:
    with pytest.raises(VerificationError, match="32 bytes"):
        KeyPair.from_private(b"short")


def test_verify_fails_closed_on_malformed_lengths() -> None:
    key = KeyPair.generate()
    sig = key.sign(b"m")
    assert verify(key.public[:-1], b"m", sig) is False
    assert verify(key.public, b"m", sig[:-1]) is False
    assert verify(KeyPair.generate().public, b"m", sig) is False
    assert verify(key.public, b"m2", sig) is False


def test_save_and_load(tmp_path: Path) -> None:
    key = KeyPair.generate()
    priv, pub = key.save(tmp_path / "keys", "acme")
    assert priv.stat().st_mode & 0o777 == 0o600
    assert pub.read_text().strip() == key.public_encoded
    assert KeyPair.load(priv) == key
    assert parse_public_key(key.public_encoded) == key.public
    assert parse_signature(key.sign_encoded(b"m")) == key.sign(b"m")


@given(st.binary(min_size=0, max_size=512), st.binary(min_size=32, max_size=32))
def test_sign_verify_round_trip(message: bytes, seed: bytes) -> None:
    key = KeyPair.from_private(seed)
    sig = key.sign(message)
    assert verify(key.public, message, sig)
    assert not verify(key.public, message + b"\x00", sig)
