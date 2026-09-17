"""Manifest model: golden signed vector, strictness (extra/malformed fields), SemVer ordering."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from verigate.common.crypto import KeyPair
from verigate.common.manifest import MAX_VERSION_COMPONENT, Manifest, SemVer, SignedManifest

CID = "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"


@pytest.fixture
def base(load_fixture: Any) -> dict[str, Any]:
    return dict(load_fixture("crypto/signed_manifest.json")["manifest"])


def test_golden_signed_manifest(load_fixture: Any) -> None:
    vec = load_fixture("crypto/signed_manifest.json")
    manifest = Manifest.model_validate(vec["manifest"])
    assert manifest.canonical().decode() == vec["canonical"]
    assert manifest.manifest_hash().hex() == vec["manifest_hash_keccak"]
    signed = SignedManifest.model_validate(vec["signed_manifest"])
    assert signed.verify(vec["public_key"])
    assert signed.verify(bytes.fromhex(vec["public_key_hex"]))
    assert signed.manifest_hash() == manifest.manifest_hash()
    assert signed.unsigned() == manifest
    key = KeyPair.from_private(hashlib.sha256(b"verigate-fixture-key").digest())
    assert manifest.sign(key) == signed


def test_verify_fails_closed(load_fixture: Any) -> None:
    signed = SignedManifest.model_validate(
        load_fixture("crypto/signed_manifest.json")["signed_manifest"]
    )
    assert signed.verify(KeyPair.generate().public) is False
    assert signed.verify("ed25519:zz") is False
    assert signed.verify("rsa:" + "0" * 64) is False
    tampered = signed.model_copy(update={"deviceModel": "other-model"})
    assert tampered.verify(load_fixture("crypto/signed_manifest.json")["public_key"]) is False


def test_expiry_serialises_as_utc_z(base: dict[str, Any]) -> None:
    m = Manifest.model_validate(
        {**base, "expiry": datetime(2030, 1, 1, 12, 30, 15, 999, tzinfo=UTC)}
    )
    assert m.model_dump(mode="json")["expiry"] == "2030-01-01T12:30:15Z"
    assert m.expiry.tzinfo is not None


@pytest.mark.parametrize(
    ("patch", "match"),
    [
        ({"extra": 1}, "extra"),
        ({"version": "1.2"}, "MAJOR.MINOR.PATCH"),
        ({"version": "01.2.3"}, "MAJOR.MINOR.PATCH"),
        ({"version": "1.2.3-rc1"}, "MAJOR.MINOR.PATCH"),
        ({"version": f"{MAX_VERSION_COMPONENT + 1}.0.0"}, "2\\*\\*32"),
        ({"firmwareHash": "sha256:abcd"}, "32 bytes"),
        ({"sbomHash": "md5:" + "0" * 64}, "start with"),
        ({"expiry": "2030-01-01T00:00:00"}, "UTC"),
        ({"expiry": datetime(2030, 1, 1, tzinfo=timezone(timedelta(hours=5)))}, "UTC"),
        (
            {"cids": {"firmware": CID, "sbom": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}},
            "CIDv1",
        ),
        ({"cids": {"firmware": "not-a-cid", "sbom": CID}}, "valid CID"),
        ({"cids": {"firmware": CID, "sbom": CID, "extra": CID}}, "extra"),
        ({"publisherDid": "acme"}, "did:"),
        ({"deviceModel": "Acme Lock"}, "lowercase"),
    ],
)
def test_manifest_rejects(base: dict[str, Any], patch: dict[str, Any], match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        Manifest.model_validate({**base, **patch})


def test_missing_field_rejected(base: dict[str, Any]) -> None:
    base.pop("sbomHash")
    with pytest.raises(ValidationError, match="sbomHash"):
        Manifest.model_validate(base)


def test_signed_manifest_requires_well_formed_signature(base: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="64 bytes"):
        SignedManifest.model_validate({**base, "signature": "ed25519:abcd"})


def test_manifest_is_frozen(base: dict[str, Any]) -> None:
    m = Manifest.model_validate(base)
    with pytest.raises(ValidationError):
        m.version = SemVer(9, 9, 9)  # type: ignore[misc]


def test_semver_parse_and_str() -> None:
    v = SemVer.parse("1.10.3")
    assert (v.major, v.minor, v.patch) == (1, 10, 3)
    assert str(v) == "1.10.3"
    assert repr(v) == "SemVer(1, 10, 3)"
    assert v.as_tuple() == (1, 10, 3)
    assert hash(v) == hash((1, 10, 3))
    assert v == SemVer(1, 10, 3)
    assert v != "1.10.3"
    assert SemVer.parse("1.10.0") > SemVer.parse("1.9.9")
    assert SemVer.parse("0.0.0") <= SemVer.parse("0.0.0")
    with pytest.raises(ValueError, match="major"):
        SemVer(-1, 0, 0)


def test_semver_accepts_instance_in_model(base: dict[str, Any]) -> None:
    m = Manifest.model_validate({**base, "version": SemVer(2, 0, 0)})
    assert m.version == SemVer(2, 0, 0)
    assert m.model_dump(mode="json")["version"] == "2.0.0"


components = st.integers(min_value=0, max_value=MAX_VERSION_COMPONENT)


@given(components, components, components, components, components, components)
def test_semver_total_order_matches_tuples(a: int, b: int, c: int, d: int, e: int, f: int) -> None:
    x, y = SemVer(a, b, c), SemVer(d, e, f)
    assert (x < y) == ((a, b, c) < (d, e, f))
    assert (x == y) == ((a, b, c) == (d, e, f))
    assert SemVer.parse(str(x)) == x
