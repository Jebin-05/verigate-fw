"""Verdict record: strictness, canonical leaf, EIP-191 signing, feature hash."""

from __future__ import annotations

import pytest
from eth_account import Account
from pydantic import ValidationError

from verigate.common.merkle import VERDICT_DOMAIN, leaf_hash
from verigate.gateway.verdicts.record import VerdictRecord, feature_hash
from verigate.gateway.verdicts.types import Verdict

KEY = "0x" + "11" * 32
BASE = {
    "releaseId": "0x" + "ab" * 32,
    "deviceId": "dev-1",
    "modelHashes": ["0x" + "cd" * 32],
    "featureHash": feature_hash({"max_cvss": 98, "kev": 1}),
    "r_sbom": 1234,
    "r_img": 0,
    "reputation": 5000,
    "R": 1494,
    "verdict": "APPROVE",
    "rationaleCid": None,
    "ts": 1_789_000_000,
}


def test_leaf_and_canonical() -> None:
    record = VerdictRecord.model_validate(BASE)
    assert record.leaf() == leaf_hash(VERDICT_DOMAIN, record.canonical())
    assert b'"R":1494' in record.canonical()
    assert record.gatewaySig is None and record.signer() is None
    assert b'"gatewaySig":null' in record.canonical()
    assert b"gatewaySig" not in record.signing_bytes()  # the signature never covers itself


def test_sign_and_recover() -> None:
    record = VerdictRecord.model_validate(BASE).sign(KEY)
    assert record.gatewaySig is not None and record.gatewaySig.startswith("eth:")
    assert record.signer() == Account.from_key(KEY).address
    assert record.signing_bytes() != record.canonical()  # canonical includes the signature
    assert record.leaf() != VerdictRecord.model_validate(BASE).leaf()
    tampered = record.model_copy(update={"R": 1})
    assert tampered.signer() != Account.from_key(KEY).address
    assert record.model_copy(update={"gatewaySig": "eth:zz"}).signer() is None
    assert record.model_copy(update={"gatewaySig": "sig:00"}).signer() is None


@pytest.mark.parametrize(
    "patch",
    [
        {"extra": 1},
        {"R": 10_001},
        {"r_sbom": -1},
        {"releaseId": "0x1234"},
        {"modelHashes": ["zz"]},
        {"verdict": "MAYBE"},
        {"deviceId": ""},
        {"ts": -1},
    ],
)
def test_rejections(patch: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        VerdictRecord.model_validate({**BASE, **patch})


def test_hex_normalisation_and_enum() -> None:
    record = VerdictRecord.model_validate(
        {**BASE, "releaseId": "AB" * 32, "verdict": Verdict.REJECT}
    )
    assert record.releaseId == "0x" + "ab" * 32
    assert record.verdict is Verdict.REJECT


def test_feature_hash_is_order_independent_and_quantised() -> None:
    assert feature_hash({"a": 1, "b": 2}) == feature_hash({"b": 2, "a": 1})
    assert (
        feature_hash({})
        == "0x" + "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    )
    with pytest.raises(Exception, match="floats"):
        feature_hash({"a": 0.5})  # type: ignore[dict-item]
