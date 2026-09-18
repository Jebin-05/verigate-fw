"""Signed device messages: round-trip, replay (nonce), clock window, malformed keys/signatures."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from verigate.common.crypto import KeyPair
from verigate.common.protocol import SignedMessage, sign_message, signing_bytes, verify_message

KEY = KeyPair.generate()
PAYLOAD = {"deviceModel": "demo-device", "installedVersion": "1.0.0"}


def test_round_trip() -> None:
    msg = sign_message(KEY, "dev-1", 1, 1_000, PAYLOAD)
    assert msg.signed_bytes() == signing_bytes("dev-1", 1, 1_000, PAYLOAD)
    assert verify_message(msg, KEY.public, now=1_010, last_nonce=0).ok
    assert verify_message(msg, KEY.public_encoded, now=990, last_nonce=0).ok


def test_replay_and_reorder_rejected() -> None:
    first = sign_message(KEY, "dev-1", 5, 1_000, PAYLOAD)
    assert verify_message(first, KEY.public, 1_000, last_nonce=4).ok
    replay = verify_message(first, KEY.public, 1_000, last_nonce=5)
    assert not replay.ok and "replay" in (replay.reason or "")
    older = sign_message(KEY, "dev-1", 3, 1_000, PAYLOAD)
    assert not verify_message(older, KEY.public, 1_000, last_nonce=5).ok


def test_clock_window_boundaries() -> None:
    msg = sign_message(KEY, "dev-1", 1, 1_000, PAYLOAD)
    assert verify_message(msg, KEY.public, 1_120, 0, window_s=120).ok
    assert verify_message(msg, KEY.public, 880, 0, window_s=120).ok
    assert not verify_message(msg, KEY.public, 1_121, 0, window_s=120).ok
    assert not verify_message(msg, KEY.public, 879, 0, window_s=120).ok


def test_tampered_payload_and_wrong_key() -> None:
    msg = sign_message(KEY, "dev-1", 1, 1_000, PAYLOAD)
    tampered = msg.model_copy(update={"payload": {**PAYLOAD, "installedVersion": "0.0.1"}})
    assert verify_message(tampered, KEY.public, 1_000, 0).reason == "bad signature"
    assert verify_message(msg, KeyPair.generate().public, 1_000, 0).reason == "bad signature"
    assert not verify_message(msg, "rsa:00", 1_000, 0).ok
    assert not verify_message(msg, b"short", 1_000, 0).ok


@pytest.mark.parametrize(
    "patch",
    [
        {"signature": "ed25519:abcd"},
        {"nonce": 0},
        {"ts": -1},
        {"deviceId": ""},
        {"deviceId": "has space"},
        {"extra": 1},
    ],
)
def test_malformed_messages_rejected_at_parse(patch: dict[str, object]) -> None:
    good = sign_message(KEY, "dev-1", 1, 1_000, PAYLOAD).model_dump()
    with pytest.raises(ValidationError):
        SignedMessage.model_validate({**good, **patch})


@given(st.integers(min_value=1, max_value=2**40), st.integers(min_value=0, max_value=2**40))
def test_any_nonce_and_ts_round_trip(nonce: int, ts: int) -> None:
    msg = sign_message(KEY, "d", nonce, ts, {"k": "v"})
    assert verify_message(msg, KEY.public, ts, nonce - 1).ok
