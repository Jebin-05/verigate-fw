"""Device ↔ gateway message format: signed JSON with nonce + timestamp against replay (P3-07).

Shared by ``fleet`` (signs) and ``gateway`` (verifies) — they never import each other.

A message is ``{deviceId, nonce, ts, payload}`` signed with the device's Ed25519 key over its
canonical JSON. The verifier requires ``|now - ts| <= window`` and ``nonce > last_nonce`` for that
device, so a captured message can be neither replayed nor reordered. Verification is a pure
function: the caller supplies the clock and the last-seen nonce.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from verigate.common.canonical import Json, canonical_json
from verigate.common.crypto import KeyPair, parse_public_key, parse_signature, verify
from verigate.common.errors import VerificationError

DEFAULT_WINDOW_S = 120


def _check_signature(value: str) -> str:
    try:
        parse_signature(value)
    except VerificationError as exc:
        raise ValueError(str(exc)) from exc
    return value


class SignedMessage(BaseModel):
    """Wire format of every device → gateway request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    deviceId: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9\-_]+$")  # noqa: N815
    nonce: int = Field(ge=1)
    ts: int = Field(ge=0)
    payload: dict[str, Any]
    signature: Annotated[str, AfterValidator(_check_signature)]

    def signed_bytes(self) -> bytes:
        """The exact bytes the signature covers."""
        return signing_bytes(self.deviceId, self.nonce, self.ts, self.payload)


def signing_bytes(device_id: str, nonce: int, ts: int, payload: dict[str, Any]) -> bytes:
    """Canonical JSON of the unsigned envelope."""
    body: Json = {"deviceId": device_id, "nonce": nonce, "ts": ts, "payload": payload}
    return canonical_json(body)


def sign_message(
    key: KeyPair, device_id: str, nonce: int, ts: int, payload: dict[str, Any]
) -> SignedMessage:
    """Build and sign a message (the device side)."""
    signature = key.sign_encoded(signing_bytes(device_id, nonce, ts, payload))
    return SignedMessage(
        deviceId=device_id, nonce=nonce, ts=ts, payload=payload, signature=signature
    )


@dataclass(frozen=True)
class MessageCheck:
    """Result of :func:`verify_message`."""

    ok: bool
    reason: str | None = None


def verify_message(
    msg: SignedMessage,
    public_key: str | bytes,
    now: int,
    last_nonce: int,
    window_s: int = DEFAULT_WINDOW_S,
) -> MessageCheck:
    """Check signature, timestamp window and strictly increasing nonce (pure; fails closed).

    Args:
        msg: The received message.
        public_key: The device's pinned key (raw bytes or ``"ed25519:<hex>"``).
        now: Verifier's clock, unix seconds.
        last_nonce: Highest nonce previously accepted from this device (0 if none).
        window_s: Maximum clock skew / message age accepted.
    """
    try:
        raw = parse_public_key(public_key) if isinstance(public_key, str) else public_key
        signature = parse_signature(msg.signature)
    except VerificationError as exc:
        return MessageCheck(False, str(exc))
    if not verify(raw, msg.signed_bytes(), signature):
        return MessageCheck(False, "bad signature")
    if abs(now - msg.ts) > window_s:
        return MessageCheck(False, f"timestamp outside ±{window_s}s window")
    if msg.nonce <= last_nonce:
        return MessageCheck(False, f"nonce {msg.nonce} not greater than last {last_nonce} (replay)")
    return MessageCheck(True)
