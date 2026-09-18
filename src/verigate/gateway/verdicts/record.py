"""The verdict record (P4-01): what gets hashed into a Merkle leaf and anchored on-chain.

All numeric scores are integers in basis points (10 000 = 1.0) because canonical JSON forbids
floats; ``featureHash = SHA-256(canonical feature vector)`` lets anyone with the model files and
the inputs re-run inference and check ``R`` (Guide §8, Novelty 1).

``gatewaySig`` is an Ethereum (EIP-191 ``personal_sign``) signature by the gateway account over the
canonical unsigned record, so a verdict is attributable to the same address that committed the
batch. ``leaf = sha256(0x00 ‖ "VERIGATE-VERDICT-V1" ‖ canonical(record))``.
"""

from __future__ import annotations

from typing import Annotated, Any

from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from verigate.common.canonical import Json, canonical_json
from verigate.common.crypto import sha256
from verigate.common.merkle import VERDICT_DOMAIN, leaf_hash
from verigate.gateway.verdicts.types import Verdict

Bp = Annotated[int, Field(ge=0, le=10_000)]


def _hex32(value: str) -> str:
    raw = bytes.fromhex(value.removeprefix("0x"))
    if len(raw) != 32:
        raise ValueError("expected 32 bytes")
    return "0x" + raw.hex()


Hex32 = Annotated[str, AfterValidator(_hex32)]


class VerdictRecord(BaseModel):
    """One decision for one (release, device) pair."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    releaseId: Hex32  # noqa: N815 — wire format
    deviceId: str = Field(min_length=1, max_length=64)  # noqa: N815
    modelHashes: list[Hex32]  # noqa: N815
    featureHash: Hex32  # noqa: N815
    r_sbom: Bp
    r_img: Bp
    reputation: Bp
    R: Bp
    verdict: Verdict
    rationaleCid: str | None  # noqa: N815
    ts: int = Field(ge=0)
    gatewaySig: str | None = None  # noqa: N815

    def unsigned(self) -> dict[str, Any]:
        """Fields covered by ``gatewaySig``."""
        return self.model_dump(mode="json", exclude={"gatewaySig"})

    def signing_bytes(self) -> bytes:
        """Canonical JSON of the unsigned record."""
        body: Json = self.unsigned()
        return canonical_json(body)

    def canonical(self) -> bytes:
        """Canonical JSON of the full (signed) record — what the leaf hashes."""
        body: Json = self.model_dump(mode="json")
        return canonical_json(body)

    def leaf(self) -> bytes:
        """The 32-byte Merkle leaf."""
        return leaf_hash(VERDICT_DOMAIN, self.canonical())

    def sign(self, private_key: str) -> VerdictRecord:
        """Attach the gateway's EIP-191 signature."""
        signed = Account.sign_message(encode_defunct(self.signing_bytes()), private_key)
        return self.model_copy(update={"gatewaySig": "eth:" + signed.signature.hex()})

    def signer(self) -> str | None:
        """Recover the signing address, or ``None`` if unsigned / malformed."""
        if not self.gatewaySig or not self.gatewaySig.startswith("eth:"):
            return None
        try:
            address: str = Account.recover_message(
                encode_defunct(self.signing_bytes()), signature=bytes.fromhex(self.gatewaySig[4:])
            )
        except (ValueError, TypeError):
            return None
        return address


def feature_hash(features: Json) -> str:
    """``0x`` + SHA-256 of the canonical (integer-quantised) feature vector."""
    return "0x" + sha256(canonical_json(features)).hex()
