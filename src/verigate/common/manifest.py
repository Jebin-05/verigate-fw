"""The signed release manifest (ADR-0001) and its SemVer version type.

A :class:`Manifest` is what the publisher signs; a :class:`SignedManifest` is the manifest plus
the signature and is what travels over IPFS. Both are frozen pydantic models that reject unknown
fields, so a signed object can never be silently extended.

On-chain identifier: ``manifest_hash = keccak256(canonical_json(manifest))`` — this is what
``FirmwareRegistry`` stores and what ``releaseId`` is derived from.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from functools import total_ordering
from typing import Annotated, Any

from eth_utils.crypto import keccak
from multiformats import CID
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    GetCoreSchemaHandler,
    PlainSerializer,
)
from pydantic_core import core_schema

from verigate.common.canonical import canonical_json
from verigate.common.crypto import (
    KeyPair,
    parse_hash,
    parse_public_key,
    parse_signature,
    verify,
)
from verigate.common.errors import VerificationError

_SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
MAX_VERSION_COMPONENT = 2**32 - 1  # each component is a uint32 on-chain


@total_ordering
class SemVer:
    """Strict ``MAJOR.MINOR.PATCH`` version (no pre-release / build metadata).

    Pre-release tags are deliberately unsupported: the on-chain registry compares versions as a
    ``(uint32, uint32, uint32)`` triple and a release either is or is not newer.
    """

    __slots__ = ("major", "minor", "patch")

    def __init__(self, major: int, minor: int, patch: int) -> None:
        for name, value in (("major", major), ("minor", minor), ("patch", patch)):
            if not 0 <= value <= MAX_VERSION_COMPONENT:
                raise ValueError(f"{name} must be in [0, 2**32-1], got {value}")
        self.major = major
        self.minor = minor
        self.patch = patch

    @classmethod
    def parse(cls, text: str) -> SemVer:
        """Parse ``"1.2.3"``; leading zeros and any suffix are rejected."""
        match = _SEMVER_RE.match(text)
        if match is None:
            raise ValueError(f"not a strict MAJOR.MINOR.PATCH version: {text!r}")
        return cls(*(int(g) for g in match.groups()))

    def as_tuple(self) -> tuple[int, int, int]:
        """Return ``(major, minor, patch)``."""
        return (self.major, self.minor, self.patch)

    def __str__(self) -> str:
        """``"1.2.3"``."""
        return f"{self.major}.{self.minor}.{self.patch}"

    def __repr__(self) -> str:
        """Debug form."""
        return f"SemVer({self.major}, {self.minor}, {self.patch})"

    def __eq__(self, other: object) -> bool:
        """Component-wise equality."""
        if not isinstance(other, SemVer):
            return NotImplemented
        return self.as_tuple() == other.as_tuple()

    def __lt__(self, other: SemVer) -> bool:
        """Lexicographic order on ``(major, minor, patch)``."""
        return self.as_tuple() < other.as_tuple()

    def __hash__(self) -> int:
        """Hash of the tuple form."""
        return hash(self.as_tuple())

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source: type[Any], _handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """Accept ``SemVer`` or a string; serialise as a string."""
        return core_schema.no_info_after_validator_function(
            lambda v: v if isinstance(v, SemVer) else cls.parse(v),
            core_schema.union_schema(
                [core_schema.is_instance_schema(cls), core_schema.str_schema()]
            ),
            serialization=core_schema.to_string_ser_schema(),
        )


def _check_hash(value: str) -> str:
    try:
        parse_hash(value)
    except VerificationError as exc:
        raise ValueError(str(exc)) from exc
    return value


def _check_signature(value: str) -> str:
    try:
        parse_signature(value)
    except VerificationError as exc:
        raise ValueError(str(exc)) from exc
    return value


def _check_cid(value: str) -> str:
    try:
        cid = CID.decode(value)
    except Exception as exc:  # multiformats raises several unrelated types
        raise ValueError(f"not a valid CID: {value!r}") from exc
    if cid.version != 1:
        raise ValueError("only CIDv1 is accepted")
    return value


def _check_did(value: str) -> str:
    if not value.startswith("did:") or len(value.split(":")) < 3:
        raise ValueError("publisherDid must look like did:<method>:<id>")
    return value


def _check_model(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9\-]{0,63}", value):
        raise ValueError("deviceModel must be lowercase [a-z0-9-], 1–64 chars")
    return value


def _check_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("expiry must be an explicit UTC datetime (…Z)")
    return value.replace(microsecond=0)


Sha256Hex = Annotated[str, AfterValidator(_check_hash)]
CidV1 = Annotated[str, AfterValidator(_check_cid)]
UtcDatetime = Annotated[
    datetime,
    AfterValidator(_check_utc),
    PlainSerializer(lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ"), return_type=str),
]


class Cids(BaseModel):
    """IPFS content identifiers of the two release artefacts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    firmware: CidV1
    sbom: CidV1


class Manifest(BaseModel):
    """Everything a device needs to decide; the signature covers all of it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    firmwareHash: Sha256Hex  # noqa: N815 — wire format uses camelCase (Guide §2.3)
    sbomHash: Sha256Hex  # noqa: N815
    version: SemVer
    deviceModel: Annotated[str, AfterValidator(_check_model)]  # noqa: N815
    expiry: UtcDatetime
    cids: Cids
    publisherDid: Annotated[str, AfterValidator(_check_did)]  # noqa: N815

    def canonical(self) -> bytes:
        """Canonical JSON bytes of the manifest — the exact bytes that are signed."""
        return canonical_json(self.model_dump(mode="json"))

    def manifest_hash(self) -> bytes:
        """``keccak256(canonical)`` — the on-chain record identifier (32 bytes)."""
        return keccak(self.canonical())

    def sign(self, key: KeyPair) -> SignedManifest:
        """Produce the signed manifest with an ``"ed25519:<hex>"`` signature."""
        signature = key.sign_encoded(self.canonical())
        return SignedManifest(**self.model_dump(mode="json"), signature=signature)


class SignedManifest(Manifest):
    """A manifest plus the publisher's signature over its canonical form."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signature: Annotated[str, AfterValidator(_check_signature)]

    def unsigned(self) -> Manifest:
        """Strip the signature to recover the exact signed payload."""
        return Manifest(**self.model_dump(mode="json", exclude={"signature"}))

    def canonical(self) -> bytes:
        """Canonical bytes of the *unsigned* manifest (the signature is not self-covering)."""
        return self.unsigned().canonical()

    def manifest_hash(self) -> bytes:
        """``keccak256`` of the unsigned canonical form."""
        return self.unsigned().manifest_hash()

    def verify(self, public_key: str | bytes) -> bool:
        """Return ``True`` iff the signature is valid under ``public_key``.

        Accepts the raw 32 bytes or the ``"ed25519:<hex>"`` encoding. Never raises on a bad
        signature; a malformed key returns ``False`` (fail closed).
        """
        try:
            raw = parse_public_key(public_key) if isinstance(public_key, str) else public_key
        except VerificationError:
            return False
        return verify(raw, self.canonical(), parse_signature(self.signature))
