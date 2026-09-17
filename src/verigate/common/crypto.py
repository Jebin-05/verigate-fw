"""Ed25519 signatures and SHA-256 hashing (thin, typed wrappers around PyNaCl / hashlib).

Encodings used everywhere in manifests and on the wire:

* hashes: ``"sha256:<64 hex chars>"``
* signatures: ``"ed25519:<128 hex chars>"``
* public keys: ``"ed25519:<64 hex chars>"``

Only the *raw* 32/64-byte forms go on-chain (``bytes32`` / ``bytes``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from verigate.common.errors import VerificationError

HASH_PREFIX = "sha256:"
SIG_PREFIX = "ed25519:"
KEY_PREFIX = "ed25519:"


def sha256(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of ``data``."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Return ``"sha256:<hex>"`` for ``data`` (the manifest encoding)."""
    return HASH_PREFIX + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """Hash a file in chunks without loading it entirely into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return HASH_PREFIX + digest.hexdigest()


def parse_hash(value: str) -> bytes:
    """Decode ``"sha256:<hex>"`` to 32 raw bytes.

    Raises:
        VerificationError: On a wrong prefix, wrong length or non-hex characters.
    """
    if not value.startswith(HASH_PREFIX):
        raise VerificationError(f"hash must start with {HASH_PREFIX!r}")
    try:
        raw = bytes.fromhex(value[len(HASH_PREFIX) :])
    except ValueError as exc:
        raise VerificationError("hash is not hex") from exc
    if len(raw) != 32:
        raise VerificationError("sha256 hash must be 32 bytes")
    return raw


@dataclass(frozen=True)
class KeyPair:
    """An Ed25519 key pair. ``private`` never leaves the process except via :meth:`save`."""

    private: bytes
    public: bytes

    @classmethod
    def generate(cls) -> KeyPair:
        """Create a fresh random key pair."""
        sk = SigningKey.generate()
        return cls(private=bytes(sk), public=bytes(sk.verify_key))

    @classmethod
    def from_private(cls, private: bytes) -> KeyPair:
        """Rebuild a key pair from its 32-byte private seed."""
        if len(private) != 32:
            raise VerificationError("Ed25519 private key must be 32 bytes")
        sk = SigningKey(private)
        return cls(private=private, public=bytes(sk.verify_key))

    @property
    def public_encoded(self) -> str:
        """``"ed25519:<hex>"`` form of the public key."""
        return KEY_PREFIX + self.public.hex()

    def sign(self, message: bytes) -> bytes:
        """Return the 64-byte detached signature over ``message``."""
        return bytes(SigningKey(self.private).sign(message).signature)

    def sign_encoded(self, message: bytes) -> str:
        """Return the signature as ``"ed25519:<hex>"``."""
        return SIG_PREFIX + self.sign(message).hex()

    def save(self, directory: Path, name: str) -> tuple[Path, Path]:
        """Write ``<name>.key`` (private, mode 0600) and ``<name>.pub`` under ``directory``."""
        directory.mkdir(parents=True, exist_ok=True)
        priv = directory / f"{name}.key"
        pub = directory / f"{name}.pub"
        priv.write_bytes(self.private.hex().encode())
        priv.chmod(0o600)
        pub.write_text(self.public_encoded + "\n")
        return priv, pub

    @classmethod
    def load(cls, private_path: Path) -> KeyPair:
        """Load a key pair from a ``.key`` file written by :meth:`save`."""
        return cls.from_private(bytes.fromhex(private_path.read_text().strip()))


def parse_public_key(value: str) -> bytes:
    """Decode ``"ed25519:<hex>"`` to the 32 raw public-key bytes."""
    if not value.startswith(KEY_PREFIX):
        raise VerificationError(f"public key must start with {KEY_PREFIX!r}")
    try:
        raw = bytes.fromhex(value[len(KEY_PREFIX) :])
    except ValueError as exc:
        raise VerificationError("public key is not hex") from exc
    if len(raw) != 32:
        raise VerificationError("Ed25519 public key must be 32 bytes")
    return raw


def parse_signature(value: str) -> bytes:
    """Decode ``"ed25519:<hex>"`` to the 64 raw signature bytes."""
    if not value.startswith(SIG_PREFIX):
        raise VerificationError(f"signature must start with {SIG_PREFIX!r}")
    try:
        raw = bytes.fromhex(value[len(SIG_PREFIX) :])
    except ValueError as exc:
        raise VerificationError("signature is not hex") from exc
    if len(raw) != 64:
        raise VerificationError("Ed25519 signature must be 64 bytes")
    return raw


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Return ``True`` iff ``signature`` is a valid Ed25519 signature of ``message``.

    Never raises on a bad signature — a boolean keeps Stage-1 checks pure. Malformed key or
    signature lengths also return ``False`` (fail closed).
    """
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        VerifyKey(public).verify(message, signature)
    except BadSignatureError:
        return False
    return True
