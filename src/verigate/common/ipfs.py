"""Content-addressed storage: a Kubo (go-ipfs) backend and a local backend with identical CIDs.

Both backends produce the CIDv1 that ``ipfs add --cid-version=1 --raw-leaves`` produces:

* ≤ 256 KiB: one raw block — ``bafkrei…`` (codec ``raw`` 0x55, sha2-256);
* larger: 256 KiB raw leaves under one dag-pb/UnixFS root — ``bafybei…`` (codec ``dag-pb`` 0x70).
  Only a single-level balanced layout (≤ 174 leaves ≈ 43.5 MiB) is implemented; larger inputs
  raise :class:`IpfsError` rather than silently diverging from Kubo.

``get`` on either backend re-hashes the bytes and refuses to return data whose CID does not match
(fail closed). ``tests/integration/test_ipfs_parity.py`` asserts equality with a live Kubo.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Protocol

import httpx

from verigate.common.errors import IpfsError
from verigate.common.settings import Settings

CHUNK_SIZE = 256 * 1024
MAX_LINKS = 174
_CODEC_RAW = 0x55
_CODEC_DAG_PB = 0x70
_UNIXFS_FILE = 2


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _field(number: int, wire: int, payload: bytes) -> bytes:
    return _varint((number << 3) | wire) + payload


def _cid_bytes(codec: int, digest: bytes) -> bytes:
    # CIDv1 = <version=1><codec><multihash: sha2-256 (0x12) + length (0x20) + digest>
    return b"\x01" + _varint(codec) + b"\x12\x20" + digest


def _encode_cid(raw: bytes) -> str:
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def _decode_cid(cid: str) -> bytes:
    if not cid.startswith("b"):
        raise IpfsError("only base32 CIDv1 (b…) is supported")
    body = cid[1:].upper()
    body += "=" * (-len(body) % 8)
    try:
        return base64.b32decode(body)
    except ValueError as exc:
        raise IpfsError(f"not a base32 CID: {cid!r}") from exc


def _unixfs_root(chunks: list[bytes]) -> bytes:
    """dag-pb node bytes for a UnixFS file whose leaves are raw blocks (go-ipld-prime encoding)."""
    links = b""
    sizes = b""
    for chunk in chunks:
        leaf_cid = _cid_bytes(_CODEC_RAW, hashlib.sha256(chunk).digest())
        link = (
            _field(1, 2, _varint(len(leaf_cid)) + leaf_cid)  # Hash
            + _field(2, 2, _varint(0))  # Name = ""
            + _field(3, 0, _varint(len(chunk)))  # Tsize
        )
        links += _field(2, 2, _varint(len(link)) + link)
        sizes += _field(4, 0, _varint(len(chunk)))  # blocksizes
    total = sum(len(c) for c in chunks)
    unixfs = _field(1, 0, _varint(_UNIXFS_FILE)) + _field(3, 0, _varint(total)) + sizes
    return links + _field(1, 2, _varint(len(unixfs)) + unixfs)


def compute_cid(data: bytes) -> str:
    """CIDv1 (base32) of ``data`` exactly as Kubo computes it with ``--cid-version=1 --raw-leaves``.

    Raises:
        IpfsError: If ``data`` needs more than :data:`MAX_LINKS` chunks.
    """
    if len(data) <= CHUNK_SIZE:
        return _encode_cid(_cid_bytes(_CODEC_RAW, hashlib.sha256(data).digest()))
    chunks = [data[i : i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]
    if len(chunks) > MAX_LINKS:
        raise IpfsError(f"file too large for the single-level layout ({len(chunks)} > {MAX_LINKS})")
    root = _unixfs_root(chunks)
    return _encode_cid(_cid_bytes(_CODEC_DAG_PB, hashlib.sha256(root).digest()))


def validate_cid(cid: str) -> None:
    """Raise :class:`IpfsError` unless ``cid`` is a well-formed base32 CIDv1 with sha2-256."""
    raw = _decode_cid(cid)
    well_formed = len(raw) == 36 and raw[0] == 1 and raw[2:4] == b"\x12\x20"
    if not well_formed or raw[1] not in (_CODEC_RAW, _CODEC_DAG_PB):
        raise IpfsError(f"unsupported CID: {cid!r}")


class IpfsBackend(Protocol):
    """What the publisher and gateway need from storage."""

    def put(self, data: bytes) -> str:
        """Store ``data``; return its CID."""

    def get(self, cid: str) -> bytes:
        """Fetch ``cid``; raise :class:`IpfsError` if missing or if the bytes do not hash to it."""


class LocalCidBackend:
    """A directory of blobs keyed by CID. Same CIDs as Kubo, no daemon; used in CI and eval."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def put(self, data: bytes) -> str:
        """Write the blob under its CID (idempotent)."""
        cid = compute_cid(data)
        path = self.directory / cid
        if not path.exists():
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(path)
        return cid

    def get(self, cid: str) -> bytes:
        """Read and re-verify a blob."""
        validate_cid(cid)
        path = self.directory / cid
        if not path.is_file():
            raise IpfsError(f"not found in local store: {cid}")
        data = path.read_bytes()
        if compute_cid(data) != cid:
            raise IpfsError(f"content does not match CID {cid} (corrupted store)")
        return data


class KuboBackend:
    """Kubo HTTP API (``/api/v0``) with the same CID parameters as :func:`compute_cid`."""

    def __init__(self, api_url: str, timeout: float = 30.0) -> None:
        self.api_url = api_url.rstrip("/")
        self._client = httpx.Client(base_url=self.api_url, timeout=timeout)

    def put(self, data: bytes) -> str:
        """``ipfs add --cid-version=1 --raw-leaves --pin``; asserts Kubo's CID equals ours."""
        expected = compute_cid(data)
        try:
            resp = self._client.post(
                "/api/v0/add",
                params={"cid-version": "1", "raw-leaves": "true", "pin": "true", "quiet": "true"},
                files={"file": ("blob", data)},
            )
            resp.raise_for_status()
            cid = str(resp.json()["Hash"])
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise IpfsError(f"kubo add failed: {exc}") from exc
        if cid != expected:
            raise IpfsError(f"kubo returned {cid} but local computation gives {expected}")
        return cid

    def get(self, cid: str) -> bytes:
        """``ipfs cat`` with content verification."""
        validate_cid(cid)
        try:
            resp = self._client.post("/api/v0/cat", params={"arg": cid})
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise IpfsError(f"kubo cat failed for {cid}: {exc}") from exc
        data = resp.content
        if compute_cid(data) != cid:
            raise IpfsError(f"content fetched for {cid} does not hash to it")
        return data

    def is_available(self) -> bool:
        """True iff the daemon answers ``/api/v0/version``."""
        try:
            return self._client.post("/api/v0/version").status_code == 200
        except httpx.HTTPError:
            return False


def make_backend(settings: Settings) -> IpfsBackend:
    """Backend selected by ``IPFS_BACKEND`` (``kubo`` | ``local``)."""
    if settings.ipfs_backend == "local":
        return LocalCidBackend(settings.local_ipfs_dir)
    return KuboBackend(settings.ipfs_api)
