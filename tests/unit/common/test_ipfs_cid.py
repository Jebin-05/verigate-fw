"""CID computation (measured against Kubo), local backend round-trips, fail-closed branches."""

from __future__ import annotations

import hashlib
from pathlib import Path

import httpx
import pytest

from verigate.common.errors import IpfsError
from verigate.common.ipfs import (
    CHUNK_SIZE,
    MAX_LINKS,
    KuboBackend,
    LocalCidBackend,
    compute_cid,
    make_backend,
    validate_cid,
)
from verigate.common.settings import Settings

# Ground truth measured with `ipfs add --cid-version=1 --raw-leaves` on ipfs/kubo:v0.30.0
# (2026-09-18); tests/integration/test_ipfs_parity.py re-measures against the live daemon.
KUBO_CIDS = {
    5: "bafkreihk6fv4a6li4aj7h6kkwe2ci4sdji47yndv6eopgqngyolfs5hy5e",
    262144: "bafkreifwnz5hbvaylm32r4ss3b55dgbj5z3dagvhogbgbqu37ll24f2jzy",
    262145: "bafybeibo2duhnvojetes3cfgbzgwcr4q5i6do5oayytgir72tbtq64paqi",
    307200: "bafybeigt7qgn7np4qhnvton354dwnv26fjrh25qqq7qtvv7dlu2fjn3yc4",
    716800: "bafybeiffckoixdsmkglelktuqb7qsdk3huodwhveywz3mf5jxdrr7u7aem",
}


def blob(n: int) -> bytes:
    """Deterministic test content of ``n`` bytes (same generator as the Kubo measurement)."""
    seed = hashlib.sha256(str(n).encode()).digest()
    return seed * (n // 32) + b"x" * (n % 32)


@pytest.mark.parametrize(("size", "cid"), sorted(KUBO_CIDS.items()))
def test_compute_cid_matches_kubo(size: int, cid: str) -> None:
    assert compute_cid(blob(size)) == cid


def test_empty_and_boundary() -> None:
    assert compute_cid(b"").startswith("bafkrei")
    assert compute_cid(b"a" * CHUNK_SIZE).startswith("bafkrei")
    assert compute_cid(b"a" * (CHUNK_SIZE + 1)).startswith("bafybei")


def test_too_large_raises() -> None:
    with pytest.raises(IpfsError, match="too large"):
        compute_cid(b"\x00" * (CHUNK_SIZE * (MAX_LINKS + 1)))


@pytest.mark.parametrize(
    "cid",
    [
        "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",  # CIDv0
        "b!!!",  # not base32
        "bafkreihk6fv4a6li4aj7h6kkwe2ci4sdji47yndv6eopgqngyolfs5hy",  # truncated
        "bafyreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",  # dag-cbor codec
    ],
)
def test_validate_cid_rejects(cid: str) -> None:
    with pytest.raises(IpfsError):
        validate_cid(cid)


def test_local_backend_round_trip(tmp_path: Path) -> None:
    backend = LocalCidBackend(tmp_path / "store")
    data = blob(307200)
    cid = backend.put(data)
    assert cid == KUBO_CIDS[307200]
    assert backend.put(data) == cid  # idempotent
    assert backend.get(cid) == data
    assert (tmp_path / "store" / cid).is_file()


def test_local_backend_fails_closed(tmp_path: Path) -> None:
    backend = LocalCidBackend(tmp_path / "store")
    cid = backend.put(b"hello")
    with pytest.raises(IpfsError, match="not found"):
        backend.get(compute_cid(b"other"))
    (tmp_path / "store" / cid).write_bytes(b"tampered")
    with pytest.raises(IpfsError, match="does not match"):
        backend.get(cid)
    with pytest.raises(IpfsError):
        backend.get("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")


def test_kubo_backend_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = KuboBackend("http://127.0.0.1:1", timeout=0.2)
    assert backend.is_available() is False
    with pytest.raises(IpfsError, match="add failed"):
        backend.put(b"x")
    with pytest.raises(IpfsError, match="cat failed"):
        backend.get(compute_cid(b"x"))


def test_kubo_backend_rejects_mismatched_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = KuboBackend("http://kubo.invalid")
    good = compute_cid(b"payload")

    def respond(path: str, **kwargs: object) -> httpx.Response:
        request = httpx.Request("POST", "http://kubo.invalid" + path)
        if path.endswith("/add"):
            return httpx.Response(200, json={"Hash": compute_cid(b"other")}, request=request)
        return httpx.Response(200, content=b"not the payload", request=request)

    fake_post = respond

    monkeypatch.setattr(backend._client, "post", fake_post)
    with pytest.raises(IpfsError, match="local computation"):
        backend.put(b"payload")
    with pytest.raises(IpfsError, match="does not hash"):
        backend.get(good)

    def bad_json(path: str, **_: object) -> httpx.Response:
        return httpx.Response(200, content=b"{}", request=httpx.Request("POST", "http://k" + path))

    monkeypatch.setattr(backend._client, "post", bad_json)
    with pytest.raises(IpfsError, match="add failed"):
        backend.put(b"payload")


def test_make_backend(settings: Settings) -> None:
    assert isinstance(make_backend(settings), LocalCidBackend)
    kubo = make_backend(Settings(_env_file=None, ipfs_backend="kubo", ipfs_api="http://h:5001/"))
    assert isinstance(kubo, KuboBackend)
    assert kubo.api_url == "http://h:5001"
