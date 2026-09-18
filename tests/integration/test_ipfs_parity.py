"""P1-14: Kubo and LocalCid backends produce identical CIDs and both verify content."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from verigate.common.errors import IpfsError
from verigate.common.ipfs import CHUNK_SIZE, IpfsBackend, KuboBackend, LocalCidBackend, compute_cid

pytestmark = pytest.mark.integration


def blob(n: int) -> bytes:
    seed = hashlib.sha256(str(n).encode()).digest()
    return seed * (n // 32) + b"x" * (n % 32)


@pytest.mark.parametrize(
    "size", [0, 1, 5, 4096, CHUNK_SIZE, CHUNK_SIZE + 1, 300 * 1024, 700 * 1024]
)
def test_kubo_and_local_agree(kubo: KuboBackend, tmp_path: Path, size: int) -> None:
    local = LocalCidBackend(tmp_path)
    data = blob(size)
    cid_k = kubo.put(data)
    cid_l = local.put(data)
    assert cid_k == cid_l == compute_cid(data)
    assert kubo.get(cid_k) == data
    assert local.get(cid_l) == data


def test_configured_backend_round_trips_fixture_manifest(ipfs: IpfsBackend) -> None:
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "crypto" / "signed_manifest.json"
    data = fixture.read_bytes()
    cid = ipfs.put(data)
    assert ipfs.get(cid) == data


def test_kubo_missing_cid_fails_closed(kubo: KuboBackend) -> None:
    kubo._client.timeout = 3  # noqa: SLF001 — an unknown CID makes Kubo search the network
    with pytest.raises(IpfsError):
        kubo.get(compute_cid(b"never-added-" + hashlib.sha256(b"x").digest()))
