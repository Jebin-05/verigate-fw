"""Batcher: size/time flush, persistence, proofs, retry after chain failure. Reputation: EWMA."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fake_chain import FakeAccount, FakeChain

from verigate.common.crypto import KeyPair
from verigate.common.merkle import MerkleTree, verify_proof
from verigate.gateway.reputation import ReputationUpdater, ewma
from verigate.gateway.verdicts.batch import VerdictBatcher
from verigate.gateway.verdicts.record import VerdictRecord, feature_hash

KEY = "0x" + "22" * 32


def record(i: int, model: str | None = None) -> VerdictRecord:
    return VerdictRecord(
        releaseId="0x" + f"{i:064x}",
        deviceId=f"dev-{i}",
        modelHashes=[model] if model else [],
        featureHash=feature_hash({"i": i}),
        r_sbom=0,
        r_img=0,
        reputation=5000,
        R=1000,
        verdict="APPROVE",  # type: ignore[arg-type]
        rationaleCid=None,
        ts=1_789_000_000 + i,
    ).sign(KEY)


@pytest.fixture
def batcher(tmp_path: Path) -> tuple[VerdictBatcher, FakeChain]:
    chain = FakeChain()
    b = VerdictBatcher(chain, FakeAccount(KEY), tmp_path / "batches", max_size=3, max_wait_s=0.05)  # type: ignore[arg-type]
    return b, chain


async def test_flush_on_size_persist_and_prove(
    batcher: tuple[VerdictBatcher, FakeChain], tmp_path: Path
) -> None:
    b, chain = batcher
    m = "0x" + "aa" * 32
    ids = [await b.add(record(i, m if i == 1 else None)) for i in range(3)]
    assert b.pending == 0 and b.commits == 1 and len(chain.committed) == 1
    leaves = [bytes.fromhex(i[2:]) for i in ids]
    assert chain.committed[0]["root"] == MerkleTree.from_leaves(leaves).root
    assert chain.committed[0]["count"] == 3 and chain.committed[0]["modelHashes"] == [
        bytes.fromhex("aa" * 32)
    ]
    proof = b.proof(ids[1])
    assert proof is not None and proof["status"] == "committed" and proof["batchId"] == 0
    assert verify_proof(
        chain.committed[0]["root"], leaves[1], [bytes.fromhex(p[2:]) for p in proof["proof"]]
    )
    assert proof["record"]["deviceId"] == "dev-1" and proof["index"] == 1
    assert b.proof(ids[1][2:]) == proof  # without 0x prefix
    assert b.proof("0x" + "00" * 32) is None
    assert [x.batch_id for x in b.batches()] == [0]
    # reload from disk
    again = VerdictBatcher(chain, FakeAccount(KEY), tmp_path / "batches")  # type: ignore[arg-type]
    assert again.proof(ids[2]) == b.proof(ids[2])
    assert (tmp_path / "batches" / "00000000.json").is_file()


async def test_flush_on_time_and_pending_proof(batcher: tuple[VerdictBatcher, FakeChain]) -> None:
    b, _chain = batcher
    vid = await b.add(record(7))
    assert b.proof(vid) == {"verdictId": vid, "status": "pending"}
    stop = asyncio.Event()
    task = asyncio.create_task(b.run(stop))
    await asyncio.sleep(0.3)
    assert b.commits == 1 and b.pending == 0
    stop.set()
    await task
    assert b.proof(vid) is not None and b.proof(vid)["status"] == "committed"
    assert await b.flush() is None  # nothing pending


async def test_commit_failure_keeps_verdicts_pending(
    batcher: tuple[VerdictBatcher, FakeChain],
) -> None:
    b, chain = batcher
    chain.down = True
    await b.add(record(1))
    assert await b.flush() is None
    assert b.pending == 1 and b.failures == 1 and b.commits == 0
    chain.down = False
    committed = await b.flush()
    assert committed is not None and committed.count == 1 and b.pending == 0


@pytest.mark.parametrize(
    ("rep", "signal", "alpha", "expected"),
    [
        (5000, 10_000, 1000, 5500),
        (5000, 0, 1000, 4500),
        (10_000, 10_000, 1000, 10_000),
        (0, 0, 1000, 0),
        (9996, 10_000, 1000, 9996),
        (5000, 10_000, 10_000, 10_000),
        (1, 0, 1000, 1),
    ],
)
def test_ewma(rep: int, signal: int, alpha: int, expected: int) -> None:
    assert ewma(rep, signal, alpha) == expected


def test_ewma_rejects_out_of_range() -> None:
    with pytest.raises(ValueError, match="alpha"):
        ewma(0, 0, 10_001)
    with pytest.raises(ValueError, match="signal"):
        ewma(0, -1, 100)


async def test_reputation_updater() -> None:
    chain = FakeChain()
    pid = chain.add_publisher("did:verigate:r", KeyPair.generate())
    updater = ReputationUpdater(chain, FakeAccount(KEY), 1000)  # type: ignore[arg-type]
    assert await updater.on_receipt(pid) == 5500
    assert await updater.on_reject(pid, "sbom_hash") == 4950
    assert chain.get_publisher(pid).reputation_bp == 4950 and updater.updates == 2
    assert await updater.on_receipt(b"\x09" * 32) is None  # unknown publisher
    chain.down = True
    assert await updater.on_receipt(pid) is None and updater.failures == 1
    chain.down = False
    chain.publisher_records[pid] = chain.get_publisher(pid).__class__(
        **{**chain.get_publisher(pid).__dict__, "reputation_bp": 10_000}
    )
    assert (
        await updater.on_receipt(pid) == 10_000 and len(chain.reputations) == 2
    )  # no tx when unchanged
