"""Merkle batching of verdicts (P4-02): accumulate → tree → ``commitBatch`` → keep proofs.

One transaction per batch of up to ``BATCH_MAX_SIZE`` verdicts or ``BATCH_MAX_WAIT_S`` seconds
(ADR-0005). Batches are persisted under ``STATE_DIR/batches/<batchId>.json`` with every record
and leaf, so ``/verdicts/{id}/proof`` can rebuild a proof at any time and anyone can check it
against ``VerdictRegistry.verifyLeaf``. A failed commit keeps the verdicts pending and retries.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from eth_account.signers.local import LocalAccount

from verigate.common.chain import ChainClient
from verigate.common.errors import ChainError
from verigate.common.logging import get_logger
from verigate.common.merkle import MerkleTree
from verigate.gateway.verdicts.record import VerdictRecord

log = get_logger(__name__)


@dataclass(frozen=True)
class CommittedBatch:
    """A batch that made it on-chain."""

    batch_id: int
    root: str
    count: int
    tx_hash: str
    block_number: int
    model_hashes: list[str]
    leaves: list[str]
    records: list[dict[str, Any]]
    committed_at: int

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        return {
            "batchId": self.batch_id,
            "root": self.root,
            "count": self.count,
            "txHash": self.tx_hash,
            "blockNumber": self.block_number,
            "modelHashes": self.model_hashes,
            "leaves": self.leaves,
            "records": self.records,
            "committedAt": self.committed_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CommittedBatch:
        """Inverse of :meth:`to_dict`."""
        return cls(
            d["batchId"],
            d["root"],
            d["count"],
            d["txHash"],
            d["blockNumber"],
            d["modelHashes"],
            d["leaves"],
            d["records"],
            d["committedAt"],
        )


@dataclass
class VerdictBatcher:
    """Collects signed verdict records and commits them as Merkle batches."""

    chain: ChainClient
    account: LocalAccount
    store_dir: Path
    max_size: int = 50
    max_wait_s: float = 10.0
    _pending: list[VerdictRecord] = field(default_factory=list, init=False)
    _index: dict[str, int] = field(default_factory=dict, init=False)
    _batches: dict[int, CommittedBatch] = field(default_factory=dict, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)
    _first_pending_at: float | None = field(default=None, init=False)
    commits: int = field(default=0, init=False)
    failures: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        """Reload committed batches from disk."""
        self.store_dir.mkdir(parents=True, exist_ok=True)
        for path in sorted(self.store_dir.glob("*.json")):
            batch = CommittedBatch.from_dict(json.loads(path.read_text()))
            self._batches[batch.batch_id] = batch
            for leaf in batch.leaves:
                self._index[leaf] = batch.batch_id

    # ------------------------------------------------------------------ queue

    async def add(self, record: VerdictRecord) -> str:
        """Queue a record; returns its verdict id (the leaf hex). Flushes when the batch is full."""
        leaf = "0x" + record.leaf().hex()
        async with self._lock:
            self._pending.append(record)
            if self._first_pending_at is None:
                self._first_pending_at = time.monotonic()
            full = len(self._pending) >= self.max_size
        if full:
            await self.flush()
        return leaf

    @property
    def pending(self) -> int:
        """Verdicts waiting for the next commit."""
        return len(self._pending)

    # ------------------------------------------------------------------ commit

    def _commit(self, records: list[VerdictRecord]) -> CommittedBatch:
        leaves = [r.leaf() for r in records]
        tree = MerkleTree.from_leaves(leaves)
        hashes = sorted({h for r in records for h in r.modelHashes})
        receipt = self.chain.send(
            self.chain.verdicts.functions.commitBatch(
                tree.root, len(leaves), [bytes.fromhex(h[2:]) for h in hashes]
            ),
            self.account,
        )
        events = self.chain.verdicts.events.BatchCommitted().process_receipt(receipt)
        batch_id = int(events[0]["args"]["batchId"]) if events else -1
        return CommittedBatch(
            batch_id=batch_id,
            root="0x" + tree.root.hex(),
            count=len(leaves),
            tx_hash="0x" + bytes(receipt["transactionHash"]).hex(),
            block_number=int(receipt["blockNumber"]),
            model_hashes=hashes,
            leaves=["0x" + leaf.hex() for leaf in leaves],
            records=[r.model_dump(mode="json") for r in records],
            committed_at=int(time.time()),
        )

    async def flush(self) -> CommittedBatch | None:
        """Commit everything pending in one transaction (no-op when nothing is pending)."""
        async with self._lock:
            if not self._pending:
                return None
            records, self._pending = self._pending, []
            self._first_pending_at = None
            try:
                batch = await asyncio.to_thread(self._commit, records)
            except ChainError as exc:
                self.failures += 1
                self._pending = records + self._pending
                self._first_pending_at = time.monotonic()
                log.warning("batch.commit_failed", count=len(records), error=str(exc))
                return None
            self._batches[batch.batch_id] = batch
            for leaf in batch.leaves:
                self._index[leaf] = batch.batch_id
            path = self.store_dir / f"{batch.batch_id:08d}.json"
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(batch.to_dict(), indent=2, sort_keys=True) + "\n")
            tmp.replace(path)
            self.commits += 1
            log.info(
                "batch.committed",
                batch_id=batch.batch_id,
                count=batch.count,
                root=batch.root,
                tx=batch.tx_hash,
                block=batch.block_number,
            )
            return batch

    async def run(self, stop: asyncio.Event) -> None:
        """Flush on the time limit until ``stop`` is set (then flush once more)."""
        while not stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=min(self.max_wait_s, 1.0))
            first = self._first_pending_at
            if first is not None and time.monotonic() - first >= self.max_wait_s:
                await self.flush()
        await self.flush()

    # ------------------------------------------------------------------ proofs

    def proof(self, leaf: str) -> dict[str, Any] | None:
        """Proof for a verdict id, ``{"status": "pending"}`` if not yet committed, or ``None``."""
        leaf = leaf if leaf.startswith("0x") else "0x" + leaf
        batch_id = self._index.get(leaf)
        if batch_id is None:
            if any("0x" + r.leaf().hex() == leaf for r in self._pending):
                return {"verdictId": leaf, "status": "pending"}
            return None
        batch = self._batches[batch_id]
        index = batch.leaves.index(leaf)
        tree = MerkleTree.from_leaves([bytes.fromhex(h[2:]) for h in batch.leaves])
        return {
            "verdictId": leaf,
            "status": "committed",
            "batchId": batch.batch_id,
            "root": batch.root,
            "txHash": batch.tx_hash,
            "blockNumber": batch.block_number,
            "index": index,
            "proof": ["0x" + p.hex() for p in tree.proof(index)],
            "record": batch.records[index],
        }

    def batches(self) -> list[CommittedBatch]:
        """Committed batches, oldest first."""
        return [self._batches[k] for k in sorted(self._batches)]
