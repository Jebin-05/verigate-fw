"""Model revocation flow (P6-06, Guide "Novelty 2"): revoked model → stale verdicts → re-verify.

The admin revokes a model hash on ``ModelRegistry`` (``verigate-admin revoke-model``). This job
polls the status of every model the gateway runs; when one turns REVOKED it

1. asks ``VerdictRegistry.staleByModel`` which committed batches used it,
2. collects the distinct (release, device) pairs in those batches from the local batch store,
3. hot-swaps the scorer slot to the registry's successor (located by hash under ``MODELS_DIR``;
   without a successor file the gate stays fail-closed: Stage 1 rejects on ``model_active``),
4. re-runs the full gate for every pair — the new records land in a new batch — and
5. persists a before/after report (``STATE_DIR/revocations.json``) the dashboard renders.

Everything is idempotent per revoked hash; a restart does not replay a handled revocation.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from verigate.common.chain import STATUS_REVOKED
from verigate.common.errors import ChainError, VerigateError
from verigate.common.logging import get_logger
from verigate.common.manifest import SemVer
from verigate.gateway.stage1.inputs import DeviceView

if TYPE_CHECKING:
    from verigate.gateway.service import GatewayService

log = get_logger(__name__)


@dataclass(frozen=True)
class Reverified:
    """One stale (release, device) pair before and after re-verification."""

    release_id: str
    device_id: str
    before: str
    before_id: str
    after: str
    after_id: str | None
    r_before: int
    r_after: int | None


@dataclass
class RevocationReport:
    """What one revocation did at this gateway."""

    model_hash: str
    successor: str
    swapped: bool
    stale_batches: list[int]
    pairs: list[Reverified] = field(default_factory=list)
    started_at: int = 0
    finished_at: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON form (camelCase like the rest of the API)."""
        return {
            "modelHash": self.model_hash,
            "successor": self.successor,
            "swapped": self.swapped,
            "staleBatches": self.stale_batches,
            "pairs": [
                {
                    "releaseId": p.release_id,
                    "deviceId": p.device_id,
                    "before": p.before,
                    "beforeId": p.before_id,
                    "after": p.after,
                    "afterId": p.after_id,
                    "rBefore": p.r_before,
                    "rAfter": p.r_after,
                }
                for p in self.pairs
            ],
            "changed": sum(p.before != p.after for p in self.pairs),
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "error": self.error,
        }


class RevocationJob:
    """Polls model status and replays stale verdicts with the successor model."""

    def __init__(self, service: GatewayService, path: Path, poll_s: float = 2.0) -> None:
        self.service = service
        self.path = path
        self.poll_s = poll_s
        self.reports: list[RevocationReport] = []
        self._running: set[str] = set()
        self._load()

    # ------------------------------------------------------------------ persistence

    def _load(self) -> None:
        if not self.path.exists():
            return
        for d in json.loads(self.path.read_text()):
            self.reports.append(
                RevocationReport(
                    model_hash=d["model_hash"],
                    successor=d["successor"],
                    swapped=d["swapped"],
                    stale_batches=d["stale_batches"],
                    pairs=[Reverified(**p) for p in d["pairs"]],
                    started_at=d["started_at"],
                    finished_at=d["finished_at"],
                    error=d.get("error"),
                )
            )

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([asdict(r) for r in self.reports], indent=2) + "\n")

    def handled(self) -> set[str]:
        """Model hashes already replayed."""
        return {r.model_hash for r in self.reports} | self._running

    # ------------------------------------------------------------------ the flow

    async def check_once(self) -> list[RevocationReport]:
        """Handle every configured model that has turned REVOKED since the last check."""
        done: list[RevocationReport] = []
        for digest in self.service.model_hashes():
            model_hash = "0x" + digest.hex()
            if model_hash in self.handled():
                continue
            try:
                record = await asyncio.to_thread(self.service.chain.get_model, digest)
            except ChainError as exc:
                log.warning("revocation.chain_unavailable", error=str(exc))
                return done
            if record.status != STATUS_REVOKED:
                continue
            self._running.add(model_hash)
            try:
                done.append(await self.handle(model_hash, "0x" + record.successor.hex()))
            finally:
                self._running.discard(model_hash)
        return done

    async def handle(self, model_hash: str, successor: str) -> RevocationReport:
        """Replay every verdict that ``model_hash`` took part in."""
        service = self.service
        report = RevocationReport(model_hash, successor, False, [], started_at=int(time.time()))
        log.warning("revocation.detected", model_hash=model_hash, successor=successor)
        try:
            stale = await asyncio.to_thread(
                service.chain.stale_by_model, bytes.fromhex(model_hash[2:])
            )
            report.stale_batches = list(stale)
            report.swapped = await service.swap_model(model_hash, successor)
            pairs = await asyncio.to_thread(self._stale_pairs, stale)
            for release_id, device_id, before, before_id, r_before in pairs:
                after = await self._reverify(release_id, device_id)
                report.pairs.append(
                    Reverified(
                        release_id,
                        device_id,
                        before,
                        before_id,
                        after["verdict"],
                        after.get("verdictId"),
                        r_before,
                        after.get("R"),
                    )
                )
        except VerigateError as exc:
            report.error = str(exc)
            log.error("revocation.failed", model_hash=model_hash, error=str(exc))
        report.finished_at = int(time.time())
        self.reports.append(report)
        self._save()
        log.warning(
            "revocation.reverified",
            model_hash=model_hash,
            successor=successor,
            swapped=report.swapped,
            stale_batches=len(report.stale_batches),
            pairs=len(report.pairs),
            changed=sum(p.before != p.after for p in report.pairs),
        )
        return report

    def _stale_pairs(self, stale: tuple[int, ...]) -> list[tuple[str, str, str, str, int]]:
        """Distinct (release, device) pairs in the stale batches, newest record per pair.

        The records live in the local batch store; a batch is only used when its root matches
        the on-chain batch of the same id (a chain reset leaves stale ids behind locally).
        """
        batcher = self.service.batcher
        if batcher is None:
            return []
        latest: dict[tuple[str, str], tuple[str, str, int]] = {}
        for batch in batcher.batches():
            if batch.batch_id not in stale:
                continue
            on_chain = self.service.chain.get_batch(batch.batch_id)
            if "0x" + on_chain.root.hex() != batch.root:
                log.warning("revocation.batch_mismatch", batch_id=batch.batch_id)
                continue
            for leaf, record in zip(batch.leaves, batch.records, strict=True):
                key = (record["releaseId"], record["deviceId"])
                latest[key] = (record["verdict"], leaf, int(record["R"]))
        return [(rid, dev, v, leaf, r) for (rid, dev), (v, leaf, r) in sorted(latest.items())]

    async def _reverify(self, release_id: str, device_id: str) -> dict[str, Any]:
        from verigate.gateway.service import REFERENCE_DEVICE_ID  # noqa: PLC0415 — cycle

        rid = bytes.fromhex(release_id[2:])
        if device_id == REFERENCE_DEVICE_ID:
            return (await self.service.verify(rid)).to_dict()
        device = self.service.devices.get(device_id)
        if device is None:  # the device is gone; still re-judge the release for the record
            return (await self.service.verify(rid)).to_dict()
        view = DeviceView(device_id, device.device_model, SemVer.parse(device.installed_version))
        return (await self.service.verify(rid, view)).to_dict()

    async def run(self, stop: asyncio.Event) -> None:
        """Background loop until ``stop`` is set."""
        while not stop.is_set():
            with contextlib.suppress(VerigateError):
                await self.check_once()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.poll_s)
