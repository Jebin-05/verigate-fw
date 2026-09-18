"""``NewRelease`` event listener (P3-04): polling, resumable, exponential backoff, never skips.

The cursor (``STATE_DIR/listener.json``) only advances after every event of a block range has
been handled, so a crash or an RPC error re-processes rather than skips. Handling is idempotent
(the service just re-fetches the record), so re-processing is harmless.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from typing import Any

from verigate.common.chain import ChainClient
from verigate.common.errors import ChainError
from verigate.common.logging import get_logger
from verigate.gateway.store import Cursor

log = get_logger(__name__)

MAX_RANGE = 2_000


class NewReleaseListener:
    """Poll ``FirmwareRegistry.NewRelease`` and hand each ``releaseId`` to ``on_release``."""

    def __init__(
        self,
        chain: ChainClient,
        cursor: Cursor,
        on_release: Callable[[bytes, int], Awaitable[None]],
        poll_interval_s: float = 2.0,
        max_backoff_s: float = 60.0,
    ) -> None:
        self.chain = chain
        self.cursor = cursor
        self.on_release = on_release
        self.poll_interval_s = poll_interval_s
        self.max_backoff_s = max_backoff_s
        self.backoff_s = poll_interval_s
        self.errors = 0
        self.events = 0

    def _fetch(self, from_block: int, to_block: int) -> list[Any]:
        try:
            event = self.chain.firmware.events.NewRelease()
            return list(event.get_logs(from_block=from_block, to_block=to_block))
        except Exception as exc:
            raise ChainError(f"get_logs failed: {exc}") from exc

    async def poll_once(self) -> int:
        """Process every new block once; returns the number of events handled.

        Raises:
            ChainError: If the RPC failed (the cursor is left untouched).
        """
        latest = await asyncio.to_thread(self.chain.block_number)
        if self.cursor.last_block > latest:
            # A local node was restarted from genesis (dev/demo). Re-processing is idempotent.
            log.warning("listener.chain_reset", cursor=self.cursor.last_block, latest=latest)
            self.cursor.advance(-1)
        start = self.cursor.last_block + 1
        if start > latest:
            return 0
        handled = 0
        while start <= latest:
            end = min(start + MAX_RANGE - 1, latest)
            logs = await asyncio.to_thread(self._fetch, start, end)
            for entry in logs:
                release_id = bytes(entry["args"]["releaseId"])
                block = int(entry["blockNumber"])
                log.info("listener.new_release", release_id="0x" + release_id.hex(), block=block)
                await self.on_release(release_id, block)
                handled += 1
            self.cursor.advance(end)
            start = end + 1
        self.events += handled
        return handled

    async def run(self, stop: asyncio.Event | None = None) -> None:
        """Poll forever (or until ``stop`` is set) with exponential backoff on RPC errors."""
        stop = stop or asyncio.Event()
        while not stop.is_set():
            try:
                await self.poll_once()
                self.backoff_s = self.poll_interval_s
            except ChainError as exc:
                self.errors += 1
                log.warning("listener.rpc_error", error=str(exc), retry_in_s=self.backoff_s)
                delay = self.backoff_s
                self.backoff_s = min(self.backoff_s * 2, self.max_backoff_s)
                await _sleep_or_stop(stop, delay)
                continue
            await _sleep_or_stop(stop, self.poll_interval_s)


async def _sleep_or_stop(stop: asyncio.Event, seconds: float) -> None:
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=seconds)
