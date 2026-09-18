"""Live log fan-out for the dashboard's ``/logs`` websocket.

A structlog processor copies every rendered event into per-subscriber asyncio queues. Log calls
may come from worker threads (``asyncio.to_thread``), so hand-off goes through
``loop.call_soon_threadsafe``. Slow subscribers drop events rather than block the gateway.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from typing import Any

QUEUE_SIZE = 500


class LogHub:
    """Broadcast of structured log events to websocket subscribers."""

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queues: set[asyncio.Queue[dict[str, Any]]] = set()
        self.dropped = 0

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        """Attach to the running event loop (call from app startup)."""
        self._loop = loop

    def processor(self, _logger: Any, _method: str, event_dict: dict[str, Any]) -> dict[str, Any]:  # noqa: ANN401
        """Structlog processor: enqueue a copy of the event, then pass it on unchanged."""
        if self._loop is not None and self._queues:
            snapshot = dict(event_dict)
            with contextlib.suppress(RuntimeError):  # loop closed during shutdown
                self._loop.call_soon_threadsafe(self._publish, snapshot)
        return event_dict

    def _publish(self, event: dict[str, Any]) -> None:
        for queue in list(self._queues):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                self.dropped += 1

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        """Yield events until the consumer stops iterating."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=QUEUE_SIZE)
        self._queues.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._queues.discard(queue)

    @property
    def subscribers(self) -> int:
        """Number of live subscribers."""
        return len(self._queues)


hub = LogHub()
"""Process-wide hub; ``configure_logging`` is given ``hub.processor``."""
