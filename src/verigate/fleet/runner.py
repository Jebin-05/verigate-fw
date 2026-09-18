"""asyncio fleet runner (P3-06): N devices that hello, poll, download, self-verify, install, report.

Each device is one coroutine; all share one ``httpx.AsyncClient``. The loop is deliberately
simple and observable: every step logs a structured event with ``device_id`` so the dashboard's
live log shows the fleet moving.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from verigate.common.errors import VerificationError
from verigate.common.logging import get_logger
from verigate.common.manifest import SignedManifest
from verigate.fleet.device import Device

log = get_logger(__name__)


@dataclass
class FleetStats:
    """Counters the CLI prints and the e2e tests assert on."""

    polls: int = 0
    installs: int = 0
    receipts: int = 0
    rejected: int = 0
    errors: int = 0
    last_verdicts: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        return {
            "polls": self.polls,
            "installs": self.installs,
            "receipts": self.receipts,
            "rejected": self.rejected,
            "errors": self.errors,
            "lastVerdicts": dict(self.last_verdicts),
        }


class DeviceAgent:
    """Drives one :class:`Device` against the gateway."""

    def __init__(self, device: Device, client: httpx.AsyncClient, stats: FleetStats) -> None:
        self.device = device
        self.client = client
        self.stats = stats

    async def _post(self, path: str, payload: dict[str, Any]) -> httpx.Response:
        msg = self.device.sign(payload, now=int(time.time()))
        return await self.client.post(path, json=msg.model_dump())

    async def hello(self) -> None:
        """Announce identity and installed version (pins the key on the gateway)."""
        resp = await self._post("/devices/hello", self.device.hello_payload())
        resp.raise_for_status()
        log.info(
            "fleet.hello",
            device_id=self.device.device_id,
            version=str(self.device.installed_version),
        )

    async def step(self) -> str | None:
        """One poll; installs if the gateway approved an update. Returns the verdict seen."""
        self.stats.polls += 1
        resp = await self._post("/devices/poll", self.device.hello_payload())
        resp.raise_for_status()
        body = resp.json()
        verdict = (body.get("verdict") or {}).get("verdict")
        if verdict:
            self.stats.last_verdicts[self.device.device_id] = verdict
        update = body.get("update")
        if not update:
            if verdict and verdict != "APPROVE":
                self.stats.rejected += 1
                log.info(
                    "fleet.blocked",
                    device_id=self.device.device_id,
                    verdict=verdict,
                    reason=(body.get("verdict") or {}).get("reason"),
                )
            return verdict
        manifest = SignedManifest.model_validate(update["manifest"])
        firmware = (await self.client.get(update["firmwareUrl"])).content
        try:
            receipt = self.device.install(firmware, manifest, update["publisherKey"])
        except VerificationError as exc:
            self.stats.errors += 1
            log.error("fleet.self_check_failed", device_id=self.device.device_id, error=str(exc))
            return verdict
        self.stats.installs += 1
        resp = await self._post("/devices/receipt", {"receipt": receipt.model_dump()})
        resp.raise_for_status()
        self.stats.receipts += 1
        log.info(
            "fleet.receipt",
            device_id=self.device.device_id,
            release_id=receipt.releaseId,
            version=receipt.version,
        )
        return verdict


async def run_fleet(
    gateway_url: str,
    state_dir: Path,
    count: int,
    device_model: str = "demo-device",
    interval_s: float = 5.0,
    rounds: int | None = None,
    prefix: str = "dev",
) -> FleetStats:
    """Run ``count`` devices; ``rounds=None`` polls forever, otherwise that many rounds each."""
    stats = FleetStats()
    devices = [Device(state_dir, f"{prefix}-{i:03d}", device_model) for i in range(count)]
    async with httpx.AsyncClient(base_url=gateway_url, timeout=60) as client:
        agents = [DeviceAgent(d, client, stats) for d in devices]
        await asyncio.gather(*(a.hello() for a in agents))

        async def loop(agent: DeviceAgent) -> None:
            done = 0
            while rounds is None or done < rounds:
                try:
                    await agent.step()
                except (httpx.HTTPError, ValueError) as exc:
                    stats.errors += 1
                    log.warning(
                        "fleet.poll_error", device_id=agent.device.device_id, error=str(exc)
                    )
                done += 1
                if rounds is None or done < rounds:
                    await asyncio.sleep(interval_s)

        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.gather(*(loop(a) for a in agents))
    log.info("fleet.done", **stats.to_dict())
    return stats
