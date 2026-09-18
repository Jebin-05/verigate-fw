"""Gateway persistence under ``STATE_DIR``: pinned devices, verdict log, listener cursor.

Small JSON files, rewritten atomically. Enough for a fleet of hundreds of emulated devices; the
evaluation runs (P7) record their own results under ``evaluation/results/``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DeviceRecord:
    """A device the gateway has heard from (key pinned on first ``hello``, TOFU)."""

    device_id: str
    device_model: str
    public_key: str
    installed_version: str
    last_nonce: int
    last_seen: int
    installed_release_id: str | None = None
    receipts: int = 0


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    tmp.replace(path)


class DeviceStore:
    """``devices.json``: device_id → :class:`DeviceRecord`."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._devices: dict[str, DeviceRecord] = {}
        if path.is_file():
            for item in json.loads(path.read_text()).values():
                record = DeviceRecord(**item)
                self._devices[record.device_id] = record

    def get(self, device_id: str) -> DeviceRecord | None:
        """Record for ``device_id`` or ``None``."""
        return self._devices.get(device_id)

    def put(self, record: DeviceRecord) -> None:
        """Insert or replace and persist."""
        self._devices[record.device_id] = record
        _atomic_write(
            self.path,
            json.dumps({k: asdict(v) for k, v in sorted(self._devices.items())}, indent=2) + "\n",
        )

    def all(self) -> list[DeviceRecord]:
        """Every device, sorted by id."""
        return [self._devices[k] for k in sorted(self._devices)]


class VerdictLog:
    """``verdicts.jsonl``: append-only log of every verification the gateway performed."""

    def __init__(self, path: Path, keep_in_memory: int = 1000) -> None:
        self.path = path
        self._recent: list[dict[str, Any]] = []
        self._keep = keep_in_memory
        if path.is_file():
            with path.open() as fh:
                for line in fh:
                    if line.strip():
                        self._recent.append(json.loads(line))
            self._recent = self._recent[-keep_in_memory:]

    def append(self, entry: dict[str, Any]) -> None:
        """Append one JSON object (one line)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        self._recent.append(entry)
        del self._recent[: -self._keep]

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Most recent entries, newest last."""
        return self._recent[-limit:]

    def __iter__(self) -> Iterator[dict[str, Any]]:
        """Iterate over the in-memory tail."""
        return iter(self._recent)


class Cursor:
    """``listener.json``: last block the ``NewRelease`` listener fully processed."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.last_block = -1
        if path.is_file():
            self.last_block = int(json.loads(path.read_text())["last_block"])

    def advance(self, block: int) -> None:
        """Persist ``block`` as fully processed."""
        self.last_block = block
        _atomic_write(self.path, json.dumps({"last_block": block}) + "\n")
