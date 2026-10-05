"""Gateway persistence under ``STATE_DIR``: pinned devices, verdict log, reviews, listener cursor.

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
        self._approved: set[str] = set()
        if path.is_file():
            with path.open() as fh:
                for line in fh:
                    if line.strip():
                        self._recent.append(json.loads(line))
                        self._note(self._recent[-1])
                        del self._recent[:-keep_in_memory]

    def append(self, entry: dict[str, Any]) -> None:
        """Append one JSON object (one line)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        self._note(entry)
        self._recent.append(entry)
        del self._recent[: -self._keep]

    def _note(self, entry: dict[str, Any]) -> None:
        if entry.get("verdict") == "APPROVE" and entry.get("releaseId"):
            self._approved.add(str(entry["releaseId"]))

    def ever_approved(self, release_id: str) -> bool:
        """True iff any logged verification of ``release_id`` (``0x…``) approved it."""
        return release_id in self._approved

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


@dataclass(frozen=True)
class Review:
    """A person's decision on a release the gate held for review (DEFER)."""

    release_id: str
    decision: str  # "APPROVE" | "REJECT"
    reviewer: str
    note: str
    decided_at: str
    held_because: str | None  # the DEFER reason the reviewer saw
    held_verdict_id: str | None  # the DEFER verdict that was reviewed
    review_verdict_id: str | None  # the anchored record of this decision

    def to_dict(self) -> dict[str, Any]:
        """JSON form (camelCase like the rest of the API)."""
        return {
            "releaseId": self.release_id,
            "decision": self.decision,
            "reviewer": self.reviewer,
            "note": self.note,
            "decidedAt": self.decided_at,
            "heldBecause": self.held_because,
            "heldVerdictId": self.held_verdict_id,
            "reviewVerdictId": self.review_verdict_id,
        }


class ReviewStore:
    """``reviews.json``: release id → :class:`Review` (one final decision per release)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._reviews: dict[str, Review] = {}
        if path.is_file():
            for rid, data in json.loads(path.read_text()).items():
                self._reviews[rid] = Review(**data)

    def get(self, release_id: str) -> Review | None:
        """The decision for ``release_id`` (``0x…``), if any."""
        return self._reviews.get(release_id)

    def put(self, review: Review) -> None:
        """Persist a decision."""
        self._reviews[review.release_id] = review
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(
            self.path,
            json.dumps({k: asdict(v) for k, v in self._reviews.items()}, indent=2) + "\n",
        )

    def all(self) -> list[Review]:
        """Every decision, oldest first."""
        return sorted(self._reviews.values(), key=lambda r: r.decided_at)
