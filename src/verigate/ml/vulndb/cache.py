"""Content-keyed disk cache shared by the OSV / EPSS / KEV clients (P5-01).

Every network answer is stored under ``VULN_CACHE_DIR/<kind>/<sha256(key)>``. With
``VULN_CACHE_ONLY=true`` a miss raises :class:`OfflineMissError` instead of touching the network,
which is how the demo runs without Wi-Fi (Manual §16). The snapshot date of every fetch is kept
next to the payload so results can say which data they were computed from.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from verigate.common.errors import VerigateError


class OfflineMissError(VerigateError):
    """Offline mode and the requested item is not cached."""


class DiskCache:
    """A tiny key → bytes store with per-entry fetch timestamps."""

    def __init__(self, root: Path, offline: bool = False) -> None:
        self.root = root
        self.offline = offline
        self.hits = 0
        self.misses = 0

    def _path(self, kind: str, key: str) -> Path:
        return self.root / kind / hashlib.sha256(key.encode()).hexdigest()

    def get(self, kind: str, key: str) -> bytes | None:
        """Cached bytes or ``None``."""
        path = self._path(kind, key)
        if path.is_file():
            self.hits += 1
            return path.read_bytes()
        self.misses += 1
        return None

    def put(self, kind: str, key: str, data: bytes) -> None:
        """Store ``data`` atomically together with a ``.meta`` record (key, fetched_at)."""
        path = self._path(kind, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)
        path.with_suffix(".meta").write_text(
            json.dumps({"key": key, "fetched_at": int(time.time())}) + "\n"
        )

    def fetched_at(self, kind: str, key: str) -> int | None:
        """Unix time the entry was fetched, or ``None``."""
        meta = self._path(kind, key).with_suffix(".meta")
        if not meta.is_file():
            return None
        return int(json.loads(meta.read_text())["fetched_at"])

    def require_online(self, what: str) -> None:
        """Raise if offline (call before any network access)."""
        if self.offline:
            raise OfflineMissError(f"offline mode (VULN_CACHE_ONLY=true) and {what} is not cached")
