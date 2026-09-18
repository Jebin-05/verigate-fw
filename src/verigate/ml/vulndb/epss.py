"""EPSS (FIRST) exploit-probability snapshots by date (P5-01)."""

from __future__ import annotations

import csv
import gzip
import io
from datetime import date

import httpx

from verigate.ml.vulndb.cache import DiskCache


class EpssSnapshot:
    """``cve → epss`` for one scoring date (``epss_scores-YYYY-MM-DD.csv.gz``)."""

    def __init__(self, snapshot_date: date, scores: dict[str, float], model_version: str) -> None:
        self.date = snapshot_date
        self.scores = scores
        self.model_version = model_version

    def get(self, cve: str) -> float | None:
        """EPSS probability in [0, 1] or ``None`` if unknown to that snapshot."""
        return self.scores.get(cve)

    @classmethod
    def load(
        cls,
        base_url: str,
        snapshot_date: date,
        cache: DiskCache,
        timeout: float = 120,
        transport: httpx.BaseTransport | None = None,
    ) -> EpssSnapshot:
        """Fetch (or read from cache) the snapshot for ``snapshot_date``."""
        key = snapshot_date.isoformat()
        raw = cache.get("epss", key)
        if raw is None:
            cache.require_online(f"EPSS snapshot {key}")
            url = f"{base_url.rstrip('/')}/epss_scores-{key}.csv.gz"
            with httpx.Client(timeout=timeout, follow_redirects=True, transport=transport) as http:
                resp = http.get(url)
                resp.raise_for_status()
                raw = resp.content
            cache.put("epss", key, raw)
        text = gzip.decompress(raw).decode("utf-8")
        lines = text.splitlines()
        model_version = (
            lines[0].lstrip("#").split(",")[0] if lines and lines[0].startswith("#") else ""
        )
        body = "\n".join(line for line in lines if not line.startswith("#"))
        scores: dict[str, float] = {}
        for row in csv.DictReader(io.StringIO(body)):
            scores[row["cve"]] = float(row["epss"])
        return cls(snapshot_date, scores, model_version)
