"""CISA Known Exploited Vulnerabilities catalogue with "as of date" membership (P5-01)."""

from __future__ import annotations

import json
from datetime import date

import httpx

from verigate.ml.vulndb.cache import DiskCache


class KevCatalogue:
    """``cve → dateAdded``; membership is evaluated as of a given date (temporal splits)."""

    def __init__(self, added: dict[str, date], released: str) -> None:
        self.added = added
        self.released = released

    def is_kev(self, cve: str, as_of: date | None = None) -> bool:
        """True iff ``cve`` was in the catalogue on ``as_of`` (default: the snapshot date)."""
        when = self.added.get(cve)
        if when is None:
            return False
        return as_of is None or when <= as_of

    @classmethod
    def load(
        cls,
        url: str,
        cache: DiskCache,
        timeout: float = 120,
        transport: httpx.BaseTransport | None = None,
    ) -> KevCatalogue:
        """Fetch (or read from cache) the catalogue; offline mode serves the cached copy."""
        raw = cache.get("kev", "catalogue")
        if raw is None:
            cache.require_online("KEV catalogue")
            with httpx.Client(timeout=timeout, follow_redirects=True, transport=transport) as http:
                resp = http.get(url)
                resp.raise_for_status()
                raw = resp.content
            cache.put("kev", "catalogue", raw)
        doc = json.loads(raw)
        added = {v["cveID"]: date.fromisoformat(v["dateAdded"]) for v in doc["vulnerabilities"]}
        return cls(added, str(doc.get("dateReleased", "")))
