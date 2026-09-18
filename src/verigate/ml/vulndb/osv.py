"""OSV.dev client: (package, version) → CVE ids, and per-vulnerability details (P5-01).

Resolution rule (documented in the model card): a query by package *name* and *version* across
every OSV ecosystem, de-duplicated to CVE identifiers via each record's ``aliases``. Firmware
packages (busybox, openssl, dropbear …) are not tied to one ecosystem, and this catches the
Alpine/Debian/upstream advisories that mention the same CVE.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from verigate.common.logging import get_logger
from verigate.ml.data.sbom import Component
from verigate.ml.vulndb.cache import DiskCache
from verigate.ml.vulndb.cvss import cvss3_base_score
from verigate.ml.vulndb.match import record_affects, upstream_component

log = get_logger(__name__)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class VulnInfo:
    """What the features need to know about one CVE."""

    cve: str
    cvss: float | None
    published: datetime | None

    def to_json(self) -> dict[str, object]:
        """Cache form."""
        return {
            "cve": self.cve,
            "cvss": self.cvss,
            "published": self.published.isoformat() if self.published else None,
        }

    @classmethod
    def from_json(cls, d: dict[str, object]) -> VulnInfo:
        """Inverse of :meth:`to_json`."""
        published = d.get("published")
        return cls(
            str(d["cve"]),
            float(d["cvss"]) if d.get("cvss") is not None else None,  # type: ignore[arg-type]
            datetime.fromisoformat(str(published)) if published else None,
        )


def _to_cve(record: dict[str, Any]) -> str | None:
    aliases = record.get("aliases") or []
    ids = [str(record.get("id", ""))] + [str(a) for a in aliases]
    for candidate in ids:
        if _CVE_RE.match(candidate):
            return candidate
        m = re.search(r"(CVE-\d{4}-\d{4,})", candidate)
        if m:
            return m.group(1)
    return None


class OsvClient:
    """HTTP client with a disk cache; every method is safe to call offline once warmed."""

    def __init__(
        self,
        api_url: str,
        cache: DiskCache,
        timeout: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.cache = cache
        self._http = httpx.Client(timeout=timeout, transport=transport)

    # ------------------------------------------------------------------ queries

    def _query_all_pages(self, name: str, version: str) -> list[dict[str, Any]]:
        vulns: list[dict[str, Any]] = []
        body: dict[str, Any] = {"package": {"name": name}, "version": version}
        while True:
            resp = self._http.post(f"{self.api_url}/query", json=body)
            resp.raise_for_status()
            page = resp.json()
            vulns.extend(page.get("vulns", []))
            token = page.get("next_page_token")
            if not token:
                return vulns
            body["page_token"] = token

    def records_for(self, name: str, version: str) -> list[dict[str, Any]]:
        """Every OSV record OSV itself matches for ``name@version`` (full records, cached by id)."""
        key = f"{name}@{version}"
        cached = self.cache.get("osv-query", key)
        if cached is not None:
            ids = json.loads(cached)
            return [self._record(i) for i in ids]
        self.cache.require_online(f"OSV query {key}")
        records = self._query_all_pages(name, version)
        for record in records:
            self.cache.put("osv-record", str(record["id"]), json.dumps(record).encode())
        self.cache.put("osv-query", key, json.dumps([str(r["id"]) for r in records]).encode())
        log.debug("osv.query", package=key, records=len(records))
        return records

    def _record(self, record_id: str) -> dict[str, Any]:
        cached = self.cache.get("osv-record", record_id)
        if cached is not None:
            loaded: dict[str, Any] = json.loads(cached)
            return loaded
        self.cache.require_online(f"OSV record {record_id}")
        resp = self._http.get(f"{self.api_url}/vulns/{record_id}")
        resp.raise_for_status()
        record: dict[str, Any] = resp.json()
        self.cache.put("osv-record", record_id, json.dumps(record).encode())
        return record

    def cves_for(self, component: Component) -> frozenset[str]:
        """CVE ids that affect the *upstream* version of an OpenWrt/CycloneDX component.

        Name/version mapping and range evaluation are in :mod:`verigate.ml.vulndb.match`.
        """
        mapped = upstream_component(component)
        if mapped is None:
            return frozenset()
        names, version = mapped
        cves: set[str] = set()
        for name in names:
            for record in self.records_for(name, version):
                if record_affects(record, names, version):
                    cve = _to_cve(record)
                    if cve:
                        cves.add(cve)
        return frozenset(cves)

    def cves_for_many(self, components: list[Component]) -> dict[Component, frozenset[str]]:
        """:meth:`cves_for` for many components (each distinct component resolved once)."""
        return {c: self.cves_for(c) for c in dict.fromkeys(components)}

    # ------------------------------------------------------------------ details

    def vuln(self, cve: str) -> VulnInfo:
        """CVSS base score and publication date of ``cve`` (cached)."""
        cached = self.cache.get("osv-vuln", cve)
        if cached is not None:
            return VulnInfo.from_json(json.loads(cached))
        record_bytes = self.cache.get("osv-record", cve)
        if record_bytes is not None:
            record: dict[str, Any] | None = json.loads(record_bytes)
        else:
            self.cache.require_online(f"OSV vuln {cve}")
            resp = self._http.get(f"{self.api_url}/vulns/{cve}")
            record = None if resp.status_code == 404 else resp.json()
            if record is None:
                pass
            else:
                resp.raise_for_status()
                self.cache.put("osv-record", cve, json.dumps(record).encode())
        if record is None:
            info = VulnInfo(cve, None, None)
        else:
            score = None
            for sev in record.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score = cvss3_base_score(str(sev.get("score", "")))
                    if score is not None:
                        break
            published = record.get("published")
            info = VulnInfo(
                cve,
                score,
                datetime.fromisoformat(published.replace("Z", "+00:00")).astimezone(UTC)
                if published
                else None,
            )
        self.cache.put("osv-vuln", cve, json.dumps(info.to_json()).encode())
        return info
