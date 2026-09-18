"""OSV / EPSS / KEV clients against a mock transport; disk cache; offline mode."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, date, datetime
from pathlib import Path

import httpx
import pytest

from verigate.ml.data.sbom import Component
from verigate.ml.vulndb.cache import DiskCache, OfflineMissError
from verigate.ml.vulndb.epss import EpssSnapshot
from verigate.ml.vulndb.kev import KevCatalogue
from verigate.ml.vulndb.osv import OsvClient, VulnInfo

AFFECTS = {
    "affected": [{"package": {"name": "openssl", "ecosystem": "OSS-Fuzz"}, "versions": ["3.0.1"]}]
}
OSV_RECORDS = {
    "openssl@3.0.1": [
        {"id": "ALPINE-CVE-2022-0778", "aliases": ["CVE-2022-0778"], **AFFECTS},
        {"id": "CVE-2022-0778", "aliases": ["ALPINE-CVE-2022-0778"], **AFFECTS},
        {"id": "GHSA-xxxx", "aliases": [], **AFFECTS},  # no CVE → dropped
        {"id": "DEBIAN-CVE-2022-1292", **AFFECTS},
        {
            "id": "DEBIAN-CVE-1999-0001",
            "affected": [
                {
                    "package": {"name": "openssl", "ecosystem": "Debian:12"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1:0.9.8-1"}],
                        }
                    ],
                }
            ],
        },
    ],
}
KEV_URL = "https://kev.test/known_exploited_vulnerabilities.json"
V3_DOS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
calls: list[str] = []


def handler(request: httpx.Request) -> httpx.Response:
    calls.append(f"{request.method} {request.url.path}")
    if request.url.path.endswith("/query"):
        body = json.loads(request.content)
        key = f"{body['package']['name']}@{body['version']}"
        if "page_token" in body:
            return httpx.Response(200, json={"vulns": [{"id": "CVE-2000-0002", **AFFECTS}]})
        if key not in OSV_RECORDS:
            return httpx.Response(200, json={})
        return httpx.Response(200, json={"vulns": OSV_RECORDS[key], "next_page_token": "t"})
    if "/vulns/CVE-2022-0778" in request.url.path:
        return httpx.Response(
            200,
            json={
                "id": "CVE-2022-0778",
                "published": "2022-03-15T17:05:20.382Z",
                "severity": [
                    {"type": "CVSS_V2", "score": "x"},
                    {"type": "CVSS_V3", "score": V3_DOS},
                ],
            },
        )
    if "/vulns/" in request.url.path:
        return httpx.Response(404, json={})
    if request.url.path.startswith("/epss_scores-"):
        csv = (
            "#model_version:v2025.03.14,score_date:2025-09-18T12:55:00Z\n"
            "cve,epss,percentile\nCVE-2022-0778,0.94,0.99\n"
        )
        return httpx.Response(200, content=gzip.compress(csv.encode()))
    if request.url.path.endswith("known_exploited_vulnerabilities.json"):
        payload = {
            "dateReleased": "2026-09-16",
            "vulnerabilities": [{"cveID": "CVE-2022-1292", "dateAdded": "2022-05-15"}],
        }
        return httpx.Response(200, json=payload)
    return httpx.Response(500)


@pytest.fixture
def transport() -> httpx.MockTransport:
    calls.clear()
    return httpx.MockTransport(handler)


def test_osv_query_filters_dedups_and_caches(
    tmp_path: Path, transport: httpx.MockTransport
) -> None:
    cache = DiskCache(tmp_path)
    osv = OsvClient("https://osv.test/v1", cache, transport=transport)
    openssl = Component("libopenssl3", "3.0.1-1")
    result = osv.cves_for_many([openssl, Component("nothing", "0"), openssl])
    # the Debian epoch range (fixed 1:0.9.8) must not match 3.0.1; the paginated CVE-2000-0002 does
    assert result[openssl] == frozenset({"CVE-2022-0778", "CVE-2022-1292", "CVE-2000-0002"})
    assert result[Component("nothing", "0")] == frozenset()
    assert calls.count("POST /v1/query") == 4  # libopenssl3 (1 page) + openssl (2 pages) + nothing
    offline = OsvClient(
        "https://osv.test/v1", DiskCache(tmp_path, offline=True), transport=transport
    )
    assert offline.cves_for(openssl) == result[openssl]
    assert calls.count("POST /v1/query") == 4  # served from cache
    with pytest.raises(OfflineMissError):
        offline.cves_for(Component("curl", "7.80.0-1"))
    assert osv.cves_for(Component("kernel", "5.15.1-1-abc")) == frozenset()


def test_osv_vuln_details(tmp_path: Path, transport: httpx.MockTransport) -> None:
    cache = DiskCache(tmp_path)
    osv = OsvClient("https://osv.test/v1", cache, transport=transport)
    info = osv.vuln("CVE-2022-0778")
    assert info == VulnInfo(
        "CVE-2022-0778", 7.5, datetime(2022, 3, 15, 17, 5, 20, 382000, tzinfo=UTC)
    )
    assert osv.vuln("CVE-2022-0778") == info and len(calls) == 1
    assert osv.vuln("CVE-1999-9999") == VulnInfo("CVE-1999-9999", None, None)
    assert VulnInfo.from_json(info.to_json()) == info
    offline = OsvClient(
        "https://osv.test/v1", DiskCache(tmp_path, offline=True), transport=transport
    )
    with pytest.raises(OfflineMissError):
        offline.vuln("CVE-2020-1")


def test_epss_and_kev(tmp_path: Path, transport: httpx.MockTransport) -> None:
    cache = DiskCache(tmp_path)
    epss = EpssSnapshot.load("https://epss.test", date(2025, 9, 18), cache, transport=transport)
    assert epss.get("CVE-2022-0778") == 0.94 and epss.get("CVE-1-1") is None
    assert epss.model_version == "model_version:v2025.03.14" and epss.date == date(2025, 9, 18)
    kev = KevCatalogue.load(KEV_URL, cache, transport=transport)
    assert kev.is_kev("CVE-2022-1292") and not kev.is_kev("CVE-2022-0778")
    assert kev.is_kev("CVE-2022-1292", date(2022, 5, 15))
    assert not kev.is_kev("CVE-2022-1292", date(2022, 5, 14))
    assert kev.released == "2026-09-16"
    offline = DiskCache(tmp_path, offline=True)
    cached = EpssSnapshot.load("https://epss.test", date(2025, 9, 18), offline, transport=transport)
    assert cached.get("CVE-2022-0778") == 0.94
    assert KevCatalogue.load(KEV_URL, offline, transport=transport).released == "2026-09-16"
    with pytest.raises(OfflineMissError):
        EpssSnapshot.load("https://epss.test", date(2024, 1, 1), offline, transport=transport)
    assert cache.misses >= 2 and offline.hits >= 2
    assert cache.fetched_at("kev", "catalogue") is not None
    assert cache.fetched_at("kev", "nope") is None


def test_recording_cache_exports_touched_entries(tmp_path: Path) -> None:
    from verigate.ml.vulndb.cache import RecordingCache  # noqa: PLC0415

    source = DiskCache(tmp_path / "full")
    source.put("kev", "catalogue", b"{}")
    source.put("epss", "2025-09-18", b"cve,epss\n")
    source.put("osv-record", "GHSA-x", b"{}")
    recording = RecordingCache(tmp_path / "full")
    assert recording.get("kev", "catalogue") == b"{}"
    assert recording.get("epss", "2025-09-18") == b"cve,epss\n"
    assert recording.get("epss", "missing") is None  # touched but absent → skipped on export
    assert recording.export(tmp_path / "demo") == 2
    demo = DiskCache(tmp_path / "demo", offline=True)
    assert demo.get("kev", "catalogue") == b"{}" and demo.fetched_at("kev", "catalogue")
    assert demo.get("osv-record", "GHSA-x") is None  # never touched


def test_unwritable_cache_is_only_a_warning(tmp_path: Path) -> None:
    blocked = tmp_path / "file-not-dir"
    blocked.write_text("x")
    cache = DiskCache(blocked / "cache")
    cache.put("kev", "catalogue", b"{}")  # parent is a file → OSError swallowed
    assert cache.get("kev", "catalogue") is None
