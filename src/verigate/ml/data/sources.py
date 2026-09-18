"""``data/sources.yaml`` model and the OpenWrt manifest fetcher (P5-02)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

import httpx
import yaml

from verigate.common.logging import get_logger

log = get_logger(__name__)

_MANIFEST_RE = re.compile(r'href="([^"]+\.manifest)"')


@dataclass(frozen=True)
class OpenWrtSources:
    """The ``openwrt`` section of ``sources.yaml``."""

    base_url: str
    releases: tuple[str, ...]
    targets: tuple[str, ...]


@dataclass(frozen=True)
class RawManifest:
    """One fetched manifest: where it came from and when upstream published it."""

    release: str
    target: str
    filename: str
    path: Path
    released_at: str  # ISO date from the server's Last-Modified header


def load_sources(path: Path) -> OpenWrtSources:
    """Parse ``sources.yaml``."""
    doc = yaml.safe_load(path.read_text())
    ow = doc["openwrt"]
    return OpenWrtSources(
        base_url=str(ow["base_url"]).rstrip("/"),
        releases=tuple(str(r) for r in ow["releases"]),
        targets=tuple(str(t) for t in ow["targets"]),
    )


def _slug(release: str, target: str) -> str:
    return f"openwrt-{release}-{target.replace('/', '-')}"


def fetch_manifests(
    sources: OpenWrtSources, raw_dir: Path, client: httpx.Client | None = None
) -> list[RawManifest]:
    """Download every (release, target) manifest that exists; idempotent (skips cached files).

    Writes ``<raw_dir>/openwrt/<slug>.manifest`` plus ``<slug>.json`` with the release date, and
    returns every manifest present afterwards (fetched now or earlier).
    """
    out_dir = raw_dir / "openwrt"
    out_dir.mkdir(parents=True, exist_ok=True)
    http = client or httpx.Client(timeout=60, follow_redirects=True)
    found: list[RawManifest] = []
    for release in sources.releases:
        for target in sources.targets:
            slug = _slug(release, target)
            meta_path = out_dir / f"{slug}.json"
            data_path = out_dir / f"{slug}.manifest"
            if meta_path.is_file() and data_path.is_file():
                meta = json.loads(meta_path.read_text())
                found.append(
                    RawManifest(release, target, meta["filename"], data_path, meta["released_at"])
                )
                continue
            listing = http.get(f"{sources.base_url}/{release}/targets/{target}/")
            if listing.status_code == 404:
                continue
            listing.raise_for_status()
            names = sorted(set(_MANIFEST_RE.findall(listing.text)))
            if not names:
                continue
            filename = names[0]
            resp = http.get(f"{sources.base_url}/{release}/targets/{target}/{filename}")
            resp.raise_for_status()
            modified = resp.headers.get("last-modified")
            released_at = (
                parsedate_to_datetime(modified).astimezone(UTC).date().isoformat()
                if modified
                else datetime.now(UTC).date().isoformat()
            )
            data_path.write_bytes(resp.content)
            meta_path.write_text(
                json.dumps(
                    {
                        "release": release,
                        "target": target,
                        "filename": filename,
                        "released_at": released_at,
                    }
                )
                + "\n"
            )
            log.info(
                "data.fetched", release=release, target=target, packages=len(resp.text.splitlines())
            )
            found.append(RawManifest(release, target, filename, data_path, released_at))
    return found
