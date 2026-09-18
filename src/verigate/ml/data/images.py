"""Benign ELF corpus from OpenWrt package feeds (P6-03 data): fetch .ipk, extract the ELF."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml

from verigate.common.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class ImageSources:
    """The ``images`` section of ``sources.yaml``."""

    base_url: str
    arch: str
    feed: str
    releases: tuple[str, ...]
    packages: tuple[str, ...]


@dataclass(frozen=True)
class ElfSample:
    """One extracted binary."""

    release: str
    package: str
    version: str
    path: Path
    sha256: str
    size: int


def load_image_sources(path: Path) -> ImageSources:
    """Parse the ``images`` section (``base_url`` comes from the ``openwrt`` section)."""
    doc = yaml.safe_load(path.read_text())
    img = doc["images"]
    return ImageSources(
        base_url=str(doc["openwrt"]["base_url"]).rstrip("/"),
        arch=str(img["arch"]),
        feed=str(img["feed"]),
        releases=tuple(str(r) for r in img["releases"]),
        packages=tuple(str(p) for p in img["packages"]),
    )


def parse_packages_index(text: str) -> dict[str, tuple[str, str]]:
    """``Packages`` index → ``{package: (version, filename)}``."""
    out: dict[str, tuple[str, str]] = {}
    current: dict[str, str] = {}
    for line in text.splitlines() + [""]:
        if not line.strip():
            if "Package" in current and "Filename" in current:
                out[current["Package"]] = (current.get("Version", ""), current["Filename"])
            current = {}
        elif ":" in line:
            key, value = line.split(":", 1)
            current[key.strip()] = value.strip()
    return out


def largest_elf(ipk_bytes: bytes) -> bytes | None:
    """The biggest ELF file inside an .ipk (``data.tar.gz`` inside a gzip tar), or ``None``."""
    with tarfile.open(fileobj=io.BytesIO(ipk_bytes), mode="r:gz") as outer:
        member = next((m for m in outer.getmembers() if m.name.lstrip("./") == "data.tar.gz"), None)
        if member is None:
            return None
        inner_bytes = outer.extractfile(member)
        if inner_bytes is None:
            return None
        data = inner_bytes.read()
    best: bytes | None = None
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as inner:
        for m in inner.getmembers():
            if not m.isfile():
                continue
            fh = inner.extractfile(m)
            if fh is None:
                continue
            blob = fh.read()
            if blob[:4] == b"\x7fELF" and (best is None or len(blob) > len(best)):
                best = blob
    return best


def fetch_elf_corpus(
    sources: ImageSources, raw_dir: Path, client: httpx.Client | None = None
) -> list[ElfSample]:
    """Download every (release, package) binary that exists; idempotent (cached on disk)."""
    http = client or httpx.Client(timeout=120, follow_redirects=True)
    out_dir = raw_dir / "elf"
    samples: list[ElfSample] = []
    for release in sources.releases:
        index_url = f"{sources.base_url}/{release}/packages/{sources.arch}/{sources.feed}/Packages"
        index_path = out_dir / release / "Packages"
        if index_path.is_file():
            index_text = index_path.read_text()
        else:
            resp = http.get(index_url)
            if resp.status_code == 404:
                log.warning("images.no_feed", release=release)
                continue
            resp.raise_for_status()
            index_path.parent.mkdir(parents=True, exist_ok=True)
            index_path.write_text(resp.text)
            index_text = resp.text
        index = parse_packages_index(index_text)
        for package in sources.packages:
            meta_path = out_dir / release / f"{package}.json"
            elf_path = out_dir / release / f"{package}.elf"
            if meta_path.is_file() and elf_path.is_file():
                meta = json.loads(meta_path.read_text())
                samples.append(
                    ElfSample(
                        release, package, meta["version"], elf_path, meta["sha256"], meta["size"]
                    )
                )
                continue
            if package not in index:
                continue
            version, filename = index[package]
            resp = http.get(
                f"{sources.base_url}/{release}/packages/{sources.arch}/{sources.feed}/{filename}"
            )
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            elf = largest_elf(resp.content)
            if elf is None:
                continue
            digest = hashlib.sha256(elf).hexdigest()
            elf_path.write_bytes(elf)
            meta = {
                "release": release,
                "package": package,
                "version": version,
                "ipk": filename,
                "ipk_sha256": hashlib.sha256(resp.content).hexdigest(),
                "sha256": digest,
                "size": len(elf),
            }
            meta_path.write_text(json.dumps(meta) + "\n")
            log.info("images.fetched", release=release, package=package, size=len(elf))
            samples.append(ElfSample(release, package, version, elf_path, digest, len(elf)))
    return samples


def write_images_index(
    samples: list[ElfSample], processed_dir: Path, sources: ImageSources
) -> list[dict[str, Any]]:
    """``processed/images_index.json``: each sample plus its predecessor (previous release)."""
    order = {r: i for i, r in enumerate(sources.releases)}
    by_key = {(s.package, s.release): s for s in samples}
    rows: list[dict[str, Any]] = []
    for s in sorted(samples, key=lambda x: (order[x.release], x.package)):
        previous = None
        for r in reversed(sources.releases[: order[s.release]]):
            if (s.package, r) in by_key:
                previous = str(by_key[(s.package, r)].path)
                break
        rows.append(
            {
                "release": s.release,
                "package": s.package,
                "version": s.version,
                "path": str(s.path),
                "sha256": s.sha256,
                "size": s.size,
                "previous": previous,
            }
        )
    processed_dir.mkdir(parents=True, exist_ok=True)
    (processed_dir / "images_index.json").write_text(json.dumps(rows, indent=1) + "\n")
    return rows
