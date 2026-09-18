"""Generate the demo-device release fixtures under ``tests/fixtures/releases/<version>/``.

Each fixture release is a **real** OpenWrt build (GPL-2.0, see the README next to the fixtures):

* ``firmware.bin`` — the ``busybox`` ELF executable (MIPS 24Kc, stripped) extracted from the
  pinned ``.ipk`` of that OpenWrt release; the .ipk SHA-256 is verified against ``IPK_SHA256``;
* ``sbom.json`` — CycloneDX 1.5 derived from that release's ``ath79/generic`` package manifest,
  the same conversion the training corpus uses;
* ``changelog.md`` — a short note.

Real binaries (rather than synthetic bytes) keep Stage-2 inputs in the same distribution as the
image-anomaly training corpus. Re-running is deterministic given the pinned hashes;
``MANIFEST.sha256`` in the directory records every output.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx

from verigate.ml.data.images import largest_elf, parse_packages_index
from verigate.ml.data.sbom import cyclonedx, parse_manifest

ROOT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "releases"
BASE = "https://downloads.openwrt.org/releases"
ARCH, FEED, TARGET = "mips_24kc", "base", "ath79/generic"

RELEASES: dict[str, dict[str, str]] = {
    "1.0.0": {
        "openwrt": "22.03.7",
        "changelog": "Initial demo-device release (OpenWrt 22.03.7 userland).",
    },
    "1.1.0": {
        "openwrt": "23.05.3",
        "changelog": "Maintenance release: OpenWrt 23.05.3 userland and security fixes.",
    },
    "2.0.0": {
        "openwrt": "24.10.0",
        "changelog": "Major release: OpenWrt 24.10.0 userland (new kernel branch, new libraries).",
    },
}
# The "vulnerable-but-genuine" attack fixture: an honest build on an end-of-life base
# (OpenWrt 19.07, last release 2022-04); same derivation, kept out of the version lineage.
LEGACY: dict[str, str] = {"dir": "legacy-19.07.10", "openwrt": "19.07.10", "version": "0.19.7"}
# SHA-256 of the busybox .ipk per OpenWrt release — filled by the first run, verified afterwards.
IPK_SHA256: dict[str, str] = {
    "22.03.7": "0ad4e2da05cace114dbd4fe62c5ee1f9a2ea1c4e66f445c7331308d976bcefa2",
    "23.05.3": "cbc32f7ee614e457a4a543ab628404f8833f671a0dd7b7bbecd09e2aeca3984b",
    "24.10.0": "5df3a0a918072bb0a2a944e0ee477bc1fdd922b2af3e816d8d069a35a3e4bf39",
    "19.07.10": "0a235651ad9be5934d446c82e1bb7061b80432d9309b03d4ab199d1aec88ccb2",
}


def fetch(client: httpx.Client, url: str) -> bytes:
    """GET with a hard failure on any non-200."""
    resp = client.get(url)
    resp.raise_for_status()
    return resp.content


def busybox_elf(client: httpx.Client, release: str) -> bytes:
    """Download the pinned busybox .ipk for ``release`` and extract its ELF."""
    index = parse_packages_index(
        fetch(client, f"{BASE}/{release}/packages/{ARCH}/{FEED}/Packages").decode()
    )
    _version, filename = index["busybox"]
    ipk = fetch(client, f"{BASE}/{release}/packages/{ARCH}/{FEED}/{filename}")
    digest = hashlib.sha256(ipk).hexdigest()
    pinned = IPK_SHA256.get(release)
    if pinned is None:
        print(f"pin this in IPK_SHA256: {release!r}: {digest!r}")  # noqa: T201 — one-off helper
    elif pinned != digest:
        raise SystemExit(f"{filename}: sha256 {digest} != pinned {pinned}")
    elf = largest_elf(ipk)
    if elf is None:
        raise SystemExit(f"{filename}: no ELF inside")
    return elf


def manifest_sbom(client: httpx.Client, release: str, version: str) -> str:
    """CycloneDX JSON from the release's target manifest."""
    listing = fetch(client, f"{BASE}/{release}/targets/{TARGET}/").decode()
    name = next(
        part.split('"')[0]
        for part in listing.split('href="')[1:]
        if part.split('"')[0].endswith(".manifest")
    )
    components = parse_manifest(fetch(client, f"{BASE}/{release}/targets/{TARGET}/{name}").decode())
    doc = cyclonedx(
        "demo-device",
        version,
        components,
        {"verigate:openwrt_release": release, "verigate:source": name},
    )
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def main() -> None:
    """Write every release and a MANIFEST.sha256 covering all files."""
    lines: list[str] = []
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        for version, spec in RELEASES.items():
            d = ROOT / f"v{version}"
            d.mkdir(parents=True, exist_ok=True)
            files = {
                "firmware.bin": busybox_elf(client, spec["openwrt"]),
                "sbom.json": manifest_sbom(client, spec["openwrt"], version).encode(),
                "changelog.md": f"# demo-device {version}\n\n{spec['changelog']}\n".encode(),
            }
            for name, data in files.items():
                (d / name).write_bytes(data)
                lines.append(f"{hashlib.sha256(data).hexdigest()}  v{version}/{name}")
        d = ROOT / LEGACY["dir"]
        d.mkdir(parents=True, exist_ok=True)
        legacy = {
            "firmware.bin": busybox_elf(client, LEGACY["openwrt"]),
            "sbom.json": manifest_sbom(client, LEGACY["openwrt"], LEGACY["version"]).encode(),
        }
        for name, data in legacy.items():
            (d / name).write_bytes(data)
            lines.append(f"{hashlib.sha256(data).hexdigest()}  {LEGACY['dir']}/{name}")
    (ROOT / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
