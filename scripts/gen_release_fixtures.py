"""Generate the toy firmware releases under ``tests/fixtures/releases/<version>/``.

Each release is ``firmware.bin`` (a valid ELF32/ARM header followed by ~300 KiB of seeded
pseudo-random bytes and a few printable strings) plus ``sbom.json`` (CycloneDX 1.5 with real
package names/versions so P5 can query OSV for them) and ``changelog.md``. Deterministic: the
same script always produces the same bytes; ``MANIFEST.sha256`` in the directory records them.
Sizes are > 256 KiB on purpose so the chunked-CID path of ``common/ipfs.py`` is exercised.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "releases"
SIZE = 300 * 1024

# ELF32 header for an ARM executable (e_ident, e_type=EXEC, e_machine=ARM(0x28), e_version=1).
ELF32_ARM_HEADER = (
    b"\x7fELF"
    + bytes([1, 1, 1, 0])
    + b"\x00" * 8  # e_ident: class32, LE, version 1, SysV ABI
    + struct.pack("<HHIIIIIHHHHHH", 2, 0x28, 1, 0x8000, 52, 0, 0x5000400, 52, 32, 1, 40, 4, 3)
)

RELEASES: dict[str, dict[str, object]] = {
    "1.0.0": {
        "components": [
            ("openssl", "3.0.1"),
            ("curl", "7.80.0"),
            ("zlib", "1.2.11"),
            ("mbedtls", "2.28.0"),
            ("lwip", "2.1.3"),
            ("freertos-kernel", "10.4.6"),
            ("cjson", "1.7.15"),
        ],
        "changelog": "Initial release of the demo-device firmware.",
        "mutations": [],
    },
    "1.1.0": {
        "components": [
            ("openssl", "3.0.14"),
            ("curl", "7.80.0"),
            ("zlib", "1.3.1"),
            ("mbedtls", "2.28.0"),
            ("lwip", "2.1.3"),
            ("freertos-kernel", "10.4.6"),
            ("cjson", "1.7.15"),
        ],
        "changelog": "Upgrade OpenSSL 3.0.1 -> 3.0.14 and zlib 1.2.11 -> 1.3.1 (security fixes).",
        "mutations": [(0x1000, 0x400), (0x20000, 0x800)],
    },
    "2.0.0": {
        "components": [
            ("openssl", "3.0.14"),
            ("curl", "8.9.1"),
            ("zlib", "1.3.1"),
            ("mbedtls", "3.6.0"),
            ("lwip", "2.2.0"),
            ("freertos-kernel", "11.1.0"),
            ("cjson", "1.7.18"),
        ],
        "changelog": "Major update: new network stack (lwIP 2.2, mbedTLS 3.6), FreeRTOS 11.",
        "mutations": [(0x1000, 0x400), (0x8000, 0x4000), (0x20000, 0x800), (0x30000, 0x2000)],
    },
}


def prng(seed: bytes, n: int) -> bytes:
    """Deterministic bytes: SHA-256 counter mode."""
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


def firmware(version: str, mutations: list[tuple[int, int]]) -> bytes:
    """Base image v1.0.0 with ``mutations`` (offset, length) regions re-seeded per version."""
    body = bytearray(prng(b"verigate-demo-firmware-base", SIZE))
    body[: len(ELF32_ARM_HEADER)] = ELF32_ARM_HEADER
    for i, (offset, length) in enumerate(mutations):
        body[offset : offset + length] = prng(f"mutation-{version}-{i}".encode(), length)
    strings = (
        f"demo-device firmware {version}\0Copyright (c) 2026 VeriGate demo publisher\0"
        "https://example.invalid/demo-device\0OTA slot A/B\0"
    ).encode()
    body[0x400 : 0x400 + len(strings)] = strings
    return bytes(body)


def sbom(version: str, components: list[tuple[str, str]]) -> str:
    """CycloneDX 1.5 JSON with purl identifiers (generic type: real names, no ecosystem claim)."""
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "firmware", "name": "demo-device", "version": version},
            "tools": [{"name": "verigate-fixture-generator", "version": "1"}],
        },
        "components": [
            {"type": "library", "name": name, "version": ver, "purl": f"pkg:generic/{name}@{ver}"}
            for name, ver in components
        ],
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def main() -> None:
    """Write every release and a MANIFEST.sha256 covering all files."""
    manifest_lines: list[str] = []
    for version, spec in RELEASES.items():
        d = ROOT / f"v{version}"
        d.mkdir(parents=True, exist_ok=True)
        files = {
            "firmware.bin": firmware(version, spec["mutations"]),  # type: ignore[arg-type]
            "sbom.json": sbom(version, spec["components"]).encode(),  # type: ignore[arg-type]
            "changelog.md": f"# demo-device {version}\n\n{spec['changelog']}\n".encode(),
        }
        for name, data in files.items():
            (d / name).write_bytes(data)
            manifest_lines.append(f"{hashlib.sha256(data).hexdigest()}  v{version}/{name}")
    (ROOT / "MANIFEST.sha256").write_text("\n".join(manifest_lines) + "\n")


if __name__ == "__main__":
    main()
