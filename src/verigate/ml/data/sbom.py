"""OpenWrt package manifest → CycloneDX 1.5 SBOM, and SBOM → components (P5-02).

A manifest line is ``<name> - <version>``. The resulting SBOM has the same content a ``syft``
scan of the image's root filesystem would list (package name + version), taken from the
authoritative build manifest instead of a binary scan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from verigate.ml.data.sources import RawManifest


@dataclass(frozen=True)
class Component:
    """A (name, version) pair from an SBOM."""

    name: str
    version: str


def parse_manifest(text: str) -> list[Component]:
    """Parse ``name - version`` lines (blank / malformed lines are skipped)."""
    components: list[Component] = []
    for line in text.splitlines():
        if " - " not in line:
            continue
        name, version = line.split(" - ", 1)
        name, version = name.strip(), version.strip()
        if name and version:
            components.append(Component(name, version))
    return components


def cyclonedx(
    name: str, version: str, components: list[Component], properties: dict[str, str]
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 JSON document."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "firmware", "name": name, "version": version},
            "tools": [{"name": "verigate-data-sbom", "version": "1"}],
            "properties": [{"name": k, "value": v} for k, v in sorted(properties.items())],
        },
        "components": [
            {
                "type": "library",
                "name": c.name,
                "version": c.version,
                "purl": f"pkg:generic/{c.name}@{c.version}",
            }
            for c in components
        ],
    }


def components_of(sbom: dict[str, Any]) -> list[Component]:
    """Extract ``(name, version)`` pairs from any CycloneDX JSON (fixtures and corpus alike)."""
    out: list[Component] = []
    for c in sbom.get("components", []):
        name, version = c.get("name"), c.get("version")
        if isinstance(name, str) and isinstance(version, str) and name and version:
            out.append(Component(name, version))
    return out


def write_sboms(manifests: list[RawManifest], processed_dir: Path) -> list[dict[str, Any]]:
    """Write one CycloneDX file per manifest and return the corpus index rows."""
    out_dir = processed_dir / "sboms"
    out_dir.mkdir(parents=True, exist_ok=True)
    index: list[dict[str, Any]] = []
    for m in manifests:
        components = parse_manifest(m.path.read_text())
        slug = m.path.stem
        doc = cyclonedx(
            f"openwrt-{m.target.replace('/', '-')}",
            m.release,
            components,
            {"verigate:release_date": m.released_at, "verigate:source": m.filename},
        )
        path = out_dir / f"{slug}.json"
        path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        index.append(
            {
                "id": slug,
                "release": m.release,
                "target": m.target,
                "released_at": m.released_at,
                "sbom": str(path.relative_to(processed_dir.parent)),
                "components": len(components),
            }
        )
    (processed_dir / "index.json").write_text(json.dumps(index, indent=1) + "\n")
    return index


def write_manifest_sha256(data_dir: Path, out: Path) -> int:
    """Record the SHA-256 of every file under ``data/raw`` and ``data/processed`` (not vulndb)."""
    import hashlib  # noqa: PLC0415

    lines: list[str] = []
    for sub in ("raw", "processed"):
        base = data_dir / sub
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and "vulndb" not in path.parts:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                lines.append(f"{digest}  {path.relative_to(data_dir).as_posix()}")
    out.write_text("\n".join(lines) + ("\n" if lines else ""))
    return len(lines)
