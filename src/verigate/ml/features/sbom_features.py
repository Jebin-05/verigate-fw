"""SBOM risk features (P5-03): pure, deterministic, integer-quantised (so ``featureHash`` is exact).

Inputs are plain data: the components, the vulnerability records already looked up for them
(``VulnRecord``: CVSS, EPSS, KEV membership — all *as of* one date), and a corpus context
(newest known version per package, first-seen date per version). No I/O here; the caller
(``stage2/sbom.py`` or the training script) does the lookups.

Quantisation (units in the model card): CVSS × 10, EPSS × 10 000, ages in days, counts as-is.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date

from verigate.ml.data.sbom import Component

FEATURE_NAMES: tuple[str, ...] = (
    "n_components",
    "n_vulnerable_components",
    "n_cves",
    "max_cvss_x10",
    "mean_cvss_x10",
    "sum_epss_x1e4",
    "max_epss_x1e4",
    "kev_count",
    "n_outdated",
    "mean_dep_age_days",
)
"""Column order of the model input vector; changing it is a new model version (Manual §11)."""


@dataclass(frozen=True)
class VulnRecord:
    """One CVE as seen on the snapshot date."""

    cve: str
    cvss: float | None
    epss: float | None
    kev: bool


@dataclass(frozen=True)
class CorpusContext:
    """What "outdated" and "age" are measured against."""

    as_of: date
    latest_version: Mapping[str, str]  # package name → newest version in the corpus
    first_seen: Mapping[tuple[str, str], date]  # (name, version) → first release date seen


def sbom_features(
    components: Sequence[Component],
    vulns: Mapping[Component, Sequence[VulnRecord]],
    context: CorpusContext,
) -> dict[str, int]:
    """Compute the quantised feature vector (keys in :data:`FEATURE_NAMES` order)."""
    seen: dict[str, VulnRecord] = {}
    vulnerable = 0
    for component in components:
        records = vulns.get(component, ())
        if records:
            vulnerable += 1
        for r in records:
            seen.setdefault(r.cve, r)
    cvss = [r.cvss for r in seen.values() if r.cvss is not None]
    epss = [r.epss for r in seen.values() if r.epss is not None]
    outdated = sum(
        1 for c in components if context.latest_version.get(c.name, c.version) != c.version
    )
    ages = [
        (context.as_of - context.first_seen[(c.name, c.version)]).days
        for c in components
        if (c.name, c.version) in context.first_seen
    ]
    return {
        "n_components": len(components),
        "n_vulnerable_components": vulnerable,
        "n_cves": len(seen),
        "max_cvss_x10": round(max(cvss) * 10) if cvss else 0,
        "mean_cvss_x10": round(sum(cvss) / len(cvss) * 10) if cvss else 0,
        "sum_epss_x1e4": round(sum(epss) * 10_000),
        "max_epss_x1e4": round(max(epss) * 10_000) if epss else 0,
        "kev_count": sum(1 for r in seen.values() if r.kev),
        "n_outdated": outdated,
        "mean_dep_age_days": round(sum(ages) / len(ages)) if ages else 0,
    }


def as_vector(features: Mapping[str, int]) -> list[float]:
    """Feature dict → model input row in :data:`FEATURE_NAMES` order."""
    return [float(features[name]) for name in FEATURE_NAMES]
