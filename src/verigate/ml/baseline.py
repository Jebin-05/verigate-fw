"""Deterministic CVSS/EPSS/KEV baseline scorer (P5-05), the comparison point for the ML model.

Severity-weighted EPSS composition with a KEV floor — our reading of the SBOM-triage practice in
arXiv 2601.01308 and FIRST's EPSS guidance ("probability that at least one vulnerability is
exploited"):

    p_i     = epss_i · (cvss_i / 10)            (cvss unknown → 0.5; epss unknown → 0)
    score   = 1 − Π_i (1 − p_i)                 over the SBOM's unique CVEs
    score   = max(score, 0.9)   if any CVE is in KEV

Returned in basis points so it drops straight into the policy engine.
"""

from __future__ import annotations

from collections.abc import Iterable

from verigate.ml.features.sbom_features import VulnRecord

KEV_FLOOR = 0.9


def baseline_score(records: Iterable[VulnRecord]) -> float:
    """Risk in [0, 1] for a set of CVE records (duplicates by id are counted once)."""
    unique: dict[str, VulnRecord] = {}
    for r in records:
        unique.setdefault(r.cve, r)
    survive = 1.0
    any_kev = False
    for r in unique.values():
        severity = (r.cvss / 10.0) if r.cvss is not None else 0.5
        p = (r.epss or 0.0) * severity
        survive *= 1.0 - p
        any_kev |= r.kev
    score = 1.0 - survive
    return max(score, KEV_FLOOR) if any_kev else score


def baseline_bp(records: Iterable[VulnRecord]) -> int:
    """:func:`baseline_score` in basis points (0–10 000)."""
    return round(baseline_score(records) * 10_000)
