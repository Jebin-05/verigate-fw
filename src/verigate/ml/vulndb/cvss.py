"""CVSS v3.x base-score calculator (pure) for the vector strings OSV records carry."""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 "Roundup": smallest number, to one decimal, ≥ value (integer-safe)."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10


def cvss3_base_score(vector: str) -> float | None:
    """Base score 0.0–10.0 of a ``CVSS:3.x/…`` vector, or ``None`` if it is not one."""
    if not vector.startswith("CVSS:3"):
        return None
    try:
        parts = dict(item.split(":", 1) for item in vector.split("/")[1:])
        scope_changed = parts["S"] == "C"
        iss = 1 - (1 - _CIA[parts["C"]]) * (1 - _CIA[parts["I"]]) * (1 - _CIA[parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
        exploitability = 8.22 * _AV[parts["AV"]] * _AC[parts["AC"]] * pr * _UI[parts["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))
