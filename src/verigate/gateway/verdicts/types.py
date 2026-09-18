"""The three outcomes of the gate (Guide §7). Stable strings: they go on the wire and on-chain."""

from __future__ import annotations

from enum import StrEnum


class Verdict(StrEnum):
    """APPROVE installs, REJECT blocks, DEFER holds for retry or human review."""

    APPROVE = "APPROVE"
    REJECT = "REJECT"
    DEFER = "DEFER"
