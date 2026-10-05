"""Fail-closed orchestration of the nine checks: first failure stops and names itself."""

from __future__ import annotations

from dataclasses import dataclass, field

from verigate.common.logging import get_logger
from verigate.gateway.stage1.checks import CHECKS, DEFER_CHECKS, CheckResult
from verigate.gateway.stage1.inputs import Stage1Input
from verigate.gateway.verdicts.types import Verdict

log = get_logger(__name__)


@dataclass(frozen=True)
class Stage1Result:
    """Outcome of the gate. ``outcome`` is ``None`` when every check passed."""

    ok: bool
    results: tuple[CheckResult, ...] = field(default_factory=tuple)
    failed: str | None = None
    reason: str | None = None
    outcome: Verdict | None = None

    def to_dict(self) -> dict[str, object]:
        """JSON-friendly form for the API and the dashboard."""
        return {
            "ok": self.ok,
            "failed": self.failed,
            "reason": self.reason,
            "outcome": self.outcome.value if self.outcome else None,
            "checks": [{"name": r.name, "ok": r.ok, "reason": r.reason} for r in self.results],
        }


def run_stage1(inp: Stage1Input, release_id: str = "") -> Stage1Result:
    """Apply the checks in order; stop at the first failure (fail closed).

    Pure apart from logging: same inputs → same result. ``expiry`` or ``release_delta`` failing
    yields ``DEFER`` (stale, or a modified trusted image); any other failure yields ``REJECT``.
    """
    results: list[CheckResult] = []
    for check in CHECKS:
        result = check(inp)
        results.append(result)
        log.info(
            "stage1.check",
            check=result.name,
            ok=result.ok,
            reason=result.reason,
            release_id=release_id,
            device_id=inp.device.device_id,
        )
        if not result.ok:
            outcome = Verdict.DEFER if result.name in DEFER_CHECKS else Verdict.REJECT
            log.warning(
                "stage1.failed",
                check=result.name,
                outcome=outcome.value,
                release_id=release_id,
                device_id=inp.device.device_id,
            )
            return Stage1Result(False, tuple(results), result.name, result.reason, outcome)
    log.info("stage1.passed", release_id=release_id, device_id=inp.device.device_id)
    return Stage1Result(True, tuple(results))
