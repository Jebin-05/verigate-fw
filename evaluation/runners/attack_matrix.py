"""P7-01 attack_matrix: every scenario, ``repetitions`` times, against the running gateway.

One row per run: expected, observed, pass, duration. The summary has one row per attack with run
count and pass rate (Manual §12: any row below 100 % goes to the limitations section, not the
bin). ``poisoned-model`` can only run as often as there are revocable image models on the chain
(the shipped primary and its successor → at most two runs per chain lifetime), so it runs last
and its run count is capped; the cap is recorded.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import httpx
from common import median_iqr, write_raw, write_summary
from live import eval_settings, stack_info

from verigate.attacks.cli import ATTACKS
from verigate.attacks.common import AttackContext
from verigate.common.errors import VerigateError

POISONED = "poisoned-model"
POISONED_MAX_RUNS = 2


def run(config: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Run the matrix."""
    reps = int(config.get("repetitions", 5))
    names = list(config.get("attacks") or ATTACKS)
    settings = eval_settings()
    ctx = AttackContext.from_settings(settings)
    health = httpx.get(f"{ctx.gateway_url}/health", timeout=10).json()
    if health.get("status") != "ok":
        raise SystemExit(f"gateway at {ctx.gateway_url} is not healthy")

    order = [n for n in names if n != POISONED] + ([POISONED] if POISONED in names else [])
    raw: list[dict[str, Any]] = []
    for name in order:
        runs = min(reps, POISONED_MAX_RUNS) if name == POISONED else reps
        for rep in range(runs):
            start = time.perf_counter()
            error: str | None = None
            try:
                report = ATTACKS[name].run(ctx)
                row = report.to_dict()
            except (VerigateError, httpx.HTTPError) as exc:
                error = str(exc)
                row = {"expected": ATTACKS[name].EXPECTED, "observed": None, "passed": False}
            raw.append(
                {
                    "attack": name,
                    "rep": rep,
                    "expected": row["expected"],
                    "observed": row["observed"],
                    "check": row.get("check"),
                    "passed": bool(row["passed"]),
                    "duration_s": round(time.perf_counter() - start, 2),
                    "release_id": row.get("release_id"),
                    "R": (row.get("details") or {}).get("R"),
                    "error": error,
                }
            )
    write_raw(out_dir, raw)
    matrix = {}
    for name in order:
        rows = [r for r in raw if r["attack"] == name]
        matrix[name] = {
            "expected": rows[0]["expected"],
            "observed": sorted({str(r["observed"]) for r in rows}),
            "runs": len(rows),
            "passes": sum(r["passed"] for r in rows),
            "pass_rate": round(sum(r["passed"] for r in rows) / len(rows), 4),
            "duration_s": median_iqr([r["duration_s"] for r in rows]),
        }
    summary = {
        "experiment": "attack_matrix",
        "repetitions": reps,
        "gateway": ctx.gateway_url,
        "gateway_health": {k: health.get(k) for k in ("chainId", "block", "ipfsBackend")},
        "matrix": matrix,
        "all_pass": all(m["pass_rate"] == 1.0 for m in matrix.values()),
        "notes": [
            f"{POISONED} capped at {POISONED_MAX_RUNS} runs per chain lifetime (one revocable "
            "image model plus its successor)",
            "the gateway's explainer setting is whatever the running gateway has; attack "
            "durations include Stage-2 inference but no LLM wait (device-level verifications)",
        ],
    }
    write_summary(out_dir, summary)
    return {"stack": stack_info(settings, ctx)}
