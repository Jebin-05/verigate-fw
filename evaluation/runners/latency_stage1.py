"""P7-01 latency_stage1: how long the deterministic gate takes without any model.

In-process against the live hardhat + IPFS stack (no HTTP overhead, no explainer, Stage 2 replaced
by the ``NullScorer``) so that the numbers isolate Stage 1:

* ``checks_ms``      — the eight pure checks (``run_stage1``) on an already fetched bundle;
* ``verify_warm_ms`` — the full ``verify()`` path with the bundle cached (chain reads for model
  status + policy, checks, record signing, batch queueing);
* ``verify_cold_ms`` — the same with the bundle evicted first (manifest, firmware and SBOM
  fetched from IPFS, release + publisher records read from the chain).

The warm-up repetition is discarded; ≥ 5 repetitions per release (Manual §12).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from common import median_iqr, write_raw, write_summary
from live import (
    FIXTURE_VERSIONS,
    device_view,
    eval_settings,
    in_process_gateway,
    publish_fixtures,
    stack_info,
    stopwatch,
)

from verigate.attacks.common import AttackContext
from verigate.gateway.stage1.inputs import Stage1Input
from verigate.gateway.stage1.runner import run_stage1
from verigate.gateway.stage2.scores import NullScorer


async def _run(config: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    reps = int(config.get("repetitions", 30))
    warmup = int(config.get("warmup", 3))
    settings = eval_settings(batch_max_size=100_000, batch_max_wait_s=10_000)
    ctx = AttackContext.from_settings(settings)
    did, rids = publish_fixtures(ctx, "eval-lat1")
    service = await in_process_gateway(settings)
    service.scorer = NullScorer()
    view = device_view(0)

    raw: list[dict[str, Any]] = []
    for rep in range(warmup + reps):
        for version in FIXTURE_VERSIONS:
            rid = bytes.fromhex(rids[version][2:])
            service._bundles.pop(rid, None)  # noqa: SLF001 — evict for the cold measurement
            with stopwatch() as cold:
                result = await service.verify(rid, view)
            with stopwatch() as warm:
                await service.verify(rid, view)
            bundle = await service.bundle(rid)
            models = [
                await asyncio.to_thread(service.chain.get_model, h) for h in service.model_hashes()
            ]
            inp = Stage1Input(
                manifest=bundle.manifest,
                firmware=bundle.firmware,
                sbom=bundle.sbom,
                release=bundle.release,
                publisher=bundle.publisher,
                device=view,
                models=tuple(models),
                now=service.now(),
            )
            with stopwatch() as checks:
                stage1 = run_stage1(inp, rids[version])
            raw.append(
                {
                    "rep": rep - warmup,
                    "warmup": rep < warmup,
                    "release": version,
                    "verdict": result.verdict.value,
                    "stage1_ok": stage1.ok,
                    "firmware_bytes": len(bundle.firmware or b""),
                    "checks_ms": round(checks["ms"], 3),
                    "verify_warm_ms": round(warm["ms"], 3),
                    "verify_cold_ms": round(cold["ms"], 3),
                }
            )
    write_raw(out_dir, raw)
    kept = [r for r in raw if not r["warmup"]]
    metrics = ("checks_ms", "verify_warm_ms", "verify_cold_ms")
    summary = {
        "experiment": "latency_stage1",
        "repetitions": reps,
        "warmup_discarded": warmup,
        "publisher": did,
        "releases": rids,
        "overall": {m: median_iqr([r[m] for r in kept]) for m in metrics},
        "per_release": {
            v: {m: median_iqr([r[m] for r in kept if r["release"] == v]) for m in metrics}
            for v in FIXTURE_VERSIONS
        },
        "verdicts": sorted({r["verdict"] for r in kept}),
    }
    write_summary(out_dir, summary)
    return {"stack": stack_info(settings, ctx), "state_dir": str(settings.state_dir)}


def run(config: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Entry point for ``run.py``."""
    return asyncio.run(_run(config, out_dir))
