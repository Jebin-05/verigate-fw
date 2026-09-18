"""P7-01 latency_stage2: the cost of the AI gate on top of Stage 1.

In-process against the live stack with the configured ONNX models:

* ``sbom_cold_ms`` / ``sbom_warm_ms`` — SBOM features (vulnerability lookups from the local cache)
  + ONNX inference + SHAP top-3, with the per-SBOM cache cleared / kept;
* ``img_cold_ms`` / ``img_warm_ms``   — image features (entropy, ELF parsing, deltas vs the
  previous release) + ONNX + SHAP, likewise;
* ``verify_warm_ms``                  — the whole gate (Stage 1 + Stage 2 + policy + signing)
  with bundle and scores cached, i.e. what a device poll costs once a release has been seen;
* ``http_device_verify_ms``           — the same through the running gateway's HTTP API
  (``POST /verify/{id}?device_id=``), if a gateway is reachable;
* ``llm_ms``                          — one explainer call (Ollama) per repetition, sequential,
  only when ``llm.repetitions > 0`` and Ollama answers. Ollama keeps a prompt cache, so the
  first call per release is the cold number; both are recorded.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from pathlib import Path
from typing import Any

import httpx
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
from verigate.common.ipfs import LocalCidBackend
from verigate.gateway.stage2.explain import Explainer, ExplainInput, sbom_diff
from verigate.gateway.stage2.scores import Stage2Scorer


async def _run(config: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    reps = int(config.get("repetitions", 20))
    warmup = int(config.get("warmup", 2))
    settings = eval_settings(batch_max_size=100_000, batch_max_wait_s=10_000)
    if not settings.sbom_model or not settings.image_model:
        raise SystemExit("latency_stage2 needs SBOM_MODEL and IMAGE_MODEL configured")
    ctx = AttackContext.from_settings(settings)
    did, rids = publish_fixtures(ctx, "eval-lat2")
    service = await in_process_gateway(settings)
    scorer = service.scorer
    assert isinstance(scorer, Stage2Scorer) and scorer.sbom and scorer.image  # noqa: S101
    view = device_view(0)
    gateway_url = ctx.gateway_url
    http_ok = False
    http_device = ""
    with contextlib.suppress(httpx.HTTPError, ValueError):
        http_ok = httpx.get(f"{gateway_url}/health", timeout=5).json().get("status") == "ok"
    if http_ok:
        http_device = ctx.target_device(device_view(0).installed_version, name="eval-http-device")
        for rid_hex in rids.values():  # make sure the running gateway knows the releases
            httpx.get(f"{gateway_url}/releases", params={"refresh": "true"}, timeout=60)
            httpx.post(
                f"{gateway_url}/verify/{rid_hex}", params={"device_id": http_device}, timeout=300
            )

    raw: list[dict[str, Any]] = []
    for rep in range(warmup + reps):
        for version in FIXTURE_VERSIONS:
            rid = bytes.fromhex(rids[version][2:])
            bundle = await service.bundle(rid)
            assert bundle.firmware is not None and bundle.sbom is not None  # noqa: S101
            previous = await service.previous_firmware(bundle)
            scorer.sbom._cache.clear()  # noqa: SLF001 — cold
            with stopwatch() as sbom_cold:
                scorer.sbom.score(bundle.sbom)
            with stopwatch() as sbom_warm:
                scorer.sbom.score(bundle.sbom)
            scorer.image._cache.clear()  # noqa: SLF001
            with stopwatch() as img_cold:
                scorer.image.score(bundle.firmware, previous)
            with stopwatch() as img_warm:
                scorer.image.score(bundle.firmware, previous)
            with stopwatch() as verify_warm:
                result = await service.verify(rid, view)
            row: dict[str, Any] = {
                "rep": rep - warmup,
                "warmup": rep < warmup,
                "release": version,
                "verdict": result.verdict.value,
                "R": result.r_bp,
                "sbom_cold_ms": round(sbom_cold["ms"], 3),
                "sbom_warm_ms": round(sbom_warm["ms"], 3),
                "img_cold_ms": round(img_cold["ms"], 3),
                "img_warm_ms": round(img_warm["ms"], 3),
                "verify_warm_ms": round(verify_warm["ms"], 3),
                "http_device_verify_ms": None,
            }
            if http_ok:
                with contextlib.suppress(httpx.HTTPError):
                    with stopwatch() as http:
                        httpx.post(
                            f"{gateway_url}/verify/{rids[version]}",
                            params={"device_id": http_device},
                            timeout=300,
                        ).raise_for_status()
                    row["http_device_verify_ms"] = round(http["ms"], 3)
            raw.append(row)

    llm_cfg = config.get("llm") or {}
    llm_rows: list[dict[str, Any]] = []
    llm_reps = int(llm_cfg.get("repetitions", 0))
    if llm_reps:
        base = eval_settings()  # the .env values for OLLAMA_URL / LLM_MODEL / LLM_TIMEOUT_S
        explainer = Explainer(
            base.ollama_url,
            base.llm_model,
            LocalCidBackend(settings.state_dir / "ipfs-eval"),
            timeout_s=float(llm_cfg.get("timeout_s", base.llm_timeout_s)),
            retries=0,
        )
        for i in range(llm_reps):
            version = FIXTURE_VERSIONS[i % len(FIXTURE_VERSIONS)]
            rid = bytes.fromhex(rids[version][2:])
            bundle = await service.bundle(rid)
            assert bundle.sbom is not None  # noqa: S101
            scores = await asyncio.to_thread(
                scorer.score,
                bundle.firmware or b"",
                bundle.sbom,
                await service.previous_firmware(bundle),
            )
            inp = ExplainInput(
                release_id=f"{rids[version]}-{i}",  # defeat the explainer's per-release cache
                version=version,
                device_model="demo-device",
                diff=sbom_diff(bundle.sbom, await service.previous_sbom(bundle)),
                r_sbom_bp=scores.r_sbom_bp,
                r_img_bp=scores.r_img_bp,
                verdict="DEFER",
                top_sbom=scores.top("sbom"),
                top_img=scores.top("img"),
                expected_exploited=scores.expected_exploited,
                cves=scores.cves,
            )
            start = time.perf_counter()
            out = await asyncio.to_thread(explainer.explain, inp)
            llm_rows.append(
                {
                    "rep": i,
                    "release": version,
                    "llm_ms": round((time.perf_counter() - start) * 1000, 1),
                    "ok": out is not None,
                    "action": out.rationale.recommended_action if out else None,
                    "model": base.llm_model,
                }
            )
    write_raw(out_dir, raw)
    if llm_rows:
        import csv  # noqa: PLC0415

        with (out_dir / "raw_llm.csv").open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(llm_rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(llm_rows)
    kept = [r for r in raw if not r["warmup"]]
    metrics = ["sbom_cold_ms", "sbom_warm_ms", "img_cold_ms", "img_warm_ms", "verify_warm_ms"]
    if http_ok:
        metrics.append("http_device_verify_ms")
    summary: dict[str, Any] = {
        "experiment": "latency_stage2",
        "repetitions": reps,
        "warmup_discarded": warmup,
        "publisher": did,
        "releases": rids,
        "http_gateway": gateway_url if http_ok else None,
        "overall": {m: median_iqr([r[m] for r in kept if r[m] is not None]) for m in metrics},
        "per_release": {
            v: {
                m: median_iqr([r[m] for r in kept if r["release"] == v and r[m] is not None])
                for m in metrics
            }
            for v in FIXTURE_VERSIONS
        },
        "scores": {v: next(r["R"] for r in kept if r["release"] == v) for v in FIXTURE_VERSIONS},
    }
    if llm_rows:
        ok_rows = [r for r in llm_rows if r["ok"]]
        summary["llm"] = {
            "model": llm_rows[0]["model"],
            "calls": len(llm_rows),
            "succeeded": len(ok_rows),
            "llm_ms": median_iqr([r["llm_ms"] for r in ok_rows]) if ok_rows else None,
            "first_call_ms": llm_rows[0]["llm_ms"],
            "note": "sequential calls on the CPU; Ollama's prompt cache makes later calls on a "
            "release cheaper than the first",
        }
    write_summary(out_dir, summary)
    return {"stack": stack_info(settings, ctx), "state_dir": str(settings.state_dir)}


def run(config: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Entry point for ``run.py``."""
    return asyncio.run(_run(config, out_dir))
