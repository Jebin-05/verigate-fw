"""P7-01 revocation_propagation: how fast a revoked model's verdicts are replayed, vs fleet size.

Per repetition and fleet size ``D`` an in-process gateway (real chain, IPFS and ONNX models, no
explainer) verifies one release for ``D`` devices under image-model variant ``P`` and commits the
batch; the admin then revokes ``P`` naming successor ``S``, and the revocation job runs once:

* ``handle_ms``      — from the job noticing the revocation to the last replayed verdict
  (``staleByModel`` read, successor located by hash and loaded, ``D`` re-verifications, new batch
  queued);
* ``per_pair_ms``    — ``handle_ms / pairs``;
* ``propagation_ms`` — ``handle_ms`` plus the job's poll interval (``LISTENER_POLL_S``), the
  worst-case time from the revocation block to the replay being complete.

Variants ``P``/``S`` are byte-distinct copies of the shipped image model (only the ONNX
``doc_string`` differs) so every repetition has fresh, never-revoked registry entries while the
scores stay those of the real model. That trick is confined to this experiment.
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

import onnx
from common import ROOT, median_iqr, write_raw, write_summary
from live import device_view, eval_settings, in_process_gateway, publish_fixtures, stack_info

from verigate.attacks.common import AttackContext
from verigate.gateway.revocation import RevocationJob
from verigate.gateway.store import DeviceRecord


def _variant(src: Path, dst: Path, tag: str) -> str:
    """A byte-distinct copy of ``src`` (doc_string = tag) plus its context; returns the 0x hash."""
    model = onnx.load(str(src))
    model.doc_string = tag
    dst.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(model, str(dst))
    shutil.copy(src.with_suffix(".context.json"), dst.with_suffix(".context.json"))
    return "0x" + hashlib.sha256(dst.read_bytes()).hexdigest()


async def _run(config: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    fleet_sizes = [int(d) for d in config.get("fleet_sizes", [5, 20, 50])]
    reps = int(config.get("repetitions", 5))
    poll_s = float(config.get("poll_s", 2.0))
    base = eval_settings()
    if not base.sbom_model or not base.image_model:
        raise SystemExit("revocation_propagation needs SBOM_MODEL and IMAGE_MODEL configured")
    ctx = AttackContext.from_settings(base)
    did, rids = publish_fixtures(ctx, "eval-revoke")
    rid_hex = rids["2.0.0"]
    sbom_hash = "0x" + hashlib.sha256((ROOT / "models" / base.sbom_model).read_bytes()).hexdigest()
    src = ROOT / "models" / base.image_model

    raw: list[dict[str, Any]] = []
    for rep in range(reps):
        for fleet in fleet_sizes:
            models_dir = Path(tempfile.mkdtemp(prefix="verigate-eval-models-"))
            shutil.copy(ROOT / "models" / base.sbom_model, models_dir / base.sbom_model)
            shutil.copy(
                (ROOT / "models" / base.sbom_model).with_suffix(".context.json"),
                (models_dir / base.sbom_model).with_suffix(".context.json"),
            )
            tag = f"revocation_propagation rep={rep} fleet={fleet}"
            primary = _variant(src, models_dir / base.image_model, tag + " P")
            successor = _variant(src, models_dir / "successor" / base.image_model, tag + " S")
            for h, name in ((primary, "eval P"), (successor, "eval S")):
                ctx.chain.send(
                    ctx.chain.models.functions.register(bytes.fromhex(h[2:]), name),
                    ctx.admin_account,
                )
            settings = eval_settings(
                models_dir=models_dir,
                stage2_model_hashes=f"{sbom_hash},{primary}",
                batch_max_size=100_000,
                batch_max_wait_s=10_000,
                listener_poll_s=poll_s,
            )
            service = await in_process_gateway(settings)
            rid = bytes.fromhex(rid_hex[2:])
            verdicts_before: dict[str, str] = {}
            for i in range(fleet):
                view = device_view(i)
                service.devices.put(
                    DeviceRecord(
                        view.device_id,
                        view.device_model,
                        "ed25519:" + "00" * 32,
                        str(view.installed_version),
                        0,
                        0,
                    )
                )
                verdicts_before[view.device_id] = (await service.verify(rid, view)).verdict.value
            assert service.batcher is not None  # noqa: S101
            committed = await service.batcher.flush()
            assert committed is not None and committed.count == fleet  # noqa: S101

            receipt = ctx.chain.send(
                ctx.chain.models.functions.revoke(
                    bytes.fromhex(primary[2:]), bytes.fromhex(successor[2:])
                ),
                ctx.admin_account,
            )
            job = RevocationJob(service, settings.state_dir / "revocations.json", poll_s)
            start = time.perf_counter()
            reports = await job.check_once()
            handle_ms = (time.perf_counter() - start) * 1000
            assert len(reports) == 1 and reports[0].swapped  # noqa: S101
            report = reports[0]
            raw.append(
                {
                    "rep": rep,
                    "fleet_size": fleet,
                    "pairs": len(report.pairs),
                    "stale_batches": len(report.stale_batches),
                    "changed": sum(p.before != p.after for p in report.pairs),
                    "handle_ms": round(handle_ms, 1),
                    "per_pair_ms": round(handle_ms / max(len(report.pairs), 1), 1),
                    "propagation_ms": round(handle_ms + poll_s * 1000, 1),
                    "revoke_tx": "0x" + bytes(receipt["transactionHash"]).hex(),
                    "revoke_block": int(receipt["blockNumber"]),
                    "primary": primary,
                    "successor": successor,
                }
            )
            shutil.rmtree(models_dir, ignore_errors=True)
    write_raw(out_dir, raw)
    metrics = ("handle_ms", "per_pair_ms", "propagation_ms")
    summary = {
        "experiment": "revocation_propagation",
        "repetitions": reps,
        "fleet_sizes": fleet_sizes,
        "poll_s": poll_s,
        "release": rid_hex,
        "publisher": did,
        "per_fleet_size": {
            str(f): {
                **{m: median_iqr([r[m] for r in raw if r["fleet_size"] == f]) for m in metrics},
                "pairs": median_iqr([r["pairs"] for r in raw if r["fleet_size"] == f]),
                "changed": median_iqr([r["changed"] for r in raw if r["fleet_size"] == f]),
            }
            for f in fleet_sizes
        },
        "note": "in-process gateway, explainer off; pairs = D device verdicts (release-level "
        "verdicts are not part of this fleet)",
    }
    write_summary(out_dir, summary)
    return {"stack": stack_info(base, ctx)}


def run(config: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Entry point for ``run.py``."""
    return asyncio.run(_run(config, out_dir))
