"""P7-01 gas_per_verdict_vs_batched: on-chain cost of anchoring verdicts vs batch size.

Commits real ``VerdictRegistry.commitBatch`` transactions from the gateway account on the local
Hardhat node — one batch per (batch size, repetition) — and reads ``gasUsed`` from the receipts.
Gas per verdict is ``gasUsed / count``; batch size 1 is the "one transaction per verdict" baseline
(what a naive design would pay). ``contracts/gas-report.txt`` (hardhat-gas-reporter, from the
contract test-suite) is referenced for comparison; Sepolia receipts are a separate run (P7-02).
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from common import ROOT, median_iqr, write_raw, write_summary
from live import eval_settings, stack_info

from verigate.attacks.common import AttackContext
from verigate.common.merkle import MerkleTree


def run(config: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Commit batches of the configured sizes and measure gas."""
    sizes = [int(s) for s in config.get("batch_sizes", [1, 10, 50, 100, 200])]
    reps = int(config.get("repetitions", 5))
    n_models = int(config.get("model_hashes", 2))
    settings = eval_settings()
    ctx = AttackContext.from_settings(settings)
    if not settings.gateway_private_key:
        raise SystemExit("GATEWAY_PRIVATE_KEY (GATEWAY_ROLE) is required to commit batches")
    account = ctx.chain.account(settings.gateway_private_key)
    # commitBatch refuses hashes that are not ACTIVE models: use the gate's registered ones.
    registered = [
        bytes.fromhex(h.strip().removeprefix("0x"))
        for h in settings.stage2_model_hashes.split(",")
        if h.strip()
    ]
    if len(registered) < n_models:
        raise SystemExit(f"STAGE2_MODEL_HASHES has {len(registered)} hashes; need {n_models}")
    model_hashes = registered[:n_models]

    raw: list[dict[str, Any]] = []
    for rep in range(reps):
        for size in sizes:
            leaves = [secrets.token_bytes(32) for _ in range(size)]
            root = MerkleTree.from_leaves(leaves).root
            receipt = ctx.chain.send(
                ctx.chain.verdicts.functions.commitBatch(root, size, model_hashes), account
            )
            gas = int(receipt["gasUsed"])
            raw.append(
                {
                    "rep": rep,
                    "batch_size": size,
                    "gas_used": gas,
                    "gas_per_verdict": round(gas / size, 2),
                    "tx_hash": "0x" + bytes(receipt["transactionHash"]).hex(),
                    "block": int(receipt["blockNumber"]),
                }
            )
    write_raw(out_dir, raw)
    per_size = {
        str(size): {
            "gas_used": median_iqr([r["gas_used"] for r in raw if r["batch_size"] == size]),
            "gas_per_verdict": median_iqr(
                [r["gas_per_verdict"] for r in raw if r["batch_size"] == size]
            ),
        }
        for size in sizes
    }
    baseline = per_size[str(sizes[0])]["gas_per_verdict"]["median"]
    report = ROOT / "contracts" / "gas-report.txt"
    summary = {
        "experiment": "gas_per_verdict_vs_batched",
        "network": f"chainId {settings.chain_id} (local Hardhat; receipts are real, no gas price)",
        "repetitions": reps,
        "batch_sizes": sizes,
        "per_size": per_size,
        "saving_vs_single": {
            str(size): round(1 - per_size[str(size)]["gas_per_verdict"]["median"] / baseline, 4)
            for size in sizes
        },
        "hardhat_gas_reporter": str(report.relative_to(ROOT)) if report.exists() else None,
    }
    write_summary(out_dir, summary)
    return {"stack": stack_info(settings, ctx), "gateway_account": account.address}
