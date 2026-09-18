# 0005 — Verdict batching: one Merkle root per ≤ 50 verdicts or 10 s

**Status:** Accepted   **Date:** 2026-09-18
**Deciders:** project author

## Context
Every verdict must be anchored on-chain (Guide §8, Novelty 1) but one transaction per device does not
scale (LedgerGuard commits per device; that is the efficiency claim we measure). The gateway also
needs bounded latency between a verdict and its on-chain commitment so the dashboard and devices
can obtain a proof soon after a decision.

## Decision
- The gateway signs every verdict record (EIP-191, gateway account) and queues its leaf
  `sha256(0x00 ‖ "VERIGATE-VERDICT-V1" ‖ canonical(record))`.
- A batch is committed with `VerdictRegistry.commitBatch(root, count, modelHashes)` when either
  `BATCH_MAX_SIZE = 50` verdicts are pending or the oldest pending verdict is `BATCH_MAX_WAIT_S = 10`
  seconds old, whichever comes first. Both are `.env` settings so P7 can sweep them.
- Batches (records, leaves, tx hash, block) are persisted under `STATE_DIR/batches/`; proofs are
  rebuilt on demand at `/verdicts/{id}/proof`. A failed commit keeps the verdicts pending and
  retries; nothing is ever dropped.
- `modelHashes` of a batch is the union of the model hashes of its records, so
  `staleByModel` can find every batch a revoked model touched.

## Alternatives considered
- Per-verdict transactions — rejected: the gas cost is the problem being solved.
- Fixed time-only batching — rejected: a burst of 500 devices would wait the full window.
- Off-chain aggregation with periodic checkpoints (hours) — rejected: too slow for a demo and for
  revocation propagation measurements.

## Consequences
A verdict is "pending" for up to 10 s (visible in the API); evaluation reports gas per verdict as a
function of batch size. Leaves depend on the signed record, so a re-signed record is a new verdict.
