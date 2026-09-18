# 0006 — Publisher reputation: integer EWMA of receipts and release-level rejects

**Status:** Accepted   **Date:** 2026-09-18
**Deciders:** project author

## Context
The policy engine uses a reputation term `w_rep · (1 − reputation)` (Guide §7). The value must be
on-chain (auditable), written only by gateways (`GATEWAY_ROLE`), cheap to update, and must not be
a security check on its own — Stage 1 is.

## Decision
- Reputation is stored in basis points (0–10 000) in `PublisherRegistry`; a new publisher starts at
  5 000 (neutral).
- Update rule (integer, rounds half away from zero): `rep' = rep + α · (signal − rep)` with
  `α = REPUTATION_ALPHA_BP = 1 000` (0.1), `signal = 10 000` for a signed install receipt and `0`
  for a REJECT. The integer form converges to within ≈ 1/(2α) = 5 bp of the target.
- Only **release-level** rejects count against a publisher: Stage-1 failures `firmware_hash`,
  `signature`, `sbom_hash`, `registry_record`, and policy REJECTs. Device-level failures
  (`version_monotonic` on a device that is already newer, an expired manifest, a revoked model)
  say nothing about the publisher and do not change reputation.
- Updates are best-effort: a chain error is logged and the next signal simply applies to the
  current on-chain value.

## Alternatives considered
- Counting receipts and rejects (ratio) — rejected: unbounded history makes recovery impossible.
- Off-chain reputation — rejected: the policy input would not be auditable.

## Consequences
With the default policy (`w_rep = 0.2`) a neutral publisher contributes R = 0.10; a publisher at
0 contributes 0.20 — never enough to reject on its own, but enough to tip a borderline Stage-2
score into DEFER. Values are reported in the evaluation as measured.
