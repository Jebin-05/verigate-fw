# 0009 — Model revocation: successor by hash, replay at the gateway, fail closed without one

**Status:** Accepted   **Date:** 2026-09-18
**Deciders:** project author

## Context
Guide "Novelty 2": an AI model is a supply-chain artefact. `ModelRegistry.revoke(hash, successor)`
marks every batch that used the hash STALE (`VerdictRegistry.staleByModel`). Something has to turn
that on-chain fact into re-evaluated devices, and it has to work when the successor is missing.

## Decision
- **The gateway replays, not the admin.** A background job (`gateway/revocation.py`) polls the
  status of every model it runs; on REVOKED it reads `staleByModel`, joins the batch ids with its
  local batch store (only batches whose Merkle root matches the on-chain root — a reset dev chain
  leaves stale ids locally), and re-runs the *full* gate for every distinct (release, device)
  pair. The new records go through the normal batcher, so the replay is itself anchored.
- **Successor located by hash, never by name.** The registry names the successor hash; the gateway
  searches `MODELS_DIR` recursively for an `.onnx` whose SHA-256 equals it and swaps only the slot
  that ran the revoked model. `model_hashes()` then names the successor, so Stage 1's
  `model_active` check and the verdict's `modelHashes` follow.
- **No successor file → fail closed.** The revoked hash stays configured, Stage 1 rejects on
  `model_active` and the report shows every pair going APPROVE → REJECT. That is the honest state:
  the gateway can no longer vouch for those releases.
- **Cached rationales are dropped** on a swap (ADR-0002: a rationale explains one model's scores).
- Idempotent per hash, persisted in `STATE_DIR/revocations.json`; `GET /revocations` and
  `POST /revocations/check` expose it; the Models page renders before → after with the count of
  changed verdicts.

## Consequences
- The replay judges each pair against the device's *current* state, not the state at the time of
  the stale verdict (the verdict record does not carry the installed version). A device that has
  moved on since gets REJECT (`version_monotonic`) for the old release, which is correct — that
  release must not be installed now — but it shows up as REJECT rows in the verdict log after a
  revocation (seen in the docker demo rehearsals: 20 fleet devices × 3 older releases).
- The replay costs one full verification per pair (Stage 2 inference, plus the LLM rationale for
  the release-level pair). Measured on the dev stack: 2 pairs, one release, 105 s including a
  ~100 s CPU-only LLM call; without the explainer the same replay is a few seconds.
- The successor shipped for the demo (`models/successor/`) is the same trainer at seed 43 and is
  documented as such — it demonstrates the mechanism, not a better model.
