# 0010 — Release delta is a deterministic Stage-1 check (#9) that defers, not a model feature

**Status:** Accepted
**Date:** 2026-10-02
**Deciders:** project author

## Context
The image anomaly model is at chance on small byte patches and section swaps (recall 0.012 /
0.015, AUROC 0.54 / 0.53, `release_delta/2026-10-02_1619_3300b9f`). In 120 of the 165 benign
corpus pairs OpenWrt did not rebuild the package, so the new release is byte-identical to its
predecessor — a patch on top of an unchanged image is a common, concrete case. The smallest benign
*rebuild* changes 76 of its 64-byte blocks; a catalogue byte patch changes at most 8.

## Decision
Add check #9 `release_delta` (`gateway/stage1/delta.py`). Reference = newest earlier, non-revoked
release of the same publisher and device model that this gateway **approved** and whose served
image matches its on-chain hash. Each 64-byte block of the new image is looked up among the
reference's 64-byte windows at every 4-byte offset; repeated blocks must sit where the reference
continues. Not byte-identical and ≤ 32 changed blocks (2 KiB), or reordered blocks → DEFER with
the changed offsets in the reason. Never REJECT.

## Alternatives considered
- **Delta features in the IsolationForest** — measured, worse: patch recall stays 0.012, append
  recall falls 1.000 → 0.297 (`delta_features_iforest/2026-10-02_1712_3300b9f`). An unsupervised
  model trained on mostly-identical pairs does not isolate "almost identical".
- **REJECT on a patch** — a genuine vendor binary hot-patch has the same footprint; a person
  should decide.
- **Reference = last non-revoked release** — tried first; the e2e suite showed it makes a
  rejected tampered release, or a held insider patch, the reference for the next genuine release
  (bad-history and poisoned-model failed). Hence "approved and hash-consistent".

## Consequences
Byte patches and section swaps on an unchanged base: 120/120 and 97/97 held; benign flagged 0/165
(`release_delta`). Rebuilt packages: nothing caught. Cost: ≈ 10 ms in-process / 18 ms over HTTP
per verification in a same-session A/B (`ablation_check9_off/`); the comparison is cached per
(release, reference) pair. The 2 KiB limit is set from a corpus with no benign hot-patch
releases; revisit with real hot-patch data.
