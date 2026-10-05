# Limitations (P7-06) — drafted from measured failures

Every item below is something the system was *observed* to do badly, with the result directory or
test that shows it. Items are not softened; the paper's limitations section is written from this
file.

## 1. The image anomaly detector only sees structural tampering
`evaluation/results/detection_f1/2026-09-18_0818_943d192` (165 benign, 165 per mutation class,
operating point r_img ≥ 0.5 = benign 99th percentile):

| mutation | recall | AUROC | what it means |
|---|---|---|---|
| `append` (200 KiB high-entropy payload) | 1.000 | 1.000 | the case the Guide promises is caught |
| `pack` (compress a section) | 0.061 | 0.895 | ranks tampered above benign but does not cross the threshold |
| `byte-patch` (16-byte patch) | 0.012 | 0.543 | indistinguishable from benign |
| `section-swap` | 0.012 | 0.504 | chance |
| `downgrade-relabel` | 0.000 | 0.431 | worse than chance: an old genuine build looks *more* normal |

Correction (2026-10-02, `release_delta/2026-10-02_1619_3300b9f`): in 120 of the 165 benign pairs
OpenWrt did not rebuild the package, so the release is byte-identical to its predecessor and
`downgrade-relabel` returns the *same file*; 29 `section-swap` rows likewise swap identical
regions. Those rows are not tampering. Excluding them: section-swap 0.015 / 0.527 (n = 136),
downgrade-relabel 0.000 / 0.435 (n = 45). The conclusion does not change.

What covers part of the gap is Stage-1 check #9 (release delta, ADR-0010), not the model: on pairs
whose package was not rebuilt it holds 120/120 byte patches and 97/97 section swaps for review and
flags 0/165 benign releases. On rebuilt pairs it catches nothing, so **a patch inside a rebuild is
still invisible to every detector in the system**. Feeding the delta to the IsolationForest as
features does not work either (patch recall 0.012, append recall falls to 0.297,
`delta_features_iforest/2026-10-02_1712_3300b9f`). Check #9 also holds a genuine vendor binary
hot-patch for review — by design, it never rejects — and its 2 KiB limit is set from a corpus that
contains no benign hot-patch releases (smallest benign rebuild: 76 blocks = 4.75 KiB).

A well-crafted malicious build that keeps size, entropy and layout is not detected by Stage 2;
the system relies on Stage 1 (hash, signature, registry) for that, which is exactly the Guide's
stated scope ("detects structural tampering, not well-crafted malicious builds"). The threshold
sweep shows the trade-off: recall over all classes reaches 0.62 only at r_img ≥ 0.05 with a 38 %
false-positive rate.

## 2. Hidden-payload detection depends on having the previous release
With a predecessor the `append` payload scores r_img 0.70 (`hidden-payload` attack, DEFER); the
same payload on a release with **no** predecessor scores 0.41 and the release would be APPROVED
(R ≈ 0.38, measured while designing the attack, 2026-09-18). The model's strongest feature is
`size_delta_kb`; for a publisher's first release the gate is blind to appended payloads.

## 3. Benign false-positive rate is optimistic
The benign rows used to measure the 1.2 % false-positive rate are the training rows
(`models/image_anomaly.card.md`); there is no held-out benign set beyond the 99th-percentile
calibration. One architecture (MIPS 24Kc busybox) and one distribution (OpenWrt) only.

## 4. No KEV-listed component exists in the corpus
The `vulnerable-but-genuine` scenario was meant to show a KEV hit. With the CISA catalogue as of
the snapshot date and the OpenWrt package → upstream mapping, `n_kev` is 0 for every SBOM in the
corpus (the KEV label was degenerate during training, `models/sbom_risk.card.md`). The scenario
therefore demonstrates EPSS/CVSS mass (r_sbom 0.73 on OpenWrt 19.07.10) rather than KEV, and the
KEV floor of the baseline scorer is untested on real data.

## 5. The SBOM model does not beat the baseline on ranking
`evaluation/results/sbom_ranking/2026-09-18_0818_943d192`: Spearman 0.965 (model) vs 0.976
(CVSS/EPSS/KEV baseline) on held-out releases. The model's advantage is calibration (MAE 0.17 vs
1.01 expected exploited CVEs), not ordering. A reviewer could reasonably ask why a learned model
is needed for ranking; the answer is the calibrated absolute scale the policy thresholds need.

## 6. The explainer is slow on CPU and cannot be waited for by devices
Six sequential `qwen2.5:3b-instruct` calls on an i7-1255U (no GPU): median 88 s, range 43–91 s
(`evaluation/results/latency_stage2/2026-09-18_1100_ec248b1`, `raw_llm.csv`) against 128 ms for
the whole gate in-process (244 ms over HTTP, `latency_stage2/2026-10-02_1702_3300b9f`). Consequently only release-level verifications
wait for the rationale; device polls issued before it exists carry `rationaleCid = null`. The full
demo takes 348 s with the explainer versus 53 s without (README). A GPU or a smaller prompt would
change this; the design does not.

## 7. Model revocation has a fixed ~8 s cost before the first replay
`evaluation/results/revocation_propagation/2026-10-02_1704_3300b9f`: replaying 5 / 20 / 50 stale
device verdicts takes 8.3 / 9.9 / 13.0 s (median) after the job notices the revocation, plus its
poll interval (2 s). About 7.8 s of that is loading the successor ONNX model and its SHAP
background, independent of fleet size; each additional device costs ≈ 100 ms. Every replayed
verdict kept its outcome (`changed = 0`), because the successor is the same detector retrained
with another seed — the experiment measures propagation, not a better model.

## 8. Model revocation replays consume revocable models
A model hash can be revoked once. The shipped stack has one primary image model and one
successor, so the `poisoned-model` scenario runs at most twice per chain lifetime (second run:
fail closed, no successor left). `evaluation/results/attack_matrix` records the cap. The
evaluation of propagation time works around it with byte-distinct copies of the same model.

## 9. Reputation is burned by the attack scenarios themselves
Every release-level REJECT lowers the publisher's EWMA reputation (ADR-0006), and the listener's
own verification counts as a second signal. After the six Stage-1 attacks the demo publisher's
genuine v2.0.0 release moves from APPROVE (R 0.36) to DEFER (R 0.47, observed in the first e2e
run of 2026-09-18). This is intended behaviour, but it means the order of scenarios matters and a
publisher recovers only through confirmed install receipts.

## 10. Release-id squatting
`releaseId = keccak(manifest)`: whoever registers a manifest first owns the id. A squatter's copy
fails Stage 1 #2 for the claimed DID, but the genuine publisher's identical manifest is refused
as "already registered" and must be re-issued with a different expiry (threat model row 15; found
when the `forge` scenario collided with the happy-path release).

## 11. Cold vulnerability data
The first Stage-2 verification on an empty cache fetches OSV records per component plus the
EPSS snapshot and the KEV catalogue: `make smoke` from a clean machine took 12 min including the
image build, essentially all of it in that fetch. The cache is persisted, and an offline snapshot
can be exported, but a fresh deployment is not fast until it is warm.

## 12. Local-chain numbers only (so far)
Gas figures (`evaluation/results/gas_per_verdict_vs_batched`) are `gasUsed` from a local Hardhat
node; no gas price and no L2 data-availability cost is included. A public-testnet deployment was
**deliberately left out of scope**, so the batching saving (99.5 % at 200 verdicts per batch) is a
statement about `gasUsed` only: on a real L2 each transaction also pays for its calldata, which
batching reduces in the same direction but not by the same factor. The gated deploy workflow and
the `arbitrumSepolia` network config are in the repository, so the measurement can be added later
without code changes. Latency figures are in-process on one laptop; the fleet is emulated
(asyncio), not hardware.

## 14. A compromised gateway can still approve a registered release
Devices read the publisher key and the release record from the chain (`Device._check_chain`), so a
rogue gateway cannot make them install unregistered, withdrawn, revoked-key or downgraded firmware
(`rogue-gateway` scenario, 5/5). It *can* approve a release that is registered and genuinely
signed but that the gate would have held (an `insider-patch` release, say): the gateway is the
only verdict authority. That verdict is signed, anchored and carries its feature hash and model
hashes, so the misbehaviour is detectable afterwards, not prevented. Preventing it needs k-of-n
gateways or device-side verification of anchored verdicts, neither of which is built.

## 15. One latent anchoring bug was found by the expanded attack matrix
Before 2026-10-02, two concurrent transactions from the gateway account (a batch commit and a
reputation update) could pick the same nonce; the failed batch stayed queued, and if a model it
named was revoked meanwhile, `commitBatch` reverted with `ModelNotActive` on every retry, so
anchoring stopped for good. Fixed: sends are serialised per account, and verdicts naming an
inactive model are held back and replayed by the revocation job. It is listed here because the
September measurements ran on the old code.

## 13. Operating point chosen on the fixtures
τ_approve = 0.45 / τ_reject = 0.70 (ADR-0008) were set so that the three genuine fixture
releases sit at APPROVE / DEFER / APPROVE with neutral reputation. They are defaults measured on
three releases, not a tuned operating point.

## 16. Reviewer identity is not authenticated
A held release can be accepted or rejected from the console (`POST /releases/{id}/review`); the
decision is signed by the gateway and anchored, but the reviewer's name is whatever was typed —
the console has no login. Anyone who can reach the gateway API can decide a held release (not a
Stage-1 rejection). A deployment would need reviewer accounts or reviewer-signed decisions.
