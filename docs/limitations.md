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
(`evaluation/results/latency_stage2/2026-09-18_1100_ec248b1`, `raw_llm.csv`) against 111 ms for
the whole deterministic gate in-process (216 ms over HTTP). Consequently only release-level verifications
wait for the rationale; device polls issued before it exists carry `rationaleCid = null`. The full
demo takes 348 s with the explainer versus 53 s without (README). A GPU or a smaller prompt would
change this; the design does not.

## 7. Model revocation has a fixed ~7 s cost before the first replay
`evaluation/results/revocation_propagation/2026-09-18_1109_ec248b1`: replaying 5 / 20 / 50 stale
device verdicts takes 7.5 / 8.8 / 11.7 s (median) after the job notices the revocation, plus its
poll interval (2 s). About 7 s of that is loading the successor ONNX model and its SHAP
background, independent of fleet size; each additional device costs ≈ 90 ms. Every replayed
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
node; no gas price and no L2 data-availability cost is included. Arbitrum Sepolia receipts
(P7-02) require funded keys and are not yet recorded. Latency figures are in-process on one
laptop; the fleet is emulated (asyncio), not hardware.

## 13. Operating point chosen on the fixtures
τ_approve = 0.45 / τ_reject = 0.70 (ADR-0008) were set so that the three genuine fixture
releases sit at APPROVE / DEFER / APPROVE with neutral reputation. They are defaults measured on
three releases, not a tuned operating point.
