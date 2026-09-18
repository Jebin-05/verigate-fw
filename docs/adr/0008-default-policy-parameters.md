# 0008 — Default policy parameters: w = (0.4, 0.4, 0.2), τ_approve = 0.45, τ_reject = 0.70

**Status:** Accepted   **Date:** 2026-09-18
**Deciders:** project author

## Context
`PolicyContract` needs initial values (`contracts/scripts/defaults.ts`). The placeholder
τ_approve = 0.30 / τ_reject = 0.60 was chosen before any Stage-2 model existed. With both models
registered, the genuine demo fixtures measure (gateway logs, 2026-09-18, models
`sbom_risk` 6f7c9274…, `image_anomaly` 7f5c4baa…, reputation 0.5):

| release | r_sbom | r_img | R |
|---|---|---|---|
| v1.0.0 (OpenWrt 22.03.7 busybox) | 0.516 | 0.310 | 0.451 |
| v1.1.0 (23.05.3) | 0.482 | 0.403 | 0.462 |
| v2.0.0 (24.10.0) | 0.296 | 0.431 | 0.378 |

Genuine, current firmware would be deferred under the placeholder — the AI gate must not make
every honest release a manual review.

## Decision
- Weights stay `w_sbom = 0.4, w_img = 0.4, w_rep = 0.2` (SBOM and image risk equal, reputation a
  tie-breaker that can never reject on its own — ADR-0006).
- `τ_approve = 0.45`: a current genuine release with neutral reputation approves; a release that
  is a year older or structurally unusual lands in DEFER (v1.0.0/v1.1.0 sit at the boundary and are
  the "borderline" cases the demo shows). `τ_reject = 0.70`: REJECT needs more than one strong
  signal — e.g. a structurally anomalous image (`r_img → 1`) on top of a vulnerable SBOM, or a
  publisher with a bad history — which matches the Guide §9 outcomes (hidden payload → DEFER for
  review; vulnerable-but-genuine → REJECT or DEFER).
- These are *defaults*; changing them is an on-chain transaction (`verigate-admin set-policy`) and
  P7 sweeps them (`policy_sweep` experiment) to report the attack-matrix sensitivity.

## Alternatives considered
- Tuning r_img's calibration instead — rejected: the calibration is a property of the model card
  (benign p99 → 0.5) and should not be bent to a demo.
- Lower `w_img` — rejected: the image detector is the only signal for the hidden-payload attack.

## Consequences
The smoke test (Stage 1 only, no models configured in `.env.example`) is unaffected. With models
enabled, the demo's clean release approves and the two older ones defer, which is the intended
story. Numbers above are measured on this machine and re-measured in P7.
