# Model card — `sbom_risk.onnx`

- **Model hash (SHA-256 of the ONNX bytes, registered on-chain):** `67516bbe7ca4c051e0d4b147f4c0748f7c5d39a222f88f932b70b41ceeb7e5b2`
- **Trained:** 2026-09-18 · git `943d192eeaf2b9ee08829bfb9f9d6ccad8411257` · seed 42 · Python 3.11.13

## Purpose
Stage-2 SBOM risk score `r_sbom ∈ [0, 1]` for a firmware release: an estimate of the release's
exposure to actively exploited vulnerabilities, computed from its SBOM and public vulnerability
data. It only ever *tightens* a decision (Stage 1 cannot be overridden) and is anchored on-chain
with the feature hash of every verdict so any score can be recomputed.

## Training data
- OpenWrt release manifests → CycloneDX SBOMs (`data/sources.yaml`): 624 release×target rows
  across 49 releases (19.07.0 … 25.12.5).
- `data/MANIFEST.sha256` (SHA-256 of the corpus manifest): `145967d1eb5d7f8a9f5c7f599a2d3fd7d8c44fdaedc45adf22d7bc660a14930f`.
- Vulnerability data: OSV.dev (query by package name + version across every ecosystem,
  re-evaluated client-side against upstream versions, de-duplicated by CVE; the Linux kernel and
  OpenWrt-internal components are not matched), EPSS snapshots model_version:v2025.03.14, CISA KEV catalogue
  released 2026-09-16T18:47:50.6796Z.
- ESPHome / Tasmota (named in the Project Guide) are **not** included: they ship monolithic ESP
  images without a package manifest, so no SBOM can be derived honestly.

## Target (label)
**Expected exploited-CVE count at T1 = 2026-09-17**: `Σ EPSS_T1(cve)` over every CVE of the release
published by T1 — with EPSS the 30-day exploitation probability of each CVE, the sum is the
expected number of the release's vulnerabilities that are exploited in the wild (the additive form
keeps a dynamic range that "at least one exploited" loses for firmware with 50–200 CVEs). At the
gateway `r_sbom = 1 − exp(−prediction / 6.0)` (six expected exploited CVEs → 0.63; the scale is
stored in `sbom_risk.context.json`). Features are computed as of T0 = 2025-09-18: only CVEs published by T0, the EPSS snapshot of
T0 and KEV membership as of T0, so the model predicts *future* exposure (including vulnerabilities
not yet disclosed at T0) from data that was public at T0. The label comes from an external,
evidence-driven scoring system, not from a hand-made severity formula. CISA KEV was tried first as
the label and is degenerate for this corpus (no KEV entry matches OpenWrt userland packages); it is
kept as a feature only. The tampered / malicious sets used elsewhere in this project are synthetic;
this model does not claim to detect malware.

## Features (units) — order is the ONNX input order
| # | name | unit |
|---|---|---|
| 1 | `n_components` | count |
| 2 | `n_vulnerable_components` | count |
| 3 | `n_cves` | count (unique CVEs) |
| 4 | `max_cvss_x10` | CVSS v3 base score × 10 |
| 5 | `mean_cvss_x10` | CVSS v3 base score × 10 |
| 6 | `sum_epss_x1e4` | Σ EPSS × 10 000 |
| 7 | `max_epss_x1e4` | max EPSS × 10 000 |
| 8 | `kev_count` | count (KEV as of T0) |
| 9 | `n_outdated` | components older than the corpus' newest version of that package |
| 10 | `mean_dep_age_days` | mean days since each shipped version was first seen in the corpus |

## Model
`sklearn.ensemble.HistGradientBoostingRegressor`, `{"l2_regularization": 1.0, "learning_rate": 0.05, "max_depth": 4, "max_iter": 200, "min_samples_leaf": 5}`, `random_state=42`,
no early stopping; exported with skl2onnx (opset 17 / ai.onnx.ml 3). The ONNX output is the
**growth ratio** `label / (Σ EPSS at T0)`; the prediction is `Σ EPSS_T0 × ratio` (a direct
regressor was measured first and could not extrapolate to the newest, less-vulnerable releases:
trees predict a constant outside the training range). ONNX output equals sklearn output on the
test set (max abs diff 1.27e-07, tested at atol 1e-6).

## Split and metrics (held-out = the newest releases, whole releases)
- train rows: 428 · test rows: 196 · label mean (train / test): 5.067 / 1.876 expected exploited CVEs

| metric (test set) | model | baseline (CVSS/EPSS/KEV formula at T0, mapped to −ln(1−p)) |
|---|---|---|
| auroc_high_exposure | 1.0000 | 1.0000 |
| mae | 0.1667 | 1.0116 |
| median_ae | 0.0828 | 0.9663 |
| spearman | 0.9650 | 0.9765 |

## Known failure modes / limitations
- One distribution family (OpenWrt); scores for very different SBOMs are extrapolations.
- KEV is a curated list of *observed* exploitation: a release can be dangerous without any KEV entry.
- OSV name-based matching can attach advisories of unrelated packages with the same name
  (rare for firmware package names, but not impossible).
- Per-target rows of one release share most packages; the split is by release so this cannot
  inflate the metrics, but the effective sample size is closer to the number of releases.

Regenerate with `make train` (`verigate-train sbom --seed 42`); `make models-hash` updates
`models/MANIFEST.sha256`. Old model files are never overwritten once registered — bump the name.
