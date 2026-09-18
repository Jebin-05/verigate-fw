# Model card — `image_anomaly.onnx`

- **Model hash (SHA-256 of the ONNX bytes, registered on-chain):** `53f5c172119b1c7d90bc649ecf12edd7efb57950b31196b60acba0851547c88f`
- **Trained:** 2026-09-18 · git `943d192eeaf2b9ee08829bfb9f9d6ccad8411257` · seed 42 · Python 3.11.13

## Purpose
Stage-2 image anomaly score `r_img ∈ [0, 1]`: how *structurally unusual* a firmware binary looks
compared with genuine releases — entropy profile, ELF header / segment sanity, bytes appended
after the declared end, and how much changed versus the previous version. It catches structural
tampering (appended payloads, packing, patched or shuffled regions, relabelled old images).
**It does not detect a competently built malicious firmware with normal structure** (Guide §6.2
scope statement); Stage 1, the SBOM score and reputation are the other layers.

## Training data (benign only)
- 165 real OpenWrt package binaries (ELF, mips_24kc; 15 packages across
  11 releases 21.02.7 … 24.10.2) that have a predecessor in the corpus,
  so version deltas are defined (`data/sources.yaml`, `images` section).
- `data/MANIFEST.sha256` (SHA-256 of the corpus manifest): `145967d1eb5d7f8a9f5c7f599a2d3fd7d8c44fdaedc45adf22d7bc660a14930f`.
- The tampered set below is **synthetic**: 825 mutated copies produced by
  `verigate.ml.data.mutate` with the seeds derived from `seed`. It is not real-world malware and
  the paper says so.

## Mutation catalogue (evaluation set)
| mutation | description | parameters |
|---|---|---|
| `byte-patch` | overwrite random regions with random bytes (backdoor-style patch) | `{"n_patches": 4, "patch_len": 64}` |
| `append` | append a high-entropy payload after the declared image end | `{"size": 204800}` |
| `section-swap` | swap two body regions (layout tampering, content preserved) | `{"chunk_size": 16384}` |
| `pack` | compress the body and pad randomly (packed / encrypted payload profile) | `{"level": 9}` |
| `downgrade-relabel` | old image body under the new header and version label | `{"label_len": 64}` |

## Features (units) — order is the ONNX input order
| # | name | unit |
|---|---|---|
| 1 | `size_kb` | KiB |
| 2 | `entropy_mean_x1000` | bits/byte × 1000 over 1 KiB chunks |
| 3 | `entropy_std_x1000` | bits/byte × 1000 |
| 4 | `entropy_max_x1000` | bits/byte × 1000 |
| 5 | `high_entropy_chunks_pct` | % of chunks with entropy > 7.5 |
| 6 | `printable_ratio_x1000` | fraction of printable bytes × 1000 |
| 7 | `header_valid` | ELF header sane (0/1) |
| 8 | `n_sections` | section-table entries (0 for stripped binaries) |
| 9 | `n_segments` | program-header entries |
| 10 | `declared_size_kb` | highest byte covered by a PT_LOAD segment / section, KiB |
| 11 | `appended_kb` | bytes after the declared end, KiB |
| 12 | `size_delta_kb` | size − previous version, KiB |
| 13 | `entropy_delta_x1000` | mean entropy − previous, × 1000 |
| 14 | `changed_chunks_pct` | % of 1 KiB chunks that differ from the previous version |

## Model
`sklearn.ensemble.IsolationForest`, `{"contamination": "auto", "max_samples": 128, "n_estimators": 200}`, `random_state=42`; exported with skl2onnx
(opset 17 / ai.onnx.ml 3). The ONNX `scores` output reproduces sklearn's `decision_function`
(max abs diff 3.57e-07).

**Calibration** (stored in `image_anomaly.context.json`): anomaly score `s = −score_samples`;
`r_img = clip((s − 0.4503) / (0.6273 − 0.4503) · 0.5, 0, 1)` — benign training
median → 0.0, benign 99th percentile → 0.5.

## Metrics (detection = `r_img ≥ 0.5`, benign rows are the training set)
| class | precision | recall | AUROC vs benign | n |
|---|---|---|---|---|
| benign (train) | false-positive rate 0.012 | – | – | 165 |
| `byte-patch` | 0.500 | 0.012 | 0.543 | 165 |
| `append` | 0.988 | 1.000 | 1.000 | 165 |
| `section-swap` | 0.500 | 0.012 | 0.504 | 165 |
| `pack` | 0.833 | 0.061 | 0.895 | 165 |
| `downgrade-relabel` | 0.000 | 0.000 | 0.431 | 165 |

## Known failure modes / limitations
- Benign rows are also the training rows (no held-out benign set beyond the 99th-percentile
  calibration); the false-positive rate above is therefore optimistic.
- One architecture (MIPS 24Kc) and one distribution family; other binaries are extrapolations.
- Small byte patches (`byte-patch`) change little structurally and are the weakest class — this
  is exactly why the hash and signature checks of Stage 1 exist.

Regenerate with `make train` (`verigate-train image --seed 42`); `make models-hash` updates
`models/MANIFEST.sha256`. Old model files are never overwritten once registered — bump the name.
