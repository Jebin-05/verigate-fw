# 0002 — The LLM explains; deterministic models decide

**Status:** Accepted   **Date:** 2026-09-17

## Context
LLM output is non-deterministic and may hallucinate; a security gate must be reproducible (verdict attestation needs
`f(model, features) == score`).

## Decision
`r_sbom` and `r_img` come from ONNX-exported scikit-learn models with pinned inputs. The LLM (`qwen2.5:3b-instruct`
via Ollama) only produces `rationale.json` from the SBOM diff, changelog and SHAP attributions. Its CID is stored in
the verdict; its content never influences `R`.

## Consequences
Verdicts are reproducible; LLM downtime degrades to "no rationale" not "no verdict"; `LLM_ENABLED=false` in CI.
