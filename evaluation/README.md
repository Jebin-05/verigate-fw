Every experiment = one YAML in `configs/` + one runner. Results are written, never edited:
```
evaluation/
  configs/    <experiment>.yaml   (seed, fleet size, network, repetitions, model hashes)
  runners/    run.py dispatches to runners/<experiment>.py
  results/    <experiment>/<YYYY-MM-DD_HHMM>_<git-sha>/ raw.csv + summary.json + env.json
  figures/    generated ONLY by `python evaluation/figures.py` from results/; never hand-made
```
Rules: fixed seeds · record git sha + machine info in env.json · ≥ 5 repetitions for timing · report median + IQR ·
Arbitrum Sepolia runs record tx hashes so anyone can verify on the explorer.

## Experiments (P7-01)

| config | needs | what it measures |
|---|---|---|
| `latency_stage1` | hardhat + IPFS | pure checks, warm/cold `verify()` with the `NullScorer` (in-process) |
| `latency_stage2` | + models, optional gateway/Ollama | SBOM/image scoring cold/warm, full gate, HTTP device verify, explainer calls |
| `gas_per_verdict_vs_batched` | hardhat | `commitBatch` gasUsed for batch sizes 1…200 (gateway account) |
| `revocation_propagation` | hardhat + IPFS + models | revoke → replay time vs fleet size (in-process gateway, byte-distinct model copies) |
| `attack_matrix` | running gateway | every scenario × N, pass rate per row; `poisoned-model` capped at 2 runs |
| `detection_f1`, `sbom_ranking` | datasets under `data/processed` | model metrics (bootstrap) |

Run them on a fresh stack with the explainer off so timings are not perturbed by the LLM:
`make infra-up && make contracts-deploy-local && make models-register && LLM_ENABLED=false make gateway`
then `make eval-all` and `make figures`. Runs that crashed keep their directory with a `NOTE.md`
explaining why (append-only rule); the latest complete run is what `figures.py` uses.
