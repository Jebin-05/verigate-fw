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
