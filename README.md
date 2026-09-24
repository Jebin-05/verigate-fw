# VeriGate-FW

Verifiable AI-gated firmware updates for IoT devices using blockchain and IPFS. The contracts
target an EVM L2 (Arbitrum); every number in this repository was measured on a local Hardhat node —
a public-testnet deployment is deliberately out of scope (see `docs/limitations.md`).
Software-only research prototype: emulated device fleet, two-stage verification gate
(cryptographic + AI risk), on-chain attested verdicts, model revocation.

> Read `docs/VeriGate-FW_Project_Guide.pdf` first (concepts), then `docs/VeriGate-FW_Developer_Manual.pdf`
> (how we build), then `CHECKLIST.md` (what is done).

## Run it anywhere (demo mode — only Docker needed)

```bash
git clone <repo> && cd verigate-fw
make doctor         # checks docker, RAM, disk, free ports
make up             # builds + starts chain, IPFS, contracts deploy, gateway, fleet, dashboard
make smoke          # proves the stack reaches an APPROVE verdict end-to-end
make llm-pull       # optional: LLM explainer (qwen2.5:3b-instruct, Apache-2.0, ~1.9 GB download, ~3 GB RAM, CPU only)
```
Works on Linux, macOS (Docker Desktop) and Windows (WSL2 + Docker Desktop). No Python/Node on the host required.

## Develop (host mode — hot reload)

```bash
make bootstrap      # venv, python deps, node deps
make infra-up       # hardhat node + IPFS only, in docker
make contracts-deploy-local
make gateway        # FastAPI on :8000 with reload
make fleet N=20     # 20 emulated devices
make dashboard      # Vite dev server on :5173
```

## Publish a release (host mode)

```bash
verigate-publish keygen                    # Ed25519 key under keys/ (git-ignored), reused if present
verigate-publish register                  # PublisherRegistry.register (idempotent; rotates on key change)
verigate-publish release --fw tests/fixtures/releases/v1.0.0/firmware.bin \
    --sbom tests/fixtures/releases/v1.0.0/sbom.json --version 1.0.0 \
    --model demo-device --expiry 2030-01-01T00:00:00Z --json
verigate-publish revoke <releaseId>        # withdraw a release
```

Every command prints one JSON object (`{"error": …}` and exit 1 on failure). `release` is
idempotent end to end: same inputs → same CIDs and `"status": "unchanged"`. Identity comes from
`.env`: `PUBLISHER_DID`, `PUBLISHER_PRIVATE_KEY` (the transaction account), `KEYS_DIR`.

## Demo

```bash
make up && ./scripts/demo.sh      # publish → devices install → eleven attacks caught
DEMO_MODE=host ./scripts/demo.sh  # same against `make gateway` + `make infra-up`
```
Measured on the development laptop (i7-1255U, no GPU): 53–58 s with the LLM explainer off (the
compose default — `--profile llm` adds Ollama), 348 s with a CPU-only `qwen2.5:3b-instruct`
explaining each release-level verdict (~60–120 s per rationale; device polls never wait for it).
The first run on an empty vulnerability cache takes 9–30 min (OSV/EPSS/KEV fetch); run the demo
once the day before, or `make vulndb-seed` from a host cache — runbook in `docs/demo/README.md`.
Dashboard (http://localhost:5173): a front door and two workspaces — the **publisher portal**
(`/publisher`: your releases, a new-release dialog, identity) and the **approval console**
(`/app`: overview, releases with an inspection detail panel — checks, AI analysis, explanation,
on-chain proof —, devices, live activity, governance with a rules simulator and model cards, and
`/app/scenarios` for the walkthrough and the security drills). Attack scripts: `verigate-attack run <name|all>` — Stage 1: tamper, forge, stolen-key,
rollback, freeze, sbom-swap; AI gate: vulnerable-genuine, hidden-payload, bad-history, poisoned-model, policy-tamper.

## Models and evaluation

```bash
verigate-train data fetch && verigate-train data sbom && verigate-train data images   # corpus (network)
make train                      # sbom_risk + image_anomaly (seed 42) → models/*.onnx + cards
make models-hash                # models/MANIFEST.sha256
make models-register            # register every hash in the manifest on-chain (compose does this)
verigate-admin revoke-model <hash> --successor <hash>   # Novelty 2: gateway replays stale verdicts
make eval EXP=evaluation/configs/sbom_ranking.yaml   # results/<exp>/<timestamp>_<sha>/
```
The Stage-2 SBOM scorer asks OSV / EPSS / KEV once per component and caches every answer under
`VULN_CACHE_DIR` (a named volume in compose): the first verification on an empty cache takes about
ten minutes (measured: `make smoke` from a clean machine, 12 min including the image build; a few
seconds once warm). For a demo without network run
`verigate-train data snapshot tests/fixtures/releases/*/sbom.json --out data/vulndb-demo` while
online, then `VULN_CACHE_DIR=data/vulndb-demo VULN_CACHE_ONLY=true` (host mode).

Enable Stage 2 at the gateway with `SBOM_MODEL`, `IMAGE_MODEL` and `STAGE2_MODEL_HASHES` in `.env`;
`LLM_ENABLED` / `OLLAMA_URL` / `LLM_MODEL` control the explain-only rationale (ADR-0002): a small
open-weights model (`qwen2.5:3b-instruct`, Apache-2.0, ~1.9 GB, runs on any x86-64/ARM laptop CPU
through Ollama; `qwen2.5:1.5b-instruct`, ~1.0 GB, fits 8 GB machines and answers in ~13 s, at the cost of vaguer prose — see the results table) writes a plain-language rationale from
the recorded scores and the ingredient-list diff — only when the approver presses **Explain with
AI** on a release (`POST /releases/{id}/explain`); `LLM_AUTO_EXPLAIN=true` writes after every
release-level verdict instead. The model cards under
`models/` state every number. Everything in the cards and under
`evaluation/results/` is measured on this machine — nothing is typed by hand.

## Layout

| Path | What lives here |
|---|---|
| `contracts/` | Solidity + Hardhat tests + deploy scripts |
| `src/verigate/` | All Python: publisher CLI, gateway, fleet emulator, ML, attack scripts |
| `dashboard/` | React + Vite operator console |
| `tests/` | Python unit / integration / e2e tests |
| `evaluation/` | Experiment configs, runners, raw results, figures |
| `models/` | Exported ONNX models + model cards + hash manifest |
| `data/` | Datasets (git-ignored; `data/README.md` says how to fetch/regenerate) |
| `infra/` | docker-compose and Dockerfiles |
| `docs/` | Guide, manual, SRS, ADRs, paper |
| `.github/` | Issue/PR templates, CODEOWNERS (no workflows — see Status) |

## Results (v1.0.0, measured — every number has a directory under `evaluation/results/`)

Machine: Intel i7-1255U, 15 GB RAM, no GPU; local Hardhat + Kubo; explainer off unless stated;
≥ 5 repetitions, warm-up discarded, median (IQR in the summaries).

| what | result | source |
|---|---|---|
| Stage 1: eight checks · warm verify · cold verify (IPFS + chain) | 3.3 ms · 89 ms · 98 ms | `latency_stage1/2026-09-18_1045_ec248b1` |
| Stage 2: SBOM score cold / warm · image score cold / warm | 115 / 0.1 ms · 104 / 1.3 ms | `latency_stage2/2026-09-18_1100_ec248b1` |
| full gate per device: in-process · over HTTP | 111 ms · 216 ms | same |
| LLM rationale (qwen2.5:3b-instruct, CPU) | 43–91 s, median 88 s | same, `raw_llm.csv` |
| Explanation on request, model warm (i7-1255U, CPU only, 2026-09-24) | `qwen2.5:3b-instruct` 30–33 s, specific and correct · `qwen2.5:1.5b-instruct` 12–15 s, valid but generic | two live releases, both models, `POST /releases/{id}/explain` |
| gas per `commitBatch` · per verdict at 200/batch | 209 642 · 1 048 (−99.5 % vs 1 tx per verdict) | `gas_per_verdict_vs_batched/2026-09-18_1044_ec248b1_1` |
| model revocation → 5 / 20 / 50 device verdicts replayed | 7.5 / 8.8 / 11.7 s (+2 s poll) | `revocation_propagation/2026-09-18_1109_ec248b1` |
| attack matrix, 11 scenarios × 5 runs (poisoned-model × 2) | 52 / 52 expected outcomes | `attack_matrix/2026-09-18_1114_ec248b1` |
| image anomaly: append · pack · byte-patch · section-swap · downgrade (recall @ r_img ≥ 0.5 / AUROC) | 1.00/1.00 · 0.06/0.90 · 0.01/0.54 · 0.01/0.50 · 0.00/0.43 | `detection_f1/2026-09-18_1125_ec248b1` |
| SBOM risk model vs CVSS/EPSS/KEV baseline (held-out, Spearman / MAE) | 0.965 / 0.17 vs 0.976 / 1.01 | `sbom_ranking/2026-09-18_1125_ec248b1` |
| demo (`scripts/demo.sh`, 11 attacks) | docker: 58 s warm cache, 553 s cold · host: 53 s without / 348 s with the CPU-only explainer | `docs/demo/README.md` |

The weak rows are discussed, not hidden: `docs/limitations.md`. Figures: `evaluation/figures/`
(regenerate with `make figures`). Paper: `docs/paper/main.pdf`. Requirements: `docs/srs/SRS.md`.

### Reproduce
```bash
make up                                   # or: make infra-up && make contracts-deploy-local && make models-register && LLM_ENABLED=false make gateway
./scripts/demo.sh                         # publish → fleet installs → eleven attacks (host mode: DEMO_MODE=host)
make eval-all && make figures             # every experiment (needs the host toolchain; ~40 min, explainer section ~10 min)
make train                                # retrain both models (byte-identical ONNX; needs the corpus: verigate-train data fetch|sbom|images)
```
Datasets are never committed; they regenerate from `data/sources.yaml` (hashes in `data/MANIFEST.sha256`).

## Status
All phases P0–P8 of the Developer Manual are done. Repository: `Jebin-05/verigate-fw` (private),
`v1.0.0` released with the wheel, both ONNX models, their cards, the hash manifest and the gas
report.

**No automation runs on this repository.** GitHub Actions, Dependabot and the pre-commit hooks
were removed on 2026-09-24 at the owner's request, and `main` is no longer protected. The gates
still exist as commands and must be run by hand before a commit or a release:

```bash
make lint typecheck test-all   # ruff · mypy strict · solhint · eslint · 331 unit + 72 contract tests
make test-integration          # after: make infra-up && make contracts-deploy-local && make models-register
make smoke                     # full compose stack from a clean state → APPROVE verdict
gitleaks detect --config .gitleaks.toml && .venv/bin/pip-audit   # secrets + dependency audit
```

Out of scope by decision: the public-testnet deployment (P0-10 / P7-02). The gated
`deploy-contracts.yml` workflow and the `arbitrumSepolia` network config are in place, so the run
is one dispatch away if it is ever wanted, but no testnet numbers are claimed anywhere.
Still open: P8-07 (fresh-machine rehearsal on a different computer). See `CHECKLIST.md`.
