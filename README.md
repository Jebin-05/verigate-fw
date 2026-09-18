# VeriGate-FW

Verifiable AI-gated firmware updates for IoT devices using blockchain (Arbitrum L2) and IPFS.
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
make llm-pull       # optional: LLM explainer (~2 GB, needs ~12 GB RAM)
```
Works on Linux, macOS (Docker Desktop) and Windows (WSL2 + Docker Desktop). No Python/Node on the host required.

## Develop (host mode — hot reload)

```bash
make bootstrap      # venv, python deps, node deps, pre-commit hooks
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
Measured on the development laptop (i7-1255U, no GPU): 53 s with the LLM explainer off (the
compose default — `--profile llm` adds Ollama), 348 s with a CPU-only `qwen2.5:3b-instruct`
explaining each release-level verdict (~60–120 s per rationale; device polls never wait for it).
Dashboard: Releases · Verdicts (Merkle proof, on-chain `verifyLeaf` via direct RPC) · Fleet ·
Publishers · Models · Policy · Attacks (buttons run `verigate-attack` through the gateway) with a
live websocket log. Attack scripts: `verigate-attack run <name|all>` — Stage 1: tamper, forge, stolen-key,
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
`LLM_ENABLED` / `OLLAMA_URL` control the explain-only rationale (ADR-0002). The model cards under
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
| `.github/` | CI/CD workflows, templates, CODEOWNERS |

## Status
See `CHECKLIST.md`.
