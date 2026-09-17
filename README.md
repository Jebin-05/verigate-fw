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
