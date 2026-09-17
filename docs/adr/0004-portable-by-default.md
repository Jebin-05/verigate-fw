# 0004 — Portable by default: one command runs the whole stack on any machine

**Status:** Accepted   **Date:** 2026-09-18

## Context
The project must be demonstrated on hardware we do not control (panel room PC, a reviewer's laptop, a fresh VM) and
reproduced by others for the paper. "Works on the author's laptop" is the most common FYP demo failure.

## Decision
- Every runtime component has a pinned Docker image (`infra/Dockerfile.app`, `.hardhat`, `.dashboard`; pinned base tags).
- `infra/docker-compose.yml` runs the full stack with `--profile app`; the LLM is an optional `--profile llm`.
- `make up`, `make smoke`, `make doctor` are the only commands a new machine needs; host Python/Node are for development only.
- No absolute paths in code or config; everything resolves relative to the repository root or a container path.
  Ports are overridable via `.env`. Line endings normalised via `.gitattributes`.
- CI has a `portability` job that builds all images and runs `scripts/smoke.sh` from a clean checkout on every PR.
- Datasets are regenerable (`data/sources.yaml` + scripts); models are committed; results carry `env.json`.

## Alternatives considered
- Host-only setup with a long README — rejected; drifts immediately.
- Kubernetes / Helm — rejected; overkill for a single-machine demo.

## Consequences
Image builds add ~3 min to CI. Windows users need WSL2 + Docker Desktop (documented). The smoke test doubles as the
first e2e test and as the pre-demo ritual on any new machine.
