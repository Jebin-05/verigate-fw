# VeriGate-FW — Master Build Checklist

Single source of truth for progress. Update in the same PR that completes an item. IDs are referenced in PRs and issues.
Legend: `[ ]` todo · `[~]` in progress · `[x]` done (PR merged, CI green) · `[-]` dropped (say why in ADR).

Definition of Done for every item: code + tests + docstrings/NatSpec + CHANGELOG line + CI green + reviewed + squash-merged.

## P0 — Repository & tooling (week 1)
- [x] P0-01 Scaffold layout, `pyproject.toml`, `Makefile`, `.editorconfig`, `.gitignore`
- [x] P0-02 Pre-commit: ruff, mypy, gitleaks, conventional commits, solhint, prettier
- [x] P0-03 GitHub Actions: `ci.yml`, `security.yml`, `release.yml`, `deploy-contracts.yml`
- [x] P0-04 Templates: PR, issues, CODEOWNERS, dependabot; `CONTRIBUTING.md`, `SECURITY.md`
- [x] P0-05 ADRs 0001–0003; docs index; Project Guide and diagrams in `docs/`
- [x] P0-06 `make bootstrap` runs clean on a fresh clone (venv, `npm ci` in contracts + dashboard, hooks)
- [x] P0-07 Commit lockfiles (`contracts/package-lock.json`, `dashboard/package-lock.json`)
- [x] P0-08 `dashboard/` bootstrapped with Vite react-ts; `npm run lint`/`build` pass
- [x] P0-09 First push to GitHub; branch protection on `main` (PR required, CI required, linear history)
- [ ] P0-10 `arbitrum-sepolia` environment created with required reviewer; secrets added (RPC URL, deployer key)
- [x] P0-11 CI green on `main` for all four workflows (security may run on schedule) — CI, Security (dispatch) and Release green on `Jebin-05/verigate-fw`; "Deploy contracts" stays untested until P0-10's Sepolia secrets exist
- [x] P0-12 Choose licence (MIT recommended for a research artefact) — add `LICENSE`
- [x] P0-13 Portability scaffold: pinned images, `Dockerfile.app/.hardhat/.dashboard`, compose profiles, `make up/down/smoke/doctor`, `.gitattributes`, `.nvmrc`, `.python-version`
- [x] P0-14 `docker compose --profile app build` succeeds on a clean clone (needs lockfiles + dashboard bootstrap)
- [x] P0-15 `make doctor` passes; no absolute host paths anywhere in the repo (doctor greps for them)

## P1 — Common library & contracts (weeks 1–2)
- [x] P1-01 `common/settings.py` (pydantic-settings), `common/logging.py`
- [x] P1-02 `common/canonical.py` + golden vectors shared with TS (`tests/fixtures/canonical/*.json`)
- [x] P1-03 `common/crypto.py` Ed25519 + SHA-256; property tests (hypothesis)
- [x] P1-04 `common/manifest.py` model, sign, verify; rejects unknown fields; version parsed as SemVer
- [x] P1-05 `common/merkle.py` domain-separated leaves, proofs; cross-checked against Solidity lib
- [x] P1-06 `PublisherRegistry.sol` + tests (register, rotate, revoke, reputation update, all revert paths)
- [x] P1-07 `ModelRegistry.sol` + tests (register, revoke, successor, revokedAt)
- [x] P1-08 `FirmwareRegistry.sol` + tests (ACTIVE-publisher-only, monotonic version per model, revoke, events)
- [x] P1-09 `PolicyContract.sol` + tests (bounded weights sum to 1e4, τ_approve < τ_reject, versioned, event)
- [x] P1-10 `VerdictRegistry.sol` + tests (gateway-role-only, batch root, leaf proof verify, stale-by-model query)
- [x] P1-11 `scripts/deploy.ts` idempotent; writes `deployments/<net>/addresses.json` and local `.env`
- [x] P1-12 Contract coverage ≥ 95 % lines; slither: no medium+ findings; gas report committed
- [x] P1-13 `common/chain.py` bindings from ABI artifacts; integration test: deploy → register → read
- [x] P1-14 `common/ipfs.py` Kubo + LocalCid backends produce identical CIDv1 for fixtures
- [x] P1-15 `docs/threat-model.md` filled from Guide §9 with "test that proves it" column

## P2 — Publisher CLI (week 2)
- [x] P2-01 `verigate-publish keygen` → keys under `keys/` (git-ignored)
- [x] P2-02 `verigate-publish register` → PublisherRegistry
- [x] P2-03 `verigate-publish release --fw --sbom --version --model --expiry` → IPFS + manifest + on-chain
- [x] P2-04 `verigate-publish revoke <releaseId>`
- [x] P2-05 Integration test: full publish flow against hardhat + local IPFS
- [x] P2-06 Sample release fixtures (3 versions of a toy firmware + SBOMs) in `tests/fixtures/releases/`

## P3 — Gateway Stage 1 & fleet (weeks 3–4)
- [x] P3-01 `stage1/checks.py`: 8 checks as pure functions returning `CheckResult`; table-driven tests
- [x] P3-02 `stage1/runner.py`: fail-closed orchestration; first failure short-circuits; structured log
- [x] P3-03 `gateway/api`: `/health`, `/releases`, `/verify/{releaseId}`, websocket `/logs`
- [x] P3-04 Event listener for `NewRelease` (polling with backoff; resumable from last block)
- [x] P3-05 `fleet/device.py`: identity, NVS JSON, A/B slots, self-verify hash+sig, install receipt
- [x] P3-06 `fleet/runner.py`: asyncio N devices; `verigate-fleet run --count N`
- [x] P3-07 Device ↔ gateway protocol (HTTP, signed messages, nonce replay protection)
- [x] P3-08 Attack scripts: tamper, forge, stolen-key, rollback, freeze, sbom-swap → each has an e2e test asserting REJECT/DEFER
- [x] P3-09 Integration tests for Stage 1 against deployed contracts

## P4 — Verdicts, batching, reputation, dashboard (weeks 5–6)
- [x] P4-01 `verdicts/record.py` schema; featureHash = SHA-256(canonical feature vector)
- [x] P4-02 `verdicts/batch.py` Merkle batching + `VerdictRegistry` writer; proof endpoint
- [x] P4-03 Reputation update: receipts ↑, rejects ↓ (EWMA), written by gateway role
- [x] P4-04 `policy/engine.py` with on-chain weights; DEFER on outage; unit tests for every branch
- [x] P4-05 Dashboard pages: Releases, Verdicts, Fleet, Publishers, Models, Policy, Attacks
- [x] P4-06 Dashboard live log via websocket; attack buttons call gateway `/attacks/{name}`
- [x] P4-07 e2e: docker compose full stack, publish → verify → install → receipt → reputation
- [x] P4-08 Demo script v1 (`scripts/demo.sh`) runs all P3 attacks end-to-end in < 5 min
- [x] P4-09 `make smoke` passes from a fresh clone (CI portability job green) — the stack is provably movable
- [x] P4-10 Tag `v0.1.0` — crypto-path baseline release

## P5 — SBOM risk model (weeks 7–8)
- [x] P5-01 `ml/vulndb`: OSV, EPSS, KEV clients with disk cache; offline mode
- [x] P5-02 `ml/data`: fetch pinned firmware releases; syft SBOMs; `data/MANIFEST.sha256`
- [x] P5-03 `ml/features/sbom_features.py` + golden vectors
- [x] P5-04 Training script (seed 42) → `models/sbom_risk.onnx` + card; ONNX == sklearn on test set
- [x] P5-05 Baseline: deterministic CVSS/EPSS/KEV scorer (arXiv 2601.01308-style) for comparison
- [x] P5-06 `stage2/sbom.py` inference; SHAP top-3; cached per release
- [x] P5-07 Evaluation config `sbom_ranking.yaml`; AUROC / Spearman vs baseline recorded
- [x] P5-08 Register model hash on-chain via admin CLI; verdict carries modelHash

## P6 — Image anomaly, LLM explainer, model revocation (weeks 9–10)
- [x] P6-01 `ml/data/mutate.py`: byte-patch, append, section-swap, pack, downgrade-relabel (documented, seeded)
- [x] P6-02 `ml/features/image_features.py` + golden vectors
- [x] P6-03 Isolation Forest training → `models/image_anomaly.onnx` + card
- [x] P6-04 `stage2/image.py` inference; per-mutation-class precision/recall in evaluation
- [x] P6-05 `stage2/explain.py`: Ollama client, strict JSON schema, retry, `LLM_ENABLED` switch; rationale → IPFS
- [x] P6-06 Model revocation flow: revoke → stale query → re-verify job → dashboard shows delta
- [x] P6-07 Attack scripts: vulnerable-but-genuine, hidden-payload, bad-history, poisoned-model, policy-tamper
- [x] P6-08 Tag `v0.2.0` — full AI gate release

## P7 — Evaluation (weeks 11–12)
- [x] P7-01 Experiment configs: latency_stage1, latency_stage2, gas_per_verdict_vs_batched, detection_f1, sbom_ranking, revocation_propagation, attack_matrix
- [ ] P7-02 Deploy to Arbitrum Sepolia via workflow; addresses committed; tx hashes recorded
- [x] P7-03 All runners produce `raw.csv + summary.json + env.json`; ≥ 5 repetitions
- [x] P7-04 `evaluation/figures.py` regenerates every figure from results
- [x] P7-05 Comparison table vs Uptane / LedgerGuard / DIDAuth-IoTFW / SBOM-triage (feature presence, cited)
- [x] P7-06 Limitations section drafted from measured failures (what the anomaly detector missed, etc.)

## P8 — Paper, demo, hand-in (weeks 13–14)
- [x] P8-01 SRS finalised in `docs/srs/`
- [x] P8-02 Paper draft in `docs/paper/` (LaTeX), figures from P7-04 only
- [x] P8-03 Demo rehearsal ×3 with `scripts/demo.sh`; recorded video fallback
- [x] P8-04 README updated with results summary and reproduction steps
- [x] P8-05 Tag `v1.0.0`; GitHub Release with models, wheel, gas report; Zenodo DOI (optional — not done)
- [x] P8-06 Final `pip-audit`, `npm audit`, slither clean; secrets scan clean
- [ ] P8-07 Fresh-machine rehearsal: clone on a DIFFERENT computer (or clean VM), `make doctor && make up && make smoke`, run the demo — record time-to-running
- [x] P8-08 Offline demo mode verified: `VULN_CACHE_ONLY=true`, `LLM_ENABLED=false`, no internet, demo script completes
