# VeriGate-FW — Software Requirements Specification

**Version 1.0 · 2026-09-18 · status: final (P8-01)**
Applies to VeriGate-FW v1.0.0. Structure follows IEEE 830 / ISO 29148 in spirit; every
requirement carries an identifier and a *verification* column naming the test, code or measured
result that demonstrates it. Requirements use *shall*; design notes use *is*.

## 1. Introduction

### 1.1 Purpose
This SRS states what VeriGate-FW does so that the panel, reviewers and future maintainers can
check each claim against the code and the measured results. It was finalised after the build
(P0–P7), so it specifies the system as delivered, not a plan.

### 1.2 Scope
VeriGate-FW verifies firmware updates for a fleet of IoT devices before they are installed. A
publisher signs a **manifest** (hashes of firmware and SBOM, version, expiry, IPFS CIDs) and
registers its hash on a blockchain; artefacts live on IPFS. A **gateway** runs a two-stage gate for
every (release, device) pair: Stage 1 is eight deterministic cryptographic/registry checks that can
only reject or defer; Stage 2 is an AI risk score (SBOM vulnerability model + firmware image
anomaly model + publisher reputation) combined by an on-chain policy into APPROVE / DEFER / REJECT.
Each verdict names the models that produced it and is anchored on-chain in Merkle batches; models
are registry artefacts that can be revoked, which replays their verdicts. A local LLM writes a
human-readable rationale that never influences the decision.

Software-only: devices are emulated; the chain is a local Hardhat node (Arbitrum Sepolia optional).

### 1.3 Definitions
| term | meaning |
|---|---|
| release | one firmware version for one device model, identified by `releaseId = keccak256(canonical manifest)` |
| manifest | signed JSON: `firmwareHash`, `sbomHash`, `version` (SemVer), `deviceModel`, `expiry`, `cids`, `publisherDid` |
| Stage 1 | the eight fail-closed checks (`gateway/stage1/checks.py`) |
| Stage 2 | `r_sbom`, `r_img` ∈ [0,1] from ONNX models plus reputation; `R = w_sbom·r_sbom + w_img·r_img + w_rep·(1−rep)` in basis points |
| verdict | APPROVE / DEFER / REJECT plus scores, feature hash, model hashes, gateway signature |
| batch | a Merkle tree of verdict leaves committed by `VerdictRegistry.commitBatch` |
| stale verdict | a verdict whose model hash has been revoked |
| bp | basis points, 10 000 = 1.0 (canonical JSON forbids floats) |

### 1.4 References
Project Guide (`docs/VeriGate-FW_Project_Guide.pdf`), Developer Manual v1.1
(`docs/VeriGate-FW_Developer_Manual.pdf`), ADR-0001…0009 (`docs/adr/`), threat model
(`docs/threat-model.md`), comparison (`docs/comparison.md`), limitations (`docs/limitations.md`),
evaluation results (`evaluation/results/`).

## 2. Overall description

### 2.1 Product perspective
```
publisher CLI ──(manifest, artefacts)──► IPFS (Kubo)            ┌─ dashboard (React)
      │                                     ▲                    │
      └──(register releaseId)──► chain ◄────┼── gateway (FastAPI) ┴─ emulated fleet (asyncio)
   PublisherRegistry · ModelRegistry · FirmwareRegistry · PolicyContract · VerdictRegistry
                                                    ▲
                                          admin CLI (models, policy, revocations)
```
Dependency direction inside the Python package: `common ← ml ← gateway`; `publisher`, `fleet`
and `attacks` depend on `common` only (Manual §4).

### 2.2 User classes
| actor | interface | privileges |
|---|---|---|
| Publisher | `verigate-publish` | PUBLISHER_ROLE: register / revoke own releases, rotate own key |
| Admin / operator | `verigate-admin`, dashboard | ADMIN_ROLE: register / revoke models, set policy, revoke publishers, grant gateway role |
| Gateway (service) | `verigate-gateway` | GATEWAY_ROLE: commit verdict batches, write reputation |
| Device (emulated) | signed HTTP protocol | none on-chain; TOFU-pinned Ed25519 key at the gateway |
| Auditor / reviewer | dashboard, chain RPC, `evaluation/` | read-only |

### 2.3 Operating environment
Python 3.11, Node 20, Docker Compose (Hardhat 2.29, Kubo 0.30, optional Ollama); Solidity 0.8.26
with OpenZeppelin 5; ONNX Runtime for inference. Reference machine: i7-1255U, 15 GB RAM, no GPU.

### 2.4 Constraints
C1 no secrets in the repository (only the public Hardhat test keys) · C2 the decision path is
deterministic and the LLM never touches `R` (ADR-0002) · C3 every reported number comes from a
file under `evaluation/results/` or a model card · C4 portable: `make up`, `make smoke`,
`make doctor` on any machine with Docker · C5 datasets are reproducible, never committed.

### 2.5 Assumptions
A1 the publisher's private key is held off-chain by the publisher · A2 the admin key is trusted
(policy and model governance) · A3 the local chain and IPFS node are reachable in normal
operation; outages are handled by deferring, not by approving · A4 devices can verify an
Ed25519 signature and a SHA-256 hash.

## 3. Functional requirements

Verification column: **U** unit test, **I** integration test (hardhat + IPFS), **E** e2e test
(running gateway), **C** Hardhat contract test, **M** measured result directory.

### 3.1 Publishing (FR-P)
| id | requirement | verification |
|---|---|---|
| FR-P1 | The publisher CLI shall produce a manifest whose canonical JSON (JCS subset, UTF-16 key order, no floats) is signed with the publisher's Ed25519 key; `releaseId` shall be the keccak256 of the unsigned canonical manifest. | U `tests/unit/common/test_manifest.py`, `test_canonical.py`; ADR-0001 |
| FR-P2 | Firmware, SBOM and signed manifest shall be stored on IPFS with CIDv1 (raw leaves / single-level UnixFS) identical to Kubo's. | U `test_ipfs_cid.py`, I `test_ipfs_parity.py` |
| FR-P3 | `verigate-publish release` shall be idempotent end to end (same inputs → same CIDs, `"status": "unchanged"`), print one JSON object and exit 1 with `{"error": …}` on failure. | I `test_publish_flow.py` |
| FR-P4 | `FirmwareRegistry.register` shall refuse a version not strictly greater than the publisher's last version for that device model, an expiry not in the future and callers without PUBLISHER_ROLE. | C `FirmwareRegistry.test.ts` |
| FR-P5 | A publisher shall be able to revoke its own release; a revoked release shall never be approved afterwards. | C, U `test_stage1_checks.py` (`registry_record`) |

### 3.2 Stage 1 — deterministic gate (FR-S1)
| id | requirement | verification |
|---|---|---|
| FR-S1.0 | Stage 1 shall consist of exactly these checks, run in order, short-circuiting on the first failure: firmware_hash, signature, publisher_active, version_monotonic, expiry, sbom_hash, registry_record, model_active. | U `test_stage1_runner.py` |
| FR-S1.1 | Each check shall be a pure function of its inputs (no I/O), so that a verdict can be reproduced from the recorded inputs. | U `test_stage1_checks.py` (table-driven, missing/malformed/boundary rows) |
| FR-S1.2 | Any failing check except `expiry` shall yield REJECT; a failed `expiry` shall yield DEFER and an alert. | U, E `test_attack_freeze.py` |
| FR-S1.3 | A dependency failure (chain RPC, IPFS) shall yield DEFER, never APPROVE. | U `test_service_verdicts.py`, `test_chain_bindings.py` |
| FR-S1.4 | The six Stage-1 attack scenarios (tamper, forge, stolen-key, rollback, freeze, sbom-swap) shall end in the verdict of the threat model with the named check. | E `tests/e2e/test_attack_*.py`; M `attack_matrix` (5/5 each) |

### 3.3 Stage 2 — AI risk gate (FR-S2)
| id | requirement | verification |
|---|---|---|
| FR-S2.1 | The SBOM scorer shall compute integer-quantised features from a CycloneDX SBOM using OSV, EPSS (dated snapshot) and KEV data from a disk cache with an offline mode, and produce `r_sbom` from an ONNX model whose hash is recorded. | U `tests/unit/ml/test_vulndb.py`, `test_train_sbom.py`, `tests/unit/gateway/test_stage2_sbom.py` |
| FR-S2.2 | The image scorer shall compute pure ELF/entropy features (including deltas versus the previous release) and produce a calibrated `r_img` from an ONNX IsolationForest. | U `test_train_image.py`, `test_image_mutate.py` |
| FR-S2.3 | Models shall run only as ONNX at inference; `make train` twice shall produce byte-identical files; each model ships a card stating its label, data, seed, metrics and limitations. | U (ONNX == sklearn, determinism) ; `models/*.card.md` |
| FR-S2.4 | The feature vector shall be committed to by `featureHash = SHA-256(canonical features)` in the verdict, and the top-3 SHAP attributions recorded. | U `test_verdict_record.py`, `test_stage2_sbom.py` |
| FR-S2.5 | The gate shall be usable without models (`NullScorer`: `r = 0`, decision from Stage 1 + reputation). | U `test_stage2_sbom.py::test_build_scorer_from_settings` |

### 3.4 Policy and reputation (FR-POL)
| id | requirement | verification |
|---|---|---|
| FR-POL1 | `PolicyContract` shall hold weights (bp, sum 10 000) and thresholds `τ_approve < τ_reject`; only ADMIN_ROLE may change them; every change shall emit the old and new policy and the sender. | C `PolicyContract.test.ts`; E `test_attack_policy_tamper.py` |
| FR-POL2 | The gateway shall compute `R` in integer basis points from the policy in force (cached per block) and decide APPROVE if `R < τ_approve`, REJECT if `R ≥ τ_reject`, else DEFER; a policy read failure shall yield DEFER. | U `test_policy_engine.py` |
| FR-POL3 | Publisher reputation shall move by an EWMA (α = 0.1): up on a signed install receipt, down on a release-level REJECT; only GATEWAY_ROLE may write it. | U `test_batch_reputation.py`; C `PublisherRegistry.test.ts`; ADR-0006 |
| FR-POL4 | The reputation term shall be able to move a borderline release from APPROVE to DEFER but never to REJECT on its own (`w_rep = 0.2 < τ_reject − τ_approve`… see ADR-0008). | E `test_attack_bad_history.py` |

### 3.5 Verdicts and anchoring (FR-V)
| id | requirement | verification |
|---|---|---|
| FR-V1 | A verdict record shall contain releaseId, deviceId, modelHashes, featureHash, r_sbom, r_img, reputation, R, verdict, rationaleCid, ts and an EIP-191 gateway signature over the unsigned record. | U `test_verdict_record.py` |
| FR-V2 | Verdicts shall be batched (size or time bound) into a SHA-256 Merkle tree with domain-separated leaves and committed with `commitBatch(root, count, modelHashes)`; the gateway shall serve a proof for any verdict id and the chain shall verify it (`verifyLeaf`). | U `test_batch_reputation.py`; C `VerdictRegistry.test.ts`, `MerkleLeaf`; I `test_verdict_batch_live.py`; E `test_full_stack.py`; ADR-0005 |
| FR-V3 | `commitBatch` shall refuse hashes that are not ACTIVE models and callers without GATEWAY_ROLE. | C; M `gas_per_verdict_vs_batched` (NOTE.md of the crashed run) |

### 3.6 Model lifecycle (FR-M)
| id | requirement | verification |
|---|---|---|
| FR-M1 | `ModelRegistry` shall register a model by SHA-256 hash and allow ADMIN_ROLE to revoke it naming an optional successor; `VerdictRegistry.staleByModel` shall list the batches that used a revoked model. | C `ModelRegistry.test.ts`, `VerdictRegistry.test.ts` |
| FR-M2 | A configured model that is not ACTIVE shall fail Stage 1 (`model_active`) — the gate fails closed. | U `test_revocation.py::test_revocation_without_successor_stays_closed` |
| FR-M3 | The gateway shall detect a revocation, locate the successor by hash under `MODELS_DIR`, swap only the affected scorer slot, re-verify every stale (release, device) pair through the normal batcher and persist a before/after report. | U `test_revocation.py`; E `test_attack_poisoned_model.py`; M `revocation_propagation`; ADR-0009 |

### 3.7 Explainer (FR-X)
| id | requirement | verification |
|---|---|---|
| FR-X1 | The explainer shall ask a local Ollama model for a JSON object `{summary, top_risks[≤5], recommended_action ∈ {install, review, block}}` using a schema-constrained response, validate it, retry once and pin it to IPFS; its CID shall be stored in the verdict. | U `test_explain.py` |
| FR-X2 | The explainer's output shall never be read by the decision path; `LLM_ENABLED=false`, an unreachable Ollama or a malformed answer shall degrade to "no rationale", never to "no verdict". | U `test_explain.py`; code review of `service.verify()`; ADR-0002 |
| FR-X3 | Device-level verifications shall never wait for the explainer. | U `test_explain.py::test_release_verify_waits_for_rationale_devices_do_not` |

### 3.8 Device protocol and fleet (FR-D)
| id | requirement | verification |
|---|---|---|
| FR-D1 | Devices shall authenticate to the gateway with Ed25519-signed messages carrying a nonce and a timestamp inside a window; the first key seen is pinned (TOFU); replays shall be refused. | U `tests/unit/common/test_protocol.py`, `test_service_api.py` |
| FR-D2 | A device shall re-verify the manifest and firmware hash itself before installing (defence in depth), install into an A/B slot, persist NVS state and send a signed install receipt. | U `tests/unit/fleet/test_device.py`, `test_runner.py`; E `test_full_stack.py` |
| FR-D3 | `verigate-fleet run` shall emulate N devices concurrently (asyncio) and report installs/receipts. | U `test_runner.py`; `scripts/demo.sh` |

### 3.9 Operator interfaces (FR-O)
| id | requirement | verification |
|---|---|---|
| FR-O1 | The gateway shall expose: `/health`, `/releases[...]`, `POST /verify/{id}[?device_id]`, `/verdicts`, `/verdicts/{id}/proof`, `/batches`, `POST /batches/flush`, `/policy`, `/publishers`, `/models`, `/devices`, device protocol endpoints, `/revocations`, `POST /revocations/check`, `/rationales/{cid}`, `/attacks`, `POST /attacks/{name}` and a websocket log. | U `test_service_api.py`, `test_service_verdicts.py`, `test_revocation.py`, `test_explain.py`; OpenAPI → `dashboard/src/api/schema.d.ts` |
| FR-O2 | The dashboard shall show releases, verdicts (with Merkle proof and on-chain `verifyLeaf` via direct RPC), fleet, publishers, models (with revocation before/after deltas), policy and attack buttons, plus the live log. | `dashboard/src/pages/*`; `npm run lint && tsc --noEmit && build` in CI |
| FR-O3 | `verigate-admin` shall register / revoke models, register every hash of `models/MANIFEST.sha256`, set policy, revoke publishers and grant the gateway role, printing JSON. | U `test_admin_cli.py` |
| FR-O4 | `verigate-attack run <name|all>` shall execute the eleven scenarios against the local emulated fleet only and print one JSON report per scenario with expected vs observed. | E `tests/e2e/`; M `attack_matrix` |

## 4. Non-functional requirements

| id | requirement | measured / verified |
|---|---|---|
| NFR-1 Fail closed | No path shall produce APPROVE on a failed check, an outage or a revoked model. | FR-S1.2/3, FR-M2; `attack_matrix` 11/11 |
| NFR-2 Determinism | Same inputs → same verdict; verdict reproducible from featureHash + model files. | ONNX byte-identity tests; ADR-0002 |
| NFR-3 Stage-1 latency | Deterministic gate ≤ 250 ms per verification on the reference machine. | `latency_stage1`: checks 3.3 ms, warm verify 89 ms, cold 98 ms (median) |
| NFR-4 Stage-2 latency | Full gate per device poll ≤ 500 ms once a release has been scored. | `latency_stage2`: 111 ms in-process, 216 ms over HTTP; cold scoring 115 + 104 ms |
| NFR-5 Explainer cost | Rationale generation shall not block device polls; cost stated. | 43–91 s per rationale on CPU (`latency_stage2/raw_llm.csv`) |
| NFR-6 Anchoring cost | Gas per verdict shall fall with batch size. | `gas_per_verdict_vs_batched`: 209 642 per batch, 1 048 per verdict at 200 |
| NFR-7 Revocation propagation | All stale device verdicts replayed within 30 s for a 50-device fleet. | 11.7 s + 2 s poll (`revocation_propagation`) |
| NFR-8 Test coverage | Python unit coverage ≥ 80 %, contracts 100 % statements. | 92 % / 100 % (`make test-all`) |
| NFR-9 Portability | `make up` from a clean clone reaches a verdict; `make smoke` in CI. | smoke 12 min cold (vulnerability fetch), demo 53 s warm |
| NFR-10 Security hygiene | No secrets in git; audits recorded. | `.gitleaks.toml`, `docs/security-audit.md` |
| NFR-11 Reproducibility | Seeds fixed; datasets regenerable from `data/sources.yaml`; results append-only with env.json. | `data/MANIFEST.sha256`, `evaluation/results/*/env.json` |
| NFR-12 Code quality | ruff (strict rule set) + mypy strict + solhint + eslint/prettier clean; Conventional Commits; PRs ≤ 400 lines. | pre-commit + CI |

## 5. External interfaces
- **CLI**: `verigate-publish`, `verigate-gateway`, `verigate-fleet`, `verigate-attack`,
  `verigate-train`, `verigate-admin` (all JSON output).
- **HTTP**: FastAPI, OpenAPI at `/openapi.json`; the dashboard's types are generated from it.
- **Contracts**: `contracts/contracts/interfaces/I*.sol` (NatSpec); ABIs packaged in
  `verigate.common.abi`.
- **Configuration**: environment variables read only in `common/settings.py`; documented in
  `.env.example`.

## 6. Traceability to the threat model
Rows 1–17 of `docs/threat-model.md` map to FR-S1.4 (rows 1–7), FR-M (row 8), FR-S2 (rows 9–10),
FR-POL3/4 (row 11), FR-POL1 (row 12), FR-V2 (row 13), FR-S1.3 (row 14), FR-P1 (row 15),
FR-D2 (row 16), FR-D1 (row 17).

## 7. Out of scope (stated)
Real hardware devices; detection of well-crafted malicious builds that preserve size, entropy
and layout (see `docs/limitations.md` §1); KEV-driven decisions on the current corpus (§4);
production key management and HSMs; a public IPFS pinning strategy.
