# Threat model

Mirrors Project Guide §9. Every row names the mitigation and the test that proves it. Tests marked
*(P3)* / *(P6)* are the end-to-end attack tests scheduled for those phases; contract-level tests
already exist for the on-chain half of each mitigation.

**Assets:** firmware image, SBOM, signed manifest, publisher signing key, device installed-version
counter, AI model files (ONNX), policy parameters, verdict records, gateway signing key.

**Attacker capabilities considered:** read/write access to IPFS content and the network path
(tamper, replay, block), a leaked publisher key, a publisher with a poor track record, a rogue
operator with a normal account (no admin key), a buggy or poisoned AI model, an outage of the
chain RPC or vulnerability feeds. Out of scope: compromise of the admin key or the Hardhat/Arbitrum
node itself, side channels on the emulated devices, and well-crafted malicious builds with normal
structure (Guide §6.2 scope statement).

| # | Asset | Attacker capability | Attack | Mitigation | Test that proves it |
|---|---|---|---|---|---|
| 1 | Firmware image | Modify bytes on IPFS / in transit | **Tampering** | Stage 1 #1: `SHA-256(firmware) == manifest.firmwareHash`; IPFS `get` also re-hashes against the CID (`common/ipfs.py`) | `tests/unit/common/test_ipfs_cid.py::test_local_backend_fails_closed`; `tests/e2e/test_attack_tamper.py` *(P3)* |
| 2 | Manifest | Sign with own key, claim to be the publisher | **Forgery** | Stage 1 #2: Ed25519 signature over canonical manifest under the key in `PublisherRegistry` (ADR-0001) | `tests/unit/common/test_manifest.py::test_verify_fails_closed`; `contracts/test/Crypto.test.ts`; `tests/e2e/test_attack_forge.py` *(P3)* |
| 3 | Publisher key | Use a leaked key after revocation | **Stolen key** | Stage 1 #3 + `PublisherRegistry.revoke` strips `PUBLISHER_ROLE`; `FirmwareRegistry.register` rejects non-ACTIVE | `contracts/test/FirmwareRegistry.test.ts` ("rejects a revoked publisher"); `contracts/test/PublisherRegistry.test.ts` (revoke); `tests/e2e/test_attack_stolen_key.py` *(P3)* |
| 4 | Installed-version counter | Replay a genuine old release | **Rollback** | Stage 1 #4 (`version > installedVersion`, device-side) and on-chain monotonic version per `(publisher, deviceModel)` | `contracts/test/FirmwareRegistry.test.ts` ("strictly increasing versions", "revoked release does not free its version"); `tests/e2e/test_attack_rollback.py` *(P3)* |
| 5 | Update channel | Block the device from seeing new releases | **Freeze** | Stage 1 #5: `manifest.expiry > now` → DEFER + alert when the only known manifest is expired; `register` refuses already-expired manifests | `contracts/test/FirmwareRegistry.test.ts` ("past expiry"); `tests/e2e/test_attack_freeze.py` *(P3)* |
| 6 | SBOM | Pair a clean SBOM with a dirty image | **SBOM swap** | Stage 1 #6: `SHA-256(sbom) == manifest.sbomHash`; sbomHash is inside the signed manifest | `tests/unit/common/test_manifest.py::test_verify_fails_closed` (tampered field); `tests/e2e/test_attack_sbom_swap.py` *(P3)* |
| 7 | Release record | Keep installing a withdrawn release | **Known-bad release** | Stage 1 #7: `FirmwareRegistry.isRevoked`, `PublisherRegistry.isActive` | `contracts/test/FirmwareRegistry.test.ts` (revoke suite); `tests/unit/gateway/test_stage1_checks.py` *(P3)* |
| 8 | AI model | Verdicts from a faulty model stay trusted | **Poisoned / buggy model** | Stage 1 #8 + `ModelRegistry.revoke` → `VerdictRegistry.staleByModel` → re-verify with successor (Novelty 2) | `contracts/test/ModelRegistry.test.ts`; `contracts/test/VerdictRegistry.test.ts` ("staleByModel"); `tests/e2e/test_attack_poisoned_model.py` *(P6)* |
| 9 | Device fleet | Ship genuine firmware containing a KEV-listed library | **Vulnerable-but-genuine** | Stage 2 `r_sbom` (OSV/EPSS/KEV features) → policy REJECT/DEFER | `tests/unit/ml/test_sbom_features.py` *(P5)*; `tests/e2e/test_attack_vulnerable_genuine.py` *(P6)* |
| 10 | Firmware image | Append packed payload to a genuine build | **Hidden payload** | Stage 2 `r_img` (entropy, appended bytes) → DEFER for review | `tests/unit/ml/test_image_features.py` *(P6)*; `tests/e2e/test_attack_hidden_payload.py` *(P6)* |
| 11 | Reputation | Publisher with many rejections ships a borderline release | **Bad history** | Reputation term `w3·(1 − reputation)`; only `GATEWAY_ROLE` may write it | `contracts/test/PublisherRegistry.test.ts` (setReputation); `tests/e2e/test_attack_bad_history.py` *(P6)* |
| 12 | Policy | Operator lowers thresholds quietly | **Policy tampering** | Weights/thresholds only via `PolicyContract.setPolicy` (ADMIN_ROLE); every change is an event with old/new | `contracts/test/PolicyContract.test.ts` ("rejects non-admins", "emits old and new policy"); `tests/e2e/test_attack_policy_tamper.py` *(P6)* |
| 13 | Verdict record | Claim a verdict that was never committed | **Verdict forgery** | Merkle leaf domain separation + `verifyLeaf` against the committed root; `GATEWAY_ROLE` only | `contracts/test/MerkleLeaf.test.ts`; `contracts/test/VerdictRegistry.test.ts`; `tests/unit/common/test_merkle.py` |
| 14 | Any decision | Chain RPC / OSV.dev unreachable | **Outage** | Fail-closed: `ChainError`/`IpfsError` → DEFER, never APPROVE | `tests/unit/common/test_chain_bindings.py::test_dependency_down_is_a_chain_error`; `tests/unit/common/test_ipfs_cid.py::test_kubo_backend_unavailable`; `tests/unit/gateway/test_policy_engine.py` *(P4)* |
| 15 | Gateway | Compromised gateway pushes unsigned code | **Rogue gateway** | Defence in depth: the device re-verifies hash + signature before switching slots | `tests/unit/fleet/test_device.py` *(P3)* |
| 16 | Device ↔ gateway messages | Replay a captured install/receipt message | **Replay** | Signed messages with nonce + timestamp window | `tests/unit/fleet/test_protocol.py` *(P3)* |

Residual risks are collected in the paper's limitations section from measured failures (P7-06).
