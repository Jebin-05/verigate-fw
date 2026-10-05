# Comparison with the closest prior systems (P7-05)

Feature presence only — no performance numbers are claimed for other systems. "●" = present as
described in the cited source, "◐" = partial or differently scoped, "○" = absent or not described, "?" = not assessed (the source was not checked for this row).
Every VeriGate-FW cell points at the code or the measured result that backs it.

| Feature | Uptane / TUF [1, 2] | FOTB [3] | Baza et al. [4] | DIDAuth-IoTFW [5] | LedgerGuard [6] | SBOM triage [7] | **VeriGate-FW** |
|---|---|---|---|---|---|---|---|
| Signed metadata / manifest, roles, key rotation | ● | ◐ | ◐ | ● (VCs, DIDs) | ● | ○ | ● manifest signed over canonical JSON, DID-bound keys, rotation + revocation on-chain (`contracts/PublisherRegistry.sol`, ADR-0001) |
| Firmware fingerprint + revocation on a ledger | ○ (repositories) | ● | ● | ● | ● | ○ | ● `FirmwareRegistry` (release id = manifest hash, monotonic versions, revoke) |
| Content-addressed artefact storage (IPFS) | ○ | ● | ● | ● | ● | ○ | ● CIDv1 byte-identical to Kubo (`common/ipfs.py`) |
| Rollback / freeze protection | ● | ◐ | ○ | ◐ | ◐ | ○ | ● Stage 1 #4 (device-side monotonic version) and #5 (expiry → DEFER + alert) |
| SBOM carried with the release and checked | ○ | ○ | ○ | ○ | ● | ● (generated) | ● SBOM hash in the signed manifest (Stage 1 #6), CycloneDX 1.5 |
| Vulnerability-aware risk score (CVSS / EPSS / KEV) | ○ | ○ | ○ | ○ | ○ | ● | ● baseline + learned `sbom_risk` model with temporal split (`models/sbom_risk.card.md`, `evaluation/results/sbom_ranking`) |
| Binary anomaly detection on the image | ○ | ○ | ○ | ○ | ○ | ○ | ● `image_anomaly` IsolationForest, per-mutation metrics (`evaluation/results/detection_f1`); plus Stage-1 check #9 (release delta vs the last approved image: 120/120 patches, 97/97 swaps on an unchanged base, 0/165 benign; `release_delta`) |
| Three-outcome decision (approve / defer / reject) with on-chain policy | ○ | ○ | ○ | ○ | ○ | ○ (score only) | ● `PolicyContract`, τ_approve / τ_reject, ADR-0008; DEFER on any dependency outage |
| Decision anchored on the ledger | ○ | ◐ (update record) | ◐ | ◐ (credential presentation) | ● (signed receipts, Merkle-rooted) | ○ | ● verdict record (scores, feature hash, model hashes, gateway signature) as a Merkle leaf, `commitBatch` per batch |
| Batched anchoring (one tx per N verdicts) | ○ | ○ | ○ | ○ | ◐ (Merkle-rooted accountability; batching granularity per its docs) | ○ | ● measured: gas per verdict 209 642 → 1 048 at 200/batch (`evaluation/results/gas_per_verdict_vs_batched`) |
| Analysis model as a registered, revocable artefact | ○ | ○ | ○ | ○ | ○ | ○ | ● `ModelRegistry`, `staleByModel`, gateway replay under the successor (ADR-0009, `evaluation/results/revocation_propagation`) |
| Human-readable rationale, kept out of the decision | ○ | ○ | ○ | ○ | ○ | ○ | ● LLM explain-only, CID in the verdict (ADR-0002) |
| Publisher reputation feeding the decision | ○ | ○ | ○ | ○ | ○ | ○ | ● EWMA from receipts / release-level rejects (ADR-0006) |
| Device verifies against the ledger itself (resilient to a compromised gateway) | ● (full verification on ECUs) | ? | ? | ● (device-side VC + revocation checks on ESP32) | ? | ○ | ● device reads publisher key + release record from the chain, refuses unregistered / withdrawn / revoked-key pushes (`fleet/device.py`, `rogue-gateway` 5/5); a rogue gateway can still approve a registered release (limitations §14) |
| Emulated fleet, attack scripts, reproducible evaluation | ◐ (reference impl.) | ○ | ○ | ◐ (hardware testbed) | ● (emulated devices, receipts) | ◐ (firmware corpus) | ● thirteen scripted attacks with measured pass rates (`evaluation/results/attack_matrix`) |
| Real hardware validation | ● (deployments) | ○ | ○ | ● | ○ | ○ | ○ — software emulation only (stated scope) |

## References

1. J. Samuel, N. Mathewson, J. Cappos, R. Dingledine, "Survivable Key Compromise in Software Update Systems", ACM CCS 2010 (The Update Framework).
2. T. K. Kuppusamy, A. Brown, S. Awwad, D. McCoy, R. Bielawski, C. Mott, S. Lauzon, A. Weimerskirch, J. Cappos, "Uptane: Securing Software Updates for Automobiles", ESCAR Europe 2016; Uptane Standard, https://uptane.org.
3. A. Yohan, N.-W. Lo, "An Over-the-Blockchain Firmware Update Framework for IoT Devices", IEEE DSC 2018 (FOTB).
4. M. Baza, M. Nabil, N. Lasla, K. Fidan, M. Mahmoud, M. Abdallah, "Blockchain-based Firmware Update Scheme Tailored for Autonomous Vehicles", IEEE WCNC 2019.
5. W. M. A. B. Wijesundara, J.-S. Lee, E. Aloupogianni, D. Tith, H. Suzuki, T. Obi, "DIDAuth-IoTFW: Decentralized firmware authentication for smart home IoT devices using verifiable credentials", Internet of Things 34 (2025) 101788.
6. LedgerGuard — "permissioned-DLT firmware governance, artifact anchoring, staged rollout control, and Merkle-rooted update accountability", https://github.com/ajalkhodair-spec/ledgerguard (Hyperledger Besu, Apache-2.0; Zenodo DOI 10.5281/zenodo.22387057), 2026.
7. A. Tolay, "Automated SBOM-Driven Vulnerability Triage for IoT Firmware: A Lightweight Pipeline for Risk Prioritization", arXiv:2601.01308, January 2026.

Cells for [1]–[7] were filled from the cited documents' own descriptions (abstracts, standard text,
repository README); where a source does not describe a feature it is marked "○", which is not a
claim that the feature is impossible in that system.
