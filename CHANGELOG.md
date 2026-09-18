# Changelog
All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com), versioning: SemVer.

## [Unreleased]
### Added
- Stage 1: eight pure, fail-closed checks (`gateway/stage1/checks.py`) and the short-circuiting runner with structured logs; `expiry` failure yields DEFER (freeze), everything else REJECT; table-driven tests with missing/malformed/boundary/dependency-down rows (P3-01, P3-02).
- `verigate-publish` CLI (keygen / register / release / revoke) with JSON output and idempotent steps; three toy firmware release fixtures (ELF/ARM header, CycloneDX SBOMs) under `tests/fixtures/releases/`; publish-flow integration test (P2-01..P2-06).
### Fixed
- Module-level loggers now follow `configure_logging()` (were bound to structlog's default stdout printer at import time).
- Contracts: `PublisherRegistry`, `ModelRegistry`, `FirmwareRegistry`, `PolicyContract`, `VerdictRegistry` + `MerkleLeaf` library (OpenZeppelin 5 AccessControl, custom errors, NatSpec); Hardhat tests at 100 % coverage, slither clean at medium+, measured gas report; idempotent `deploy.ts` writing `deployments/<net>/addresses.json` and `.env` (P1-06..P1-12).
- `common/chain.py` typed web3 bindings with packaged ABIs (`scripts/sync_abi.py`) and decoded custom errors; `common/ipfs.py` Kubo + LocalCid backends with byte-identical CIDv1 (raw leaves + single-level UnixFS); integration tests; threat model table (P1-13..P1-15).
- `verigate.common`: settings (pydantic-settings), structlog logging, canonical JSON (JCS subset, UTF-16 key order, no floats), Ed25519/SHA-256 crypto, SemVer + signed `Manifest` model, SHA-256 Merkle tree with domain-separated leaves; golden vectors under `tests/fixtures/` (P1-01..P1-05).
- Repository scaffold, tooling, CI/CD, developer manual (P0).
- Toolchain bootstrap: contracts + dashboard lockfiles, Vite react-ts dashboard shell with eslint/prettier, MIT licence, package sanity test (P0-06/07/08/12/15).
- Portability layer: full-stack compose profiles, pinned images, `make up/smoke/doctor`, CI portability job (ADR-0004).
