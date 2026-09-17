# Changelog
All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com), versioning: SemVer.

## [Unreleased]
### Added
- `verigate.common`: settings (pydantic-settings), structlog logging, canonical JSON (JCS subset, UTF-16 key order, no floats), Ed25519/SHA-256 crypto, SemVer + signed `Manifest` model, SHA-256 Merkle tree with domain-separated leaves; golden vectors under `tests/fixtures/` (P1-01..P1-05).
- Repository scaffold, tooling, CI/CD, developer manual (P0).
- Toolchain bootstrap: contracts + dashboard lockfiles, Vite react-ts dashboard shell with eslint/prettier, MIT licence, package sanity test (P0-06/07/08/12/15).
- Portability layer: full-stack compose profiles, pinned images, `make up/smoke/doctor`, CI portability job (ADR-0004).
