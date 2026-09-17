# 0001 — Sign the manifest, not the bare firmware hash

**Status:** Accepted   **Date:** 2026-09-17

## Context
Most prior work signs only `SHA-256(firmware)`. Version, expiry and SBOM hash then live unsigned on-chain,
so anyone able to write to the registry can re-list a validly signed old image under a new version (signed rollback).

## Decision
The publisher signs the canonical JSON of the full manifest `{firmwareHash, sbomHash, version, deviceModel, expiry, cids, publisherDid}`.
`FirmwareRegistry` stores `keccak256(canonicalManifest)` and the signature; the gateway verifies the signature over the
manifest it fetched from IPFS and checks the hash matches the on-chain record.

## Alternatives considered
- Sign hash only — rejected (rollback).
- Sign hash‖version — rejected; expiry and SBOM hash would still be unprotected.

## Consequences
Manifest must be canonicalised identically in Python and TypeScript; golden test vectors shared in `tests/fixtures/`.
