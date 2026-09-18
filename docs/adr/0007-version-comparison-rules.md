# 0007 — Version comparison: strict SemVer triple, no pre-release, packed uint96 on-chain

**Status:** Accepted   **Date:** 2026-09-18
**Deciders:** project author

## Context
Rollback protection (Stage-1 #4) and the registry's monotonic-version rule need one unambiguous
ordering shared by Python, Solidity and TypeScript. Full SemVer 2.0 pre-release ordering
(`1.0.0-rc.1 < 1.0.0`) is easy to get subtly wrong across three languages.

## Decision
- A release version is exactly `MAJOR.MINOR.PATCH`, each a `uint32`, no leading zeros, no
  pre-release or build metadata (`common/manifest.py::SemVer`, regex-validated).
- Ordering is lexicographic on the triple. On-chain the triple is packed as
  `major << 64 | minor << 32 | patch` (`FirmwareRegistry.packVersion`) so a single integer compare
  is the same order.
- `FirmwareRegistry.register` requires the packed version to be strictly greater than the
  publisher's last one for that device model; revoking a release does not free its number.
- A device installs only if `manifest.version > installedVersion`; equal is a rollback.

## Alternatives considered
- Full SemVer with pre-release tags — rejected: three implementations of a tricky comparison for
  no demo or evaluation benefit.
- Monotonic integer build numbers — rejected: less readable in a manifest and in the paper.

## Consequences
Release candidates must use a distinct device-model string (e.g. `demo-device-rc`) or a patch
bump. Property tests (`tests/unit/common/test_manifest.py`) and Hardhat tests
(`FirmwareRegistry.test.ts`) pin the ordering on both sides.
