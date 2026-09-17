One file per contract, in this order of dependency:

1. `PublisherRegistry.sol` — publisher DID → Ed25519 pubkey, status, rotation, reputation
2. `ModelRegistry.sol`     — modelHash → status, successor, revokedAt
3. `FirmwareRegistry.sol`  — releaseId → manifest record (depends on PublisherRegistry)
4. `PolicyContract.sol`    — weights, thresholds, version, changedBy
5. `VerdictRegistry.sol`   — batchId → Merkle root, per-verdict leaves (depends on ModelRegistry)

Shared: `libraries/MerkleLeaf.sol`, `interfaces/I*.sol`, `access/Roles.sol` (OpenZeppelin AccessControl).
Rules: custom errors not revert strings · events on every state change · NatSpec on every public item ·
no `tx.origin` · checks-effects-interactions · storage layout documented at top of each file.
