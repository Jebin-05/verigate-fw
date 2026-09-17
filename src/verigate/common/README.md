| Module | Responsibility |
|---|---|
| `settings.py` | `pydantic-settings` model loaded from `.env`; the ONLY place env vars are read |
| `canonical.py` | `canonical_json(obj) -> bytes` (sorted keys, no whitespace, UTF-8) |
| `crypto.py` | Ed25519 keygen/sign/verify, SHA-256 helpers; thin wrappers around PyNaCl |
| `manifest.py` | `Manifest` pydantic model + `sign()` / `verify()` |
| `chain.py` | web3 client, contract bindings loaded from `contracts/deployments/<net>/addresses.json` |
| `ipfs.py` | `IpfsBackend` protocol; `KuboBackend`, `LocalCidBackend` (identical CIDv1 raw-leaves) |
| `merkle.py` | SHA-256 Merkle tree, domain-separated leaves, proof generation/verification |
| `logging.py` | structlog config; JSON in prod, pretty in dev |
