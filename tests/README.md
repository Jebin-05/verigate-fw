```
tests/
  unit/          pure-python, < 1 s each, no network, no infra   (runs on every commit)
  integration/   needs `make infra-up` + deploy + `make models-register`  (`make test-integration`)
  e2e/           docker compose full stack + fleet + attacks      (runs nightly / before release)
  fixtures/      golden files: sample firmware, sboms, manifests, feature vectors, keys (test keys only)
  conftest.py    shared fixtures: settings override, in-memory IPFS, deployed contracts
```
Naming: `test_<module>_<behaviour>.py`; one behaviour per test; arrange-act-assert; use hypothesis for
canonical JSON, Merkle, and version comparison properties.
