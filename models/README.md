Exported ONNX models are committed here (each < 2 MB) together with:
- `<name>.card.md` — model card: purpose, features, training data hash, seed, metrics, limitations
- `MANIFEST.sha256` — `sha256sum *.onnx`; the hash in this file is what gets registered in ModelRegistry

Procedure to ship a new model version: `make train` → review card → `make models-hash` → PR → after merge, admin
registers the hash on-chain (`verigate-admin register-model --file models/<name>.onnx`). Old hash is NOT deleted; it may be revoked.
