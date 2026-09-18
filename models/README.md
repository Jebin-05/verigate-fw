Exported ONNX models are committed here (each < 2 MB) together with:
- `<name>.card.md` — model card: purpose, features, training data hash, seed, metrics, limitations
- `MANIFEST.sha256` — `sha256sum *.onnx`; the hash in this file is what gets registered in ModelRegistry

Procedure to ship a new model version: `make train` → review card → `make models-hash` → PR → after merge, admin
registers the hash on-chain (`verigate-admin register-model --file models/<name>.onnx`). Old hash is NOT deleted; it may be revoked.

`successor/` holds the **revocation-demo successor** of `image_anomaly.onnx`: the same trainer, same
data and hyper-parameters, seed 43 (`verigate-train image --seed 43 --models-dir models/successor`).
It is registered on-chain as the successor of the seed-42 model so that `verigate-admin revoke-model`
(and the `poisoned-model` attack) can show the gateway swapping models by hash and replaying stale
verdicts (P6-06). Its card carries its own measured metrics; it is not claimed to be better.
