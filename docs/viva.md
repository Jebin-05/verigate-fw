# Viva preparation — questions a panel is likely to ask, with answers you can defend

Every number below has a results directory (`evaluation/results/…`). If a panel member asks
"how do you know?", name the directory, or offer to run the experiment.

## 1. The idea

**Q: In one sentence, what is VeriGate-FW?**
A firmware-update gate that first proves an update is genuine (nine deterministic checks against
a blockchain), then judges whether it is *safe* (an SBOM vulnerability model and an image anomaly
model), and makes the AI itself accountable: every verdict names the models that produced it,
and a model can be revoked like a bad firmware release.

**Q: What does your base paper (DIDAuth-IoTFW) do, and what is new here?**
DIDAuth-IoTFW proves *who* made firmware (DIDs + verifiable credentials, Arbitrum, IPFS,
on-chain revocation, device-side checks on ESP32). It never asks whether a genuine update is
safe. New here: the AI risk gate, three outcomes (approve / review / reject) under an on-chain
policy, models registered and revocable on-chain with automatic re-verification, Merkle-batched
verdict anchoring, and the release-delta check. Borrowed foundation: blockchain + IPFS + hash
binding + revocation (also FOTB 2018, Baza 2019).

**Q: AI for OTA updates already exists — DDoSViT (2025).**
DDoSViT watches the *network* for DDoS traffic during an update. We judge the *firmware* being
delivered. And its model is not registered, named in decisions or revocable.

**Q: Why put the model on a blockchain at all?**
So a decision can be audited and undone. If a model turns out to be wrong or poisoned, its hash is
revoked; `staleByModel` lists every batch it influenced, and the gateway re-verifies those
devices with the successor. Measured: 50 devices re-verified in 13.0 s
(`revocation_propagation/2026-10-02_1704`).

## 2. Design choices

**Q: Why can the AI never approve something Stage 1 rejected?**
Stage 1 runs first and decides alone if any check fails. The AI only sees releases that passed,
and its score can only move them toward review or rejection. "The AI can tighten a decision,
never loosen it."

**Q: Why is the language model "explain-only"?**
LLM output is not deterministic and cannot be verified by recomputation. Decisions must be
reproducible from the feature hash and the model files, so the LLM writes a rationale for humans,
stored by CID, and the decision path never reads it (ADR-0002). It runs only when the reviewer
presses the button.

**Q: Why three outcomes and not two?**
Some releases are genuine but risky (an old build with exploitable libraries). Rejecting them
blocks real fixes; approving them ships known vulnerabilities. DEFER sends them to a person.

**Q: What happens to a release that "needs review"?**
A reviewer opens it in the console and presses Accept or Reject, with their name and a note. Only
holds from the risk policy or check #9 can be decided — never a forged, tampered, revoked or
expired release — and only once. The decision is signed and anchored like any verdict, so it is
auditable, and devices install an accepted release on their next poll. Honest limit: the
reviewer's name is typed in, not authenticated; a real deployment would sign decisions with a
reviewer key.

**Q: Why batch verdicts in a Merkle tree?**
Cost. One transaction per verdict costs 209 642 gas; at 200 verdicts per batch it is 1 048 per
verdict, 99.5 % less execution gas. Each verdict still has its own proof that the contract checks
(`verifyLeaf`). Be precise: this is execution gas on a local chain; on a real rollup calldata
also costs, and batching reduces that by a smaller factor.

## 3. Check #9 and the detector's weakness

**Q: Your anomaly model is at chance on small patches. Isn't that a failure?**
Yes, and the paper says so (AUROC 0.54 for byte patches, 0.53 for section swaps). We then asked
what *could* catch them. In 120 of 165 real OpenWrt update pairs the package was not rebuilt, so
a patch sits on top of an unchanged, already-approved image. Check #9 compares the new image with
the last approved one block by block: 120/120 patches and 97/97 swaps held for review, 0/165
benign releases flagged (`release_delta/2026-10-02_1619`).

**Q: Why not just add those features to the model?**
We tried; it got worse. Patch recall stayed at 0.012 and appended-payload recall fell from 1.000
to 0.297 (`delta_features_iforest/2026-10-02_1712`). An unsupervised model trained on mostly
identical pairs does not isolate "almost identical".

**Q: Why does check #9 defer instead of reject?**
A genuine vendor binary hot-patch looks exactly like an insider patch. A person decides.

**Q: Where does check #9 fail?**
Inside a rebuild. If the attacker patches and the package is rebuilt (or changes the source),
every block changes and the check sees a normal rebuild. Nothing in the system catches that, and
we say so. Also, the 2 KiB limit is set from a corpus with no benign hot-patch releases.

**Q: Which release is "trusted" for the comparison?**
The newest earlier release of the same publisher and device model that this gateway *approved*,
that is not revoked, and whose served image still matches its on-chain hash. The first version
used "last non-revoked" and the end-to-end tests caught the flaw: a rejected tampered release
became the reference for the next genuine one.

## 4. Device side

**Q: What if the gateway itself is compromised?**
The device does not trust the gateway's publisher key. It reads the publisher record and the
release record from the chain and refuses anything unregistered, withdrawn, signed by a revoked
key or older than what it runs. The `rogue-gateway` scenario pushes three such updates from a fake
gateway: all refused, 5/5 runs; a genuine release pushed the same way still installs.

**Q: So a compromised gateway can do nothing?**
It can still approve a registered, genuinely signed release that the gate would have held — it is
the verdict authority. That verdict is signed and anchored with its feature hash and model
hashes, so the lie is detectable afterwards, not prevented. Preventing it needs k-of-n gateways.

**Q: Why no real hardware, when the base paper used ESP32?**
The contribution is the decision layer — what to approve and how to make that accountable — not
device firmware. The device logic (A/B slots, NVS, self-checks, signed receipts, chain reads) is
implemented and tested in emulation. It is the main item of future work.

## 5. Evaluation honesty

**Q: How fast is it?**
95 ms per verification for the deterministic gate, 128 ms for the full gate in-process, 244 ms per
device over HTTP (`latency_stage1/2026-10-02_1702`, `latency_stage2/2026-10-02_1702`). Check #9
costs about 10 ms of that (same-session A/B, `ablation_check9_off/`).

**Q: Your September numbers were lower. Why?**
Part is check #9 (≈ 10 ms by A/B). The rest is unexplained run-to-run variation on a laptop in
daily use; we report the new numbers as measured rather than the better old ones.

**Q: Did anything break when you extended the system?**
Yes — the expanded attack matrix exposed a latent bug: two concurrent gateway transactions could
collide on a nonce, and a queued verdict naming a since-revoked model then blocked anchoring
forever. Fixed (serialised sends; such verdicts are held back and replayed). It is in the
changelog and limitations §15.

**Q: Is the attack set realistic?**
The mutations are synthetic structural tampering, not real malware; we say so. The value is that
every scenario runs against the live system, five times, with the expected outcome stated
beforehand: 62/62 (`attack_matrix/2026-10-02_1653`).

**Q: Why no public testnet?**
A scope decision. Gas figures are local `gasUsed`; the deploy script targets any EVM network, so
the measurement can be added without code changes.

**Q: Was AI used to build this?**
Yes, to assist with implementation, experiment scripts and drafting; the paper's
acknowledgment says so. Every number is produced by a script in the repository, and I can run
any of them.

## 6. Ten-second facts

| | |
|---|---|
| Stage-1 checks | 9 (8 REJECT, `expiry` and `release_delta` DEFER) |
| Policy | R = 0.4·r_sbom + 0.4·r_img + 0.2·(1 − reputation); approve < 0.45 ≤ review < 0.70 ≤ reject |
| Image corpus | 165 benign OpenWrt ELF pairs, 12 releases, 15 packages |
| SBOM corpus | 624 OpenWrt manifests, 49 releases, temporal split |
| SBOM model vs baseline | Spearman 0.965 vs 0.976; MAE 0.17 vs 1.01 (calibration, not ranking) |
| Attacks | 13 scenarios, 62/62 runs |
| Tests | 385 unit (92 %), 74 contract (100 %), 19 integration, 14 end-to-end |
