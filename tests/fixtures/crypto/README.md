`signed_manifest.json` is signed with a **test-only** Ed25519 key whose seed is
`sha256("verigate-fixture-key")`. It is public by construction and must never sign a real release.
Regenerate with `scripts/gen_fixtures.py`.
