# Contributing

Full rules are in `docs/VeriGate-FW_Developer_Manual.pdf`. The short version:

1. **Branch** from `main`: `feat/<area>-<short-desc>`, `fix/...`, `docs/...`, `eval/...`.
2. **Commit** with Conventional Commits: `feat(gateway): add expiry check to stage 1`.
3. **Before pushing**: run `make lint typecheck test-all` yourself — there are no pre-commit hooks and no CI to catch it later.
4. **Open a PR** using the template. Link the CHECKLIST item. One logical change per PR.
5. Nothing is checked automatically: the commands in step 3 (plus `make smoke` before a release) are the only gate. **Squash-merge**. Delete the branch.
6. **Never commit**: private keys, `.env`, datasets, results edited by hand, fabricated numbers.
7. **Every module** ships with tests, docstrings, and a line in `CHANGELOG.md` under *Unreleased*.
