# Contributing

Full rules are in `docs/VeriGate-FW_Developer_Manual.pdf`. The short version:

1. **Branch** from `main`: `feat/<area>-<short-desc>`, `fix/...`, `docs/...`, `eval/...`.
2. **Commit** with Conventional Commits: `feat(gateway): add expiry check to stage 1`.
3. **Before pushing**: `make test-all` must pass (pre-commit hooks run the fast parts automatically).
4. **Open a PR** using the template. Link the CHECKLIST item. One logical change per PR.
5. **CI must be green** and one review approved. **Squash-merge**. Delete the branch.
6. **Never commit**: private keys, `.env`, datasets, results edited by hand, fabricated numbers.
7. **Every module** ships with tests, docstrings, and a line in `CHANGELOG.md` under *Unreleased*.
