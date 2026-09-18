# Security audit record (P8-06) — 2026-09-18, commit 70bd407

| tool | scope | result | action |
|---|---|---|---|
| `pip-audit` | `.venv` (project + dev + eval extras) | 8 advisories, all in `setuptools 65.5.0` (venv bootstrap, not a project dependency) | upgraded to setuptools ≥ 83 in the venv; `make bootstrap` installs the latest pip/setuptools; re-run: **no known vulnerabilities** |
| `npm audit --omit=dev --audit-level=high` | `contracts/` shipped dependencies (OpenZeppelin 5.6) | **0 vulnerabilities** | — |
| `npm audit --audit-level=high` | `contracts/` incl. devDependencies | 17 high / 10 moderate / 19 low, every one transitive through Hardhat 2.29 (`adm-zip`, `undici`, `@sentry/node`, `solidity-coverage`, `hardhat-gas-reporter` …); `npm audit fix` changes nothing; the only fix is `hardhat-toolbox 7` = Hardhat 3, a breaking migration of config, tests and scripts | **accepted for v1.0.0** as build-time tooling that never runs in a deployed component; CI audits contracts without devDependencies; Hardhat 3 migration is tracked as follow-up work |
| `npm audit --audit-level=high` | `dashboard/` | 0 high; 2 moderate in `react-router` 6.30 (open redirect via backslash in `<Link>` / `useNavigate`; SSR `deserializeErrors` injection) — fix is `react-router-dom 7` (major) | **accepted**: the dashboard is client-side only (no SSR) and every route target is a constant path; below the CI threshold; upgrade tracked |
| `slither` (102 detectors, `slither.config.json`, fail-on medium in CI) | `contracts/contracts` | 2 findings, both *low*: `calls-loop` in `VerdictRegistry.commitBatch` (one `isActive` call per model hash; the array is the gate's ≤ 2 models, bounded by the caller's gas) and `timestamp` in `FirmwareRegistry.register` (`expiry <= block.timestamp` — the expiry check *is* a timestamp comparison by design, tolerance = miner drift, see ADR-0001) | no change; documented |
| `gitleaks` (pre-commit + CI) | whole tree | clean; the allow-list contains only the three public Hardhat test keys and the fixture public keys (`.gitleaks.toml`) | — |
| `detect-private-key` (pre-commit) | whole tree | clean | — |

Re-run: `.venv/bin/pip-audit`, `cd contracts && npm audit --omit=dev --audit-level=high`,
`cd dashboard && npm audit --audit-level=high`, `cd contracts && ../.venv/bin/slither . --config-file slither.config.json`,
`.venv/bin/pre-commit run --all-files`.
