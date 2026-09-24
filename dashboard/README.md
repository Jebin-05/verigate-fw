React 18 + Vite + TypeScript + ethers v6 + zustand (ADR-0003). Read-only on-chain; every write goes
through the gateway API. `make dashboard` starts Vite on :5173 against `VITE_GATEWAY_URL`
(default `http://localhost:8000`) and `VITE_RPC_URL` (default `http://localhost:8545`).

Two workspaces, one for each job, each an application shell (sidebar, top bar, KPI tiles, data
tables, a master–detail view with tabs) that shows deliberately nothing from the other side:

| route | who | screen |
|---|---|---|
| `/` | everyone | choose a workspace |
| `/publisher` | the publisher | **Releases** — only *your* releases (status, inspected, installed on N devices, the plain-words note when not approved, withdraw); **New release** (`/publisher/new`, a dialog: firmware + SBOM + version + expiry); **Identity** (`/publisher/identity`: standing, registration, signing key) |
| `/app` | the approver / fleet operator | **Overview** (KPIs, latest releases, rules in force, live activity); **Releases** (`/app/releases?r=<id>`: searchable table → detail panel with tabs *Summary* (risk meters against the rules), *Checks* (the eight checks in words), *AI analysis* (the real feature values and top drivers), *Explanation* (the written rationale with a *writing…* state), *Devices*, *Proof* (on-chain leaf check and identifiers)); **Devices**; **Activity** (`/app/activity`: the full live log); **Governance** (`/app/governance`: rules, a rules simulator that re-computes verdicts from recorded scores, inspection models with model cards, revocation replays); **Scenarios** (`/app/scenarios`: the seven-step walkthrough with one Run button each, and all eleven security drills with their results) |

Old routes redirect: `/publish` → `/publisher`, `/approve` → `/app/releases`, `/story` and
`/demo` → `/app/scenarios`. Roles are separated by route, not by login — authentication is out of
scope for this prototype.

```
src/
  api/        client.ts (typed fetch, multipart publish), schema.d.ts (generated: npm run api:types), types.ts
  chain/      abi/*.json (synced by scripts/sync_abi.py), useChain.ts (direct RPC reads, verifyLeaf)
  lib/        words.ts — every sentence the interface says (verdicts, checks, reasons, activity); scenarios.ts — the walkthrough steps
  pages/      Landing · app/{Overview,Releases,Devices,ActivityPage,Governance,Scenarios} · publisher/{PubReleases,PubIdentity}
  components/ AppShell (sidebar + top bar), Bits (stamp, id, meter, kpi, panel, tabs, modal), Insight (AI analysis, explanation, model cards, rules simulator), Activity (live feed), usePoll
  state/      store.ts (zustand: log buffer, websocket status, running drill, simulator), activity.ts (websocket → readable lines)
```

Fonts are bundled (`@fontsource/ibm-plex-*`), so the UI renders identically offline.
Checks: `npm run lint`, `npx tsc --noEmit`, `npm run build`.
