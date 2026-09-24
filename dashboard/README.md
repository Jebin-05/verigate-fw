React 18 + Vite + TypeScript + ethers v6 + zustand (ADR-0003). Read-only on-chain; every write goes
through the gateway API. `make dashboard` starts Vite on :5173 against `VITE_GATEWAY_URL`
(default `http://localhost:8000`) and `VITE_RPC_URL` (default `http://localhost:8545`).

Two portals, one for each job, plus a front door and a demonstration page:

| route | who | what it shows — and deliberately nothing else |
|---|---|---|
| `/` | everyone | choose your portal |
| `/publish` | the publisher | identity and standing; publish a release (firmware + SBOM + version + expiry); *your* releases with their journey (registered → inspected → installed on N devices), the plain-words reason when one is not approved, withdraw |
| `/approve` | the approver / fleet operator | incoming releases with their stamp; the inspection report for one (the eight checks in words, risk meters against the rules in force, written explanation, device counts, on-chain proof); live activity as sentences; fleet, rules and model summaries |
| `/demo` | presenters | the eleven security drills with what happens and what the gate does |

The publisher portal never shows fleet, rules, logs or drills; the approval console never shows a
publish form or anything from another publisher's private material. Hashes live behind
"Technical identifiers". Roles are separated by route, not by login — authentication is out of
scope for this prototype.

```
src/
  api/        client.ts (typed fetch, multipart publish), schema.d.ts (generated: npm run api:types), types.ts
  chain/      abi/*.json (synced by scripts/sync_abi.py), useChain.ts (direct RPC reads, verifyLeaf)
  lib/        words.ts — every sentence the interface says (verdicts, checks, reasons, activity)
  pages/      Landing · Publisher · Approver · Drills
  components/ Shell (top bar), Bits (stamp, meter, id), Activity (websocket /logs as sentences), usePoll
  state/      zustand store (log buffer, websocket status, running drill)
```

Fonts are bundled (`@fontsource/ibm-plex-*`), so the UI renders identically offline.
Checks: `npm run lint`, `npx tsc --noEmit`, `npm run build`.
