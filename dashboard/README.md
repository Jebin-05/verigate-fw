React 18 + Vite + TypeScript + ethers v6 + zustand (ADR-0003). Read-only on-chain; every write goes
through the gateway API. `make dashboard` starts Vite on :5173 against `VITE_GATEWAY_URL`
(default `http://localhost:8000`) and `VITE_RPC_URL` (default `http://localhost:8545`).

```
src/
  api/        client.ts (typed fetch), schema.d.ts (generated: npm run api:types), types.ts (payloads)
  chain/      abi/*.json (synced by scripts/sync_abi.py), useChain.ts (direct RPC reads, verifyLeaf)
  pages/      Releases · Verdicts · Fleet · Publishers · Models · Policy · Attacks
  components/ Layout, LiveLog (websocket /logs), ui, usePoll
  state/      zustand store (log buffer, websocket status, running attack)
```

`schema.d.ts` is generated from the gateway's OpenAPI (`npm run api:types` with the gateway
running); response payload interfaces are kept in `types.ts` because the gateway declares them as
plain JSON objects. Scripts used by CI: `npm run lint`, `npx tsc --noEmit`, `npm run build`.
