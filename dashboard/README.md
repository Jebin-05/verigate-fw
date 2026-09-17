React 18 + Vite + TypeScript + ethers v6. Bootstrap once with:
`npm create vite@latest . -- --template react-ts` then add eslint/prettier configs from `docs/adr/0003-dashboard-stack.md`.

```
src/
  api/        typed client for gateway REST + websocket
  chain/      read-only contract hooks (ethers)
  pages/      Releases · Verdicts · Fleet · Publishers · Models · Policy · Attacks
  components/ shared UI
  state/      zustand store
```
Scripts expected by CI: `npm run lint`, `npm run build`. Prettier + eslint (typescript-eslint, react-hooks).
