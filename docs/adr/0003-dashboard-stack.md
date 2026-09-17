# 0003 — Dashboard stack

**Status:** Accepted   **Date:** 2026-09-17

## Decision
React 18 + Vite + TypeScript, ethers v6 for read-only chain views, zustand for state, eslint (typescript-eslint,
react-hooks) + prettier. No UI framework lock-in; Tailwind allowed. The dashboard never holds private keys —
all writes go through the gateway API.
