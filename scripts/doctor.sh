#!/usr/bin/env bash
# `make doctor` — one-screen diagnosis on ANY machine: versions, ports, docker, disk, RAM, .env, lockfiles.
set -uo pipefail
cd "$(dirname "$0")/.."
ok()  { printf "  \033[32m✔\033[0m %s\n" "$1"; }
bad() { printf "  \033[31m✘\033[0m %s\n" "$1"; FAIL=1; }
FAIL=0
echo "Toolchain"
command -v docker >/dev/null && docker compose version >/dev/null 2>&1 && ok "docker + compose plugin" || bad "docker compose missing (Docker Desktop on macOS/Windows-WSL2, docker-ce on Linux)"
command -v python3.11 >/dev/null && ok "python3.11" || bad "python3.11 missing (only needed for host-mode dev; docker mode does not need it)"
command -v node >/dev/null && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 20 ] && ok "node ≥ 20" || bad "node ≥ 20 missing (host-mode dev only)"
echo "Repository"
[ -f .env ] && ok ".env present" || bad ".env missing → cp .env.example .env"
[ -f contracts/package-lock.json ] && ok "contracts lockfile" || bad "contracts/package-lock.json missing (P0-07)"
[ -f dashboard/package-lock.json ] && ok "dashboard lockfile" || bad "dashboard/package-lock.json missing (P0-07)"
grep -rIl --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv "/home/[a-z]*/" . 2>/dev/null | grep -v '^./docs/' | head -3 | while read -r f; do bad "absolute home path in $f"; done
echo "Machine"
MEM=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo 2>/dev/null || sysctl -n hw.memsize 2>/dev/null | awk '{printf "%d",$1/1024/1024/1024}')
[ "${MEM:-0}" -ge 8 ] && ok "RAM ${MEM} GB (≥ 8 needed; 12+ with LLM)" || bad "RAM ${MEM} GB — run without --profile llm"
DISK=$(df -Pk . | awk 'NR==2 {printf "%d", $4/1024/1024}')
[ "$DISK" -ge 10 ] && ok "disk ${DISK} GB free" || bad "disk ${DISK} GB free (< 10 GB)"
echo "Ports"
for p in ${HARDHAT_PORT:-8545} ${IPFS_API_PORT:-5001} ${GATEWAY_PORT:-8000} ${DASHBOARD_PORT:-5173}; do
  (command -v ss >/dev/null && ss -ltn | grep -q ":$p ") && bad "port $p in use → override in .env (e.g. GATEWAY_PORT=8001)" || ok "port $p free"
done
[ "$FAIL" -eq 0 ] && echo "all good — run: make up" || { echo "fix the ✘ items above"; exit 1; }
