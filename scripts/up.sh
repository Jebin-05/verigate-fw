#!/usr/bin/env bash
# One command for the whole stack in Docker: chain, IPFS, contracts, models, gateway, fleet, dashboard.
# Works on Linux, macOS and Windows (WSL2 or Git Bash) with Docker Desktop / Docker Engine.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v docker >/dev/null || { echo "Docker is not installed: https://docs.docker.com/get-docker/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is missing (docker compose …)."; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is not running. Start Docker Desktop / the docker service and retry."; exit 1; }

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example."
fi

env_value() { sed -n "s/^$1=\([^ #]*\).*/\1/p" .env | tail -1; }
if [ -z "$(env_value OPENROUTER_API_KEY)" ]; then
  echo "OPENROUTER_API_KEY is empty in .env: everything runs, but Explain with AI stays off."
  echo "Get a key at https://openrouter.ai/keys, put it in .env and run this again."
fi
GATEWAY_PORT=$(env_value GATEWAY_PORT); GATEWAY_PORT=${GATEWAY_PORT:-8000}
DASHBOARD_PORT=$(env_value DASHBOARD_PORT); DASHBOARD_PORT=${DASHBOARD_PORT:-5173}

COMPOSE=(docker compose --env-file .env -f infra/docker-compose.yml --profile app)
echo "Building and starting (the first run downloads and builds images: 5-10 min)…"
"${COMPOSE[@]}" up -d --build

echo "Waiting for the gateway…"
for _ in $(seq 1 90); do
  if curl -sf "http://localhost:${GATEWAY_PORT}/health" >/dev/null 2>&1; then
    echo
    echo "VeriGate-FW is running."
    echo "  Approval console   http://localhost:${DASHBOARD_PORT}/app"
    echo "  Publisher portal   http://localhost:${DASHBOARD_PORT}/publisher"
    echo "  Gateway API        http://localhost:${GATEWAY_PORT}/docs"
    echo "Stop with: make down   (or: docker compose --env-file .env -f infra/docker-compose.yml --profile app down)"
    exit 0
  fi
  sleep 2
done
echo "The gateway did not become healthy in 3 minutes. Last log lines:"
"${COMPOSE[@]}" logs --tail=40 gateway deployer registrar || true
exit 1
