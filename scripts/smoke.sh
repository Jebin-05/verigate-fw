#!/usr/bin/env bash
# Fresh-machine smoke test. Proves the whole stack starts from a clean clone with ONE command and reaches a verdict.
# Used by CI (portability job), by `make smoke`, and by you on any new laptop before a demo.
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE="docker compose -f infra/docker-compose.yml --profile app"
cleanup() { $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

[ -f .env ] || cp .env.example .env
echo "▶ starting full stack"
$COMPOSE up -d --build
echo "▶ waiting for gateway health"
for i in $(seq 1 60); do
  if curl -sf "http://localhost:${GATEWAY_PORT:-8000}/health" >/dev/null; then break; fi
  sleep 2; [ "$i" -eq 60 ] && { echo "gateway never became healthy"; $COMPOSE logs --tail=50; exit 1; }
done
echo "▶ publishing fixture release v1.0.0 and verifying"
$COMPOSE run --rm -T gateway verigate-publish release \
  --fw /app/fixtures/releases/v1.0.0/firmware.bin --sbom /app/fixtures/releases/v1.0.0/sbom.json \
  --version 1.0.0 --model demo-device --expiry 2030-01-01T00:00:00Z --json > /tmp/release.json
RELEASE_ID=$(python3 -c 'import json,sys; print(json.load(open("/tmp/release.json"))["releaseId"])')
VERDICT=$(curl -sf -X POST "http://localhost:${GATEWAY_PORT:-8000}/verify/${RELEASE_ID}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])')
echo "verdict: $VERDICT"
[ "$VERDICT" = "APPROVE" ] || { echo "expected APPROVE for a clean fixture"; exit 1; }
echo "✔ smoke test passed"
