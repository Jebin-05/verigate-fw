#!/usr/bin/env bash
# Fresh-machine smoke test. Proves the whole stack starts from a clean clone with ONE command and reaches a verdict.
# Used by CI (portability job), by `make smoke`, and by you on any new laptop before a demo.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || cp .env.example .env
COMPOSE="docker compose --env-file .env -f infra/docker-compose.yml --profile app"
cleanup() { $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

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
# The first Stage-2 verification fills the vulnerability cache from OSV/EPSS/KEV: minutes on a
# cold machine, and the public APIs throttle. A dependency failure is a DEFER or a 503, not a
# reason to call the stack broken — retry, then show the gateway's own reason.
VERDICT=""
for attempt in 1 2 3; do
  BODY=$(curl -s --max-time 900 -X POST "http://localhost:${GATEWAY_PORT:-8000}/verify/${RELEASE_ID}" || true)
  VERDICT=$(printf '%s' "$BODY" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("verdict", ""))
except Exception:
    print("")' )
  [ "$VERDICT" = "APPROVE" ] && break
  echo "  attempt $attempt: ${BODY:-<empty response>}"
  sleep 20
done
echo "verdict: ${VERDICT:-none}"
if [ "$VERDICT" != "APPROVE" ]; then
  echo "expected APPROVE for a clean fixture — last 40 gateway log lines:"
  $COMPOSE logs --tail=40 gateway || true
  exit 1
fi
echo "✔ smoke test passed"
