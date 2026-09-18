#!/usr/bin/env bash
# Demo script (P4-08, P6-07): publish → fleet installs → all eleven attacks, end to end, < 5 min.
# Docker mode (default): the stack from `make up` (gateway, fleet, hardhat, ipfs). Host mode
# (DEMO_MODE=host): `make gateway` + `make infra-up` running on this machine.
set -euo pipefail
cd "$(dirname "$0")/.."
DEMO_MODE="${DEMO_MODE:-docker}"
COMPOSE="docker compose -f infra/docker-compose.yml --profile app"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:${GATEWAY_PORT:-8000}}"
FIX="tests/fixtures/releases"
START=$(date +%s)

step() { printf '\n\033[36m▶ %s\033[0m\n' "$1"; }
run_in_gateway() {
  if [ "$DEMO_MODE" = "docker" ]; then
    $COMPOSE exec -T gateway "$@"
  else
    .venv/bin/"$@"
  fi
}
verdict_of() { python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])'; }

step "waiting for the gateway at $GATEWAY_URL"
for i in $(seq 1 60); do
  curl -sf "$GATEWAY_URL/health" >/dev/null && break
  sleep 2; [ "$i" -eq 60 ] && { echo "gateway not reachable"; exit 1; }
done
DATA=$(curl -s "$GATEWAY_URL/health") python3 - <<'PY'
import json, os
d = json.loads(os.environ["DATA"])
print("chain block", d["block"], "· releases", d["knownReleases"], "· devices", d["devices"])
PY

step "publishing fixture release v1.0.0 (idempotent)"
if [ "$DEMO_MODE" = "docker" ]; then FIXROOT=/app/fixtures/releases; else FIXROOT=$FIX; fi
RELEASE_JSON=$(run_in_gateway verigate-publish release --fw "$FIXROOT/v1.0.0/firmware.bin" \
  --sbom "$FIXROOT/v1.0.0/sbom.json" --version 1.0.0 --model demo-device --expiry 2030-01-01T00:00:00Z --json 2>/dev/null)
RELEASE_ID=$(echo "$RELEASE_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["releaseId"])')
echo "releaseId $RELEASE_ID"

step "release-level verification (expect APPROVE)"
VERDICT=$(curl -sf -X POST "$GATEWAY_URL/verify/$RELEASE_ID" | verdict_of)
echo "verdict: $VERDICT"; [ "$VERDICT" = "APPROVE" ]

step "fleet: devices poll, self-verify and install (one round)"
if [ "$DEMO_MODE" = "docker" ]; then
  # the compose fleet polls every 5 s; give it one cycle
  sleep 7
else
  DATA=$(.venv/bin/verigate-fleet run --count 5 --rounds 1 --interval 1 --state-dir .verigate/fleet --gateway "$GATEWAY_URL" 2>/dev/null) python3 - <<'PY'
import json, os
d = json.loads(os.environ["DATA"])
print("installs", d["installs"], "· receipts", d["receipts"])
PY
fi
DATA=$(curl -s "$GATEWAY_URL/devices") python3 - <<'PY'
import json, os
ds = json.loads(os.environ["DATA"])
print(len(ds), "devices · installed versions:", sorted({d["installed_version"] for d in ds}))
PY

step "eleven attacks: six Stage-1 (tamper … sbom-swap) + five AI-gate (vulnerable-genuine, hidden-payload, bad-history, poisoned-model, policy-tamper)"
ATTACK_URL=$GATEWAY_URL; [ "$DEMO_MODE" = "docker" ] && ATTACK_URL=http://127.0.0.1:8000
run_in_gateway verigate-attack run all --gateway "$ATTACK_URL" 2>/dev/null > /tmp/verigate-demo-attacks.json || true
python3 - <<'PY'
import json
txt = open("/tmp/verigate-demo-attacks.json").read(); dec = json.JSONDecoder(); i = 0; failed = 0
while i < len(txt):
    while i < len(txt) and txt[i].isspace(): i += 1
    if i >= len(txt): break
    r, i = dec.raw_decode(txt, i); failed += not r["passed"]
    print(f'  {r["name"]:19} expected {r["expected"]:8} observed {str(r["observed"]):8} check={r["check"]}  {"PASS" if r["passed"] else "FAIL"}')
raise SystemExit(1 if failed else 0)
PY

step "verdict log tail + committed batches"
DATA=$(curl -s "$GATEWAY_URL/verdicts?limit=8") python3 - <<'PY'
import json, os
for v in json.loads(os.environ["DATA"]):
    failed = (v.get("stage1") or {}).get("failed") or ""
    print(f"  {v.get('deviceId', ''):14} {v.get('verdict', 'receipt'):8} {failed}")
PY
curl -s -X POST "$GATEWAY_URL/batches/flush" >/dev/null
DATA=$(curl -s "$GATEWAY_URL/batches") python3 - <<'PY'
import json, os
bs = json.loads(os.environ["DATA"])
print(" ", len(bs), "batches on-chain,", sum(b["count"] for b in bs), "verdicts")
PY

printf '\n\033[32m✔ demo complete in %d s\033[0m\n' "$(( $(date +%s) - START ))"
