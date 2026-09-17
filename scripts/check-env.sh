#!/usr/bin/env bash
# Verifies toolchain versions match the manual. Run before `make bootstrap`.
set -euo pipefail
need() { command -v "$1" >/dev/null || { echo "missing: $1"; exit 1; }; }
need python3.11; need node; need npm; need docker; need git
python3.11 -c 'import sys; assert sys.version_info >= (3,11), "python >= 3.11 required"'
node -e 'const v=process.versions.node.split(".")[0]; if (v<20) { console.error("node >= 20 required"); process.exit(1) }'
docker compose version >/dev/null || { echo "docker compose plugin required"; exit 1; }
free -g | awk '/Mem:/ { if ($2 < 12) print "warning: < 12 GB RAM; run ollama only when needed" }'
echo "toolchain OK"
