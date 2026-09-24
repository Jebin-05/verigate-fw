# Demo runbook and rehearsal record (P8-03)

## Before the panel (on the demo machine, with network, the day before)
```bash
make doctor                       # docker, RAM, disk, ports
make up                           # builds images, starts chain + IPFS + deployer + registrar + gateway + fleet + dashboard
make vulndb-seed                  # optional: copy a warm OSV/EPSS/KEV cache into the gateway volume
                                  #   (SNAP=data/vulndb-demo for the exported offline snapshot);
                                  #   without it the first Stage-2 verification fetches everything: 9–30 min
./scripts/demo.sh                 # dry run — also warms the cache volume, which survives `make down`
make down                         # fresh chain next time; the cache volume stays
```

## On the day
```bash
make up && ./scripts/demo.sh      # ~1 min up + ~1 min demo with a warm cache
```
Open the dashboard (`http://localhost:5173`), enter the **approval console** and go to
**Scenarios** (`/app/scenarios`): seven steps in story order, one Run button each (or *Run all*),
with the expected and the live result — genuine release → tampered file → honest-but-old software
→ hidden payload → rules tampering → a revoked model replayed → one device's install cycle. Every
result links to the release in **Releases**, where the detail panel shows the eight checks, the
risk meters, *AI analysis*, the written *Explanation* (arrives about a minute later if Ollama is
running) and *Proof* (verify on the blockchain). The publisher portal (`/publisher`) shows the
same releases from the publisher's side; the eleven raw drills sit under the walkthrough.
`make logs`
shows every container.

Explanations need Ollama on the host (`ollama serve`, model `qwen2.5:3b-instruct`) and
`LLM_ENABLED=true`; without it the report says the explanation model is switched off and
everything else works.

## If something goes wrong
- Terminal recordings of the rehearsals below replay with
  `scriptreplay -t docs/demo/rehearsal-N.timing docs/demo/rehearsal-N.log` (no stack needed).
- `DEMO_MODE=host ./scripts/demo.sh` runs the same script against `make infra-up` + `make gateway`.
- A cold cache is the only slow path; `make vulndb-seed` fixes it in seconds when a host cache exists.

## Rehearsals (docker mode, this laptop: i7-1255U, 15 GB, no GPU, explainer off in compose)
| # | conditions | `make up` | demo | result |
|---|---|---|---|---|
| 1 | clean machine: images rebuilt, empty cache volume | 1 m 11 s (+ 4–6 min image build in the two failed attempts below) | 553 s | 11/11 PASS — the release-level verification waited ~8 min for the cold OSV/EPSS/KEV fetch |
| 1a, 1b | failed before the demo: BuildKit snapshot corruption, then a compose race building one image from four services | — | — | fixed: one `image:` per shared Dockerfile, built by one service (`infra/docker-compose.yml`) |
| 2 (first attempt) | fresh chain, cache volume kept | 1 m 31 s | aborted after 30 m 55 s | the named volume was root-owned → cache unwritable → every run re-fetched; fixed in `infra/Dockerfile.app` (volume directory pre-created as `app`) — see `rehearsal-2-unwritable-cache.log` |
| 2 | images rebuilt, `make vulndb-seed` from the host cache (3 s) | 2 m 05 s | 85 s | 11/11 PASS |
| 3 | `make down && make up` (warm volume, fresh chain) | 1 m 19 s | 58 s | 11/11 PASS |

All three recorded runs are in this directory (`rehearsal-N.log` + `.timing`).

## Offline demo (P8-08, verified 2026-09-22 — `offline-demo.log` + `.timing`)
Export the snapshot once while online, then run with no internet at all:
```bash
verigate-train data snapshot tests/fixtures/releases/*/sbom.json --out data/vulndb-demo   # online, once
export VULN_CACHE_DIR=data/vulndb-demo VULN_CACHE_ONLY=true LLM_ENABLED=false
make infra-up && make contracts-deploy-local && make models-register
.venv/bin/verigate-gateway &        # same environment
DEMO_MODE=host ./scripts/demo.sh
```
Verified run: the internet was cut off for every process (`HTTP(S)_PROXY=http://127.0.0.1:9`,
`NO_PROXY=127.0.0.1,localhost`, so only the local chain, IPFS and gateway were reachable). The
demo completed in **45 s with 11/11 attacks caught**; the gateway scored 6 SBOMs and 22 images
from the 21 MB snapshot, wrote nothing to it, and raised no `OfflineMissError`. `make up`
(docker) is not offline-capable in this form: the compose gateway reads `VULN_CACHE_DIR` from
`.env`, so set those three variables there and seed the volume with `make vulndb-seed SNAP=data/vulndb-demo`.
