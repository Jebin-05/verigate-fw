# All day-to-day commands. `make help` lists them.
SHELL := /bin/bash
PY := .venv/bin/python
PIP := .venv/bin/pip
N ?= 20

.PHONY: up down logs smoke doctor llm-pull help bootstrap lint format typecheck test test-unit test-integration test-contracts test-all \
        infra-up infra-down contracts-build contracts-deploy-local gateway fleet dashboard \
        train models-hash models-register vulndb-seed eval eval-all figures clean

up:              ## run EVERYTHING in docker (any machine, no host toolchain needed)
	[ -f .env ] || cp .env.example .env
	docker compose -f infra/docker-compose.yml --profile app up -d --build
	@echo "dashboard → http://localhost:$${DASHBOARD_PORT:-5173}   gateway → http://localhost:$${GATEWAY_PORT:-8000}/docs"

down:            ## stop everything (keeps volumes; add V=1 to wipe)
	docker compose -f infra/docker-compose.yml --profile app --profile llm down $(if $(V),-v,)

logs:            ## follow all container logs
	docker compose -f infra/docker-compose.yml --profile app logs -f --tail=100

smoke:           ## fresh-machine proof: up → deploy → publish → verify → APPROVE → down
	./scripts/smoke.sh

doctor:          ## diagnose this machine before running anything
	./scripts/doctor.sh

vulndb-seed:     ## copy the host vulnerability cache (or SNAP=data/vulndb-demo) into the running gateway's volume
	docker compose -f infra/docker-compose.yml --profile app cp $(or $(SNAP),data/processed/vulndb)/. gateway:/app/data/processed/vulndb/
	@echo "seeded; the first Stage-2 verification is now warm"

llm-pull:        ## start ollama and pull the explainer model once (~2 GB)
	docker compose -f infra/docker-compose.yml --profile llm up -d ollama
	docker compose -f infra/docker-compose.yml exec ollama ollama pull qwen2.5:3b-instruct

help:            ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'

bootstrap:       ## create venv, install python+node deps, install git hooks
	python3.11 -m venv .venv && $(PIP) install -U pip && $(PIP) install -e ".[dev,eval]"
	cd contracts && npm ci
	cd dashboard && npm ci
	.venv/bin/pre-commit install --hook-type pre-commit --hook-type commit-msg
	[ -f .env ] || cp .env.example .env

lint:            ## ruff lint + solhint + eslint
	.venv/bin/ruff check src tests evaluation
	cd contracts && npx solhint "contracts/**/*.sol"
	cd dashboard && npm run lint

format:          ## auto-format everything
	.venv/bin/ruff format src tests evaluation && .venv/bin/ruff check --fix src tests evaluation
	cd dashboard && npx prettier --write "src/**/*.{ts,tsx,css}"

typecheck:       ## mypy strict + tsc
	.venv/bin/mypy
	cd dashboard && npx tsc --noEmit

test-unit:       ## fast python tests (no infra)
	.venv/bin/pytest -m "not integration and not e2e"

test-integration:## python tests against hardhat + ipfs (make infra-up first)
	.venv/bin/pytest -m integration

test-contracts:  ## hardhat tests + coverage
	cd contracts && npx hardhat test && npx hardhat coverage

test-all: lint typecheck test-unit test-contracts  ## what CI runs

infra-up:        ## start hardhat node, kubo, ollama
	docker compose -f infra/docker-compose.yml up -d

infra-down:      ## stop them
	docker compose -f infra/docker-compose.yml down

contracts-build: ## compile + typechain + sync ABIs into the python package
	cd contracts && npx hardhat compile
	$(PY) scripts/sync_abi.py

contracts-deploy-local: contracts-build ## deploy to local node and write addresses into .env
	cd contracts && npx hardhat run scripts/deploy.ts --network localhost

models-register: ## register every hash in models/MANIFEST.sha256 on the local ModelRegistry (idempotent)
	.venv/bin/verigate-admin register-models --manifest models/MANIFEST.sha256

gateway:         ## run the gateway API with reload
	.venv/bin/uvicorn verigate.gateway.api.main:app --reload --port 8000

fleet:           ## run N emulated devices
	.venv/bin/verigate-fleet run --count $(N)

dashboard:       ## vite dev server
	cd dashboard && npm run dev

train:           ## train both ML models, export ONNX, write model cards
	.venv/bin/verigate-train all --seed 42

models-hash:     ## regenerate models/MANIFEST.sha256
	cd models && find . -name '*.onnx' | sort | sed 's|^\./||' | xargs sha256sum > MANIFEST.sha256 && cat MANIFEST.sha256

eval:            ## run an experiment: make eval EXP=evaluation/configs/latency_stage1.yaml
	.venv/bin/python evaluation/runners/run.py $(EXP)

eval-all:        ## every experiment against the live stack (infra-up + deploy + gateway with LLM_ENABLED=false first)
	for c in gas_per_verdict_vs_batched latency_stage1 latency_stage2 revocation_propagation attack_matrix detection_f1 sbom_ranking; do \
	  .venv/bin/python evaluation/runners/run.py evaluation/configs/$$c.yaml || exit 1; done

figures:         ## regenerate evaluation/figures/* from the newest results (the only producer of figures)
	.venv/bin/python evaluation/figures.py

clean:
	rm -rf .venv .pytest_cache .mypy_cache .ruff_cache htmlcov contracts/artifacts contracts/cache dashboard/dist
