# ──────────────────────────────────────────────────────────────────────────────
#  Shadow Trust SOC Honeynet — Developer Convenience Targets
#  First time?  →  make setup
#  Day-to-day   →  make up / make down / make logs
# ──────────────────────────────────────────────────────────────────────────────

COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

.PHONY: setup up down restart rebuild logs status \
        shell-backend shell-mobsf shell-frontend shell-node db-shell db-dump \
        lab-image analysis-image labs-up guac-up guac-down labs-list labs-clean \
        test verify-local clean nuke

## ── First-time setup ─────────────────────────────────────────────────────────

setup:          ## Run the one-click setup wizard (creates .env files, builds, starts)
	@chmod +x setup.sh && ./setup.sh

## ── Lifecycle ────────────────────────────────────────────────────────────────

up:             ## Start all containers in detached mode (no rebuild)
	$(COMPOSE) up -d

down:           ## Stop and remove containers (data volumes preserved)
	$(COMPOSE) down

restart:        ## Restart all running containers
	$(COMPOSE) restart

rebuild:        ## Rebuild all images and restart (use after code changes)
	$(COMPOSE) up --build -d

## ── Observability ────────────────────────────────────────────────────────────

logs:           ## Tail logs from all containers (Ctrl-C to stop)
	$(COMPOSE) logs -f

logs-backend:   ## Tail backend logs only
	$(COMPOSE) logs -f backend

logs-mobsf:     ## Tail MobSF service logs only
	$(COMPOSE) logs -f mobsf

logs-node:      ## Tail Node API logs only
	$(COMPOSE) logs -f node_api

logs-worker:    ## Tail worker logs only
	$(COMPOSE) logs -f worker

logs-frontend:  ## Tail Nginx frontend logs only
	$(COMPOSE) logs -f frontend

status:         ## Show container status
	$(COMPOSE) ps

## ── Shell access ─────────────────────────────────────────────────────────────

shell-backend:  ## Open a bash shell inside the FastAPI backend container
	docker exec -it soc_backend bash

shell-mobsf:    ## Open a bash shell inside the MobSF service container
	docker exec -it soc_mobsf bash

shell-frontend: ## Open a sh shell inside the Nginx frontend container
	docker exec -it soc_frontend sh

shell-node:     ## Open a sh shell inside the Node API container
	docker exec -it soc_node_api sh

db-shell:       ## Open a MariaDB (mysql) prompt inside the db container
	docker exec -it honeynet_db mariadb -ushadowtrust -pshadowtrust shadowtrust

db-dump:        ## Dump the shadowtrust schema to database/dump.sql
	docker exec honeynet_db mariadb-dump -ushadowtrust -pshadowtrust shadowtrust > database/dump.sql
	@echo "Wrote database/dump.sql"

## ── Local lab environment (INFRA_PROVIDER=local) ─────────────────────────────

LAB_IMAGE       ?= shadowtrust/lab-kali:latest
LAB_NETWORK     ?= shadowtrust_labnet
ANALYSIS_IMAGE  ?= shadowtrust/analysis-shell:latest

lab-image:      ## Build the local Kali lab image (Kali + XFCE + XRDP) — slow first time
	docker build -t $(LAB_IMAGE) docker/lab-kali

analysis-image: ## Build the Analysis Lab sandbox image (small Debian shell, no egress)
	docker build -t $(ANALYSIS_IMAGE) -f Dockerfile.analysis .

labs-up:        ## Build the Kali image if missing, then start the whole stack (VM Lab ready)
	@docker image inspect $(LAB_IMAGE) >/dev/null 2>&1 || { \
	  echo "Building $(LAB_IMAGE) (first build is multi-GB, ~5-15 min)..."; \
	  docker build -t $(LAB_IMAGE) docker/lab-kali; }
	$(COMPOSE) up -d --build
	@echo ""
	@echo "VM Lab:     http://localhost:5500/vm_lab.html"
	@echo "Guacamole:  http://localhost:8080/guacamole  (guacadmin/guacadmin)"

guac-up:        ## (compat) Guacamole is part of the main stack now — starts just those services
	$(COMPOSE) up -d guacd guacamole_db guacamole
	@echo "Guacamole: http://localhost:8080/guacamole  (guacadmin/guacadmin)"

guac-down:      ## Stop just the Guacamole services
	$(COMPOSE) stop guacd guacamole_db guacamole

labs-list:      ## List running lab containers
	@docker ps --filter "label=shadowtrust.managed=true" \
	  --format "table {{.Names}}\t{{.Status}}\t{{.Label \"shadowtrust.environment\"}}\t{{.Label \"shadowtrust.profile\"}}"

labs-clean:     ## Force-remove every ShadowTrust lab container
	@docker ps -aq --filter "label=shadowtrust.managed=true" | xargs -r docker rm -f
	@echo "All lab containers removed."

## ── Tests ────────────────────────────────────────────────────────────────────

test:           ## Run the backend test suite (needs the db container up)
	$(COMPOSE) up -d db
	cd backend && .venv/bin/python -m pytest tests/ -q

verify-local:   ## Live end-to-end check of the local lab provider (needs Docker)
	python3 scripts/verify_local_lab.py

## ── Cleanup ──────────────────────────────────────────────────────────────────

clean:          ## Stop containers and remove locally-built images
	$(COMPOSE) down --rmi local

nuke:           ## ⚠  DESTRUCTIVE: remove containers, images AND volumes (resets databases)
	@echo "WARNING: This will delete all containers, images, and data volumes."
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	$(COMPOSE) down -v --rmi all

## ── Help ─────────────────────────────────────────────────────────────────────

help:           ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
