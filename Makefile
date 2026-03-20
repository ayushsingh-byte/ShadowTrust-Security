# ──────────────────────────────────────────────────────────────────────────────
#  Shadow Trust SOC Honeynet — Developer Convenience Targets
#  First time?  →  make setup
#  Day-to-day   →  make up / make down / make logs
# ──────────────────────────────────────────────────────────────────────────────

COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

.PHONY: setup up down restart rebuild logs status \
        shell-backend shell-mobsf shell-frontend shell-node \
        clean nuke

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
