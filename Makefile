.PHONY: build up down restart logs shell pull-model setup

## First-time setup: build, start everything, pull the LLM model
setup:
	docker compose up -d --build
	@echo "Waiting for Ollama to be ready…"
	@until docker compose exec ollama curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; do sleep 2; done
	@echo "Pulling llama3:latest (first run only — may take a few minutes)…"
	docker compose exec ollama ollama pull llama3:latest
	@echo ""
	@echo "✓  CyberPath is running at http://localhost:5000"

## Start all containers (model already pulled)
up:
	docker compose up -d
	@echo "CyberPath running at http://localhost:5000"

## Stop all containers
down:
	docker compose down

## Rebuild app image and restart (Ollama untouched)
restart:
	docker compose up -d --build app
	@echo "App restarted at http://localhost:5000"

## Pull or re-pull the LLM model
pull-model:
	docker compose exec ollama ollama pull llama3:latest

## Stream app logs
logs:
	docker compose logs -f app

## Open a shell inside the app container
shell:
	docker compose exec app /bin/bash
