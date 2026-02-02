.PHONY: dev down build test lint migrate seed logs clean

# Docker Compose file path
COMPOSE_FILE := infra/docker/docker-compose.yml

# ---------------------------------------------------------------
# Development
# ---------------------------------------------------------------

## Start all services in development mode
dev:
	docker-compose -f $(COMPOSE_FILE) up -d
	@echo "AgentShield is running!"
	@echo "  Backend API: http://localhost:8000"
	@echo "  Frontend:    http://localhost:3000"
	@echo "  API Docs:    http://localhost:8000/docs"
	@echo "  Neo4j:       http://localhost:7474"

## Stop all services
down:
	docker-compose -f $(COMPOSE_FILE) down

## Rebuild Docker images
build:
	docker-compose -f $(COMPOSE_FILE) build --no-cache

# ---------------------------------------------------------------
# Testing
# ---------------------------------------------------------------

## Run all tests (backend + SDK)
test:
	@echo "Running backend tests..."
	docker-compose -f $(COMPOSE_FILE) exec backend pytest tests/ -v --cov=app --cov-report=term-missing
	@echo ""
	@echo "Running Python SDK tests..."
	cd sdk/python && python -m pytest tests/ -v
	@echo ""
	@echo "Running JavaScript SDK tests..."
	cd sdk/javascript && npm test

## Run linter for backend and SDKs
lint:
	@echo "Linting backend..."
	docker-compose -f $(COMPOSE_FILE) exec backend ruff check . --fix
	docker-compose -f $(COMPOSE_FILE) exec backend ruff format .
	@echo ""
	@echo "Linting Python SDK..."
	cd sdk/python && ruff check . --fix && ruff format .
	@echo ""
	@echo "Linting JavaScript SDK..."
	cd sdk/javascript && npm run lint:fix

# ---------------------------------------------------------------
# Database
# ---------------------------------------------------------------

## Run database migrations
migrate:
	docker-compose -f $(COMPOSE_FILE) exec backend alembic upgrade head

## Seed the database with test data
seed:
	docker-compose -f $(COMPOSE_FILE) exec backend python scripts/seed_data.py

# ---------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------

## View logs from all services
logs:
	docker-compose -f $(COMPOSE_FILE) logs -f

## View logs for a specific service (usage: make logs-backend)
logs-%:
	docker-compose -f $(COMPOSE_FILE) logs -f $*

# ---------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------

## Stop services and remove all data volumes
clean:
	docker-compose -f $(COMPOSE_FILE) down -v --remove-orphans
	@echo "All services stopped and volumes removed."
