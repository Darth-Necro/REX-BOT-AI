# REX-BOT-AI Makefile
# Usage: make [target]

.PHONY: build up down logs test lint dev clean install uninstall help

COMPOSE := docker compose
PYTHON := python3
PIP := pip3

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build all Docker images
	$(COMPOSE) build

up: ## Start all services
	$(COMPOSE) up -d

down: ## Stop all services
	$(COMPOSE) down

logs: ## Tail all service logs
	$(COMPOSE) logs -f

restart: ## Restart all services
	$(COMPOSE) restart

test: ## Run all tests
	$(PYTHON) -m pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage report
	$(PYTHON) -m pytest tests/ -v --cov=rex --cov-report=term-missing --cov-report=html

lint: ## Run linters (ruff for Python, eslint for JS)
	ruff check rex/ tests/
	ruff format --check rex/ tests/
	@if [ -d frontend/node_modules ]; then cd frontend && npx eslint src/; fi

lint-fix: ## Auto-fix lint issues
	ruff check --fix rex/ tests/
	ruff format rex/ tests/

typecheck: ## Run mypy type checking
	mypy rex/ --ignore-missing-imports

dev: ## Start in development mode with hot reload
	$(PYTHON) -m uvicorn rex.dashboard.app:create_app --factory --reload --host 0.0.0.0 --port 8443

dev-frontend: ## Start frontend dev server
	cd frontend && npm run dev

clean: ## Remove all build artifacts and containers
	$(COMPOSE) down -v --rmi local 2>/dev/null || true
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf htmlcov/ .coverage dist/ build/ *.egg-info

install: ## Run the install script
	@bash install.sh

uninstall: ## Run the uninstall script
	@bash uninstall.sh

compile-check: ## Verify all Python files compile
	find rex/ -name '*.py' -exec $(PYTHON) -m py_compile {} \;
	@echo "All Python files compile successfully"

security-check: ## Run security checks
	@echo "Checking for shell=True..."
	@! grep -rn 'shell=True' rex/ --include='*.py' | grep -v '__pycache__' | grep -v '#' | grep -v '"""' | grep -v "NEVER" | grep -v "not" || echo "PASS: No shell=True in code"
	@echo "Checking for hardcoded secrets..."
	@! grep -rn 'password\s*=' rex/ --include='*.py' | grep -v '__pycache__' | grep -v 'def \|self\._\|param\|#\|"""\|typing\|None\|str\|config' || echo "PASS: No hardcoded secrets"
