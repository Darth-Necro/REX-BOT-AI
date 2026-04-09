#!/usr/bin/env bash
# REX-BOT-AI Developer Setup
# Creates a complete development environment
set -euo pipefail

echo "Setting up REX-BOT-AI development environment..."

# Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .

# Install frontend dependencies
# NOTE: The SSD uses exFAT which does not support symlinks.
# frontend/.npmrc sets bin-links=false to work around this.
# Without it, npm install fails when creating node_modules/.bin symlinks.
if command -v npm &> /dev/null; then
    cd frontend && npm install && cd ..
    echo "Frontend dependencies installed"
fi

echo ""
echo "Development environment ready!"
echo ""
echo "  Activate: source .venv/bin/activate"
echo "  Run tests: make test"
echo "  Run lint: make lint"
echo "  Start dev server: make dev"
echo "  Start frontend: make dev-frontend"
