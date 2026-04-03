#!/bin/bash
# REX-BOT-AI Launcher
# Usage: ./rex-launcher.sh [start|stop|gui|status]
#
# Activates the virtual environment if present, then delegates
# to the REX CLI. Defaults to 'gui' if no arguments are given.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Activate .venv if it exists
if [ -d "$SCRIPT_DIR/.venv" ]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.venv/bin/activate"
elif [ -d "$SCRIPT_DIR/venv" ]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/venv/bin/activate"
fi

# Default to 'gui' if no arguments provided
if [ $# -eq 0 ]; then
    set -- gui
fi

exec python -m rex.core.cli "$@"
