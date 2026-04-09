#!/usr/bin/env bash
# REX-BOT-AI Uninstaller
set -euo pipefail

echo "REX-BOT-AI Uninstaller"
echo "======================"

REX_INSTALL_DIR="/opt/rex-bot-ai"
REX_DATA_DIR="/etc/rex-bot-ai"
REX_LOG_DIR="/var/log/rex-bot-ai"

# Stop services
if systemctl is-active rex-bot-ai &>/dev/null; then
    echo "Stopping REX services..."
    systemctl stop rex-bot-ai
fi

if [ -f "${REX_INSTALL_DIR}/docker-compose.yml" ]; then
    echo "Stopping Docker containers..."
    cd "${REX_INSTALL_DIR}" && docker compose down 2>/dev/null || true
fi

# Remove systemd service
if [ -f /etc/systemd/system/rex-bot-ai.service ]; then
    systemctl disable rex-bot-ai 2>/dev/null || true
    rm -f /etc/systemd/system/rex-bot-ai.service
    systemctl daemon-reload
    echo "Removed systemd service"
fi

# Ask about data
read -rp "Keep your security data (REX-BOT-AI.md, logs, configs)? [Y/n] " keep_data
if [[ "${keep_data,,}" == "n" ]]; then
    rm -rf "${REX_DATA_DIR}"
    rm -rf "${REX_LOG_DIR}"
    echo "Data removed"
else
    echo "Data preserved at ${REX_DATA_DIR}"
fi

# Remove install directory
rm -rf "${REX_INSTALL_DIR}"

# Remove user
userdel rex 2>/dev/null || true

echo ""
echo "REX-BOT-AI has been uninstalled."
