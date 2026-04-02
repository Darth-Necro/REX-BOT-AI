#!/usr/bin/env bash
# REX-BOT-AI One-Click Installer
# Usage: curl -sSL https://install.rexbot.ai | bash
set -euo pipefail

# ============================================================
# Banner
# ============================================================
cat << 'BANNER'

  /\_/\
 ( o.o )  REX-BOT-AI Installer
  > ^ <   Autonomous Security Agent
 /|   |\
(_|   |_) v0.1.0-alpha

BANNER

# ============================================================
# Configuration
# ============================================================
REX_VERSION="0.1.0-alpha"
REX_INSTALL_DIR="/opt/rex-bot-ai"
REX_DATA_DIR="/etc/rex-bot-ai"
REX_LOG_DIR="/var/log/rex-bot-ai"
REX_USER="rex"
REX_PORT=8443
LOG_FILE="/var/log/rex-bot-ai-install.log"
MANIFEST_FILE="${REX_INSTALL_DIR}/install-manifest.json"

# Exit codes
EXIT_SUCCESS=0
EXIT_GENERAL=1
EXIT_UNSUPPORTED_OS=2
EXIT_INSUFFICIENT_RESOURCES=3
EXIT_NETWORK_FAILURE=4
EXIT_DOCKER_FAILURE=5

# ============================================================
# Logging
# ============================================================
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG_FILE" 2>/dev/null; }
info() { log "INFO: $*"; }
warn() { log "WARN: $*"; }
error() { log "ERROR: $*"; }
die() { error "$1"; exit "${2:-$EXIT_GENERAL}"; }

# ============================================================
# Pre-flight Checks
# ============================================================
preflight() {
    info "Running pre-flight checks..."

    # Root check
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script requires root privileges. Re-running with sudo..."
        # In curl|bash mode, $0 is "bash" or "-bash", not a file path
        if [ ! -f "$0" ] || [ "$0" = "bash" ] || [ "$0" = "-bash" ] || [ "$0" = "/bin/bash" ]; then
            SCRIPT_TMP=$(mktemp /tmp/rex-install-XXXXXX.sh)
            # Script already consumed from stdin by this point in curl|bash
            # Re-download it
            curl -sSL https://raw.githubusercontent.com/Darth-Necro/REX-BOT-AI/main/install.sh -o "$SCRIPT_TMP"
            exec sudo bash "$SCRIPT_TMP" "$@"
        else
            exec sudo bash "$0" "$@"
        fi
    fi

    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"

    # OS detection
    if [ ! -f /etc/os-release ]; then
        die "Cannot detect OS. /etc/os-release not found." $EXIT_UNSUPPORTED_OS
    fi
    # shellcheck source=/dev/null
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    ARCH=$(uname -m)

    info "Detected OS: ${OS_ID} ${OS_VERSION} (${ARCH})"

    case "${OS_ID}" in
        ubuntu|debian|raspbian) PKG_MGR="apt-get" ;;
        fedora) PKG_MGR="dnf" ;;
        rhel|centos|rocky|almalinux) PKG_MGR="dnf" ;;
        arch|manjaro) PKG_MGR="pacman" ;;
        *) die "Unsupported OS: ${OS_ID}. Supported: Ubuntu, Debian, Fedora, RHEL, Arch." $EXIT_UNSUPPORTED_OS ;;
    esac

    case "${ARCH}" in
        x86_64|aarch64|arm64) info "Architecture: ${ARCH}" ;;
        *) die "Unsupported architecture: ${ARCH}. Supported: x86_64, aarch64." $EXIT_UNSUPPORTED_OS ;;
    esac

    # Resource checks
    TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))
    if [ "$TOTAL_RAM_MB" -lt 2048 ]; then
        die "Insufficient RAM: ${TOTAL_RAM_MB}MB. Minimum: 2048MB." $EXIT_INSUFFICIENT_RESOURCES
    fi
    if [ "$TOTAL_RAM_MB" -lt 4096 ]; then
        warn "Low RAM: ${TOTAL_RAM_MB}MB. LLM performance will be limited. 4GB+ recommended."
    fi

    DISK_FREE_KB=$(df / | tail -1 | awk '{print $4}')
    DISK_FREE_GB=$((DISK_FREE_KB / 1024 / 1024))
    if [ "$DISK_FREE_GB" -lt 10 ]; then
        die "Insufficient disk: ${DISK_FREE_GB}GB free. Minimum: 10GB." $EXIT_INSUFFICIENT_RESOURCES
    fi

    # Internet check
    if ! curl -sf --max-time 5 https://github.com > /dev/null 2>&1; then
        die "No internet connectivity. REX requires internet for installation." $EXIT_NETWORK_FAILURE
    fi

    info "Pre-flight checks passed (RAM: ${TOTAL_RAM_MB}MB, Disk: ${DISK_FREE_GB}GB free)"
}

# ============================================================
# Install Dependencies
# ============================================================
install_deps() {
    info "Installing dependencies..."

    # Docker
    if ! command -v docker &> /dev/null; then
        info "Installing Docker..."
        case "${PKG_MGR}" in
            apt-get)
                apt-get update -qq
                apt-get install -y -qq ca-certificates curl gnupg
                install -m 0755 -d /etc/apt/keyrings
                curl -fsSL https://download.docker.com/linux/${OS_ID}/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null
                chmod a+r /etc/apt/keyrings/docker.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${OS_ID} $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
                apt-get update -qq
                apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
                ;;
            dnf)
                dnf install -y -q dnf-plugins-core
                dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo 2>/dev/null || true
                dnf install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin
                ;;
            pacman)
                pacman -Sy --noconfirm docker docker-compose
                ;;
        esac
        systemctl enable docker
        systemctl start docker
        info "Docker installed"
    else
        info "Docker already installed"
    fi

    # Git
    if ! command -v git &> /dev/null; then
        info "Installing git..."
        case "${PKG_MGR}" in
            apt-get) apt-get install -y -qq git ;;
            dnf) dnf install -y -q git ;;
            pacman) pacman -Sy --noconfirm git ;;
        esac
    fi

    # Ollama
    if ! command -v ollama &> /dev/null; then
        info "Installing Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh 2>&1 | tail -1
        info "Ollama installed"
    else
        info "Ollama already installed"
    fi

    info "Dependencies installed"
}

# ============================================================
# Install REX
# ============================================================
install_rex() {
    info "Installing REX-BOT-AI..."

    # Create directories
    mkdir -p "${REX_INSTALL_DIR}" "${REX_DATA_DIR}" "${REX_LOG_DIR}"

    # Create rex system user
    if ! id -u "${REX_USER}" &>/dev/null; then
        useradd -r -s /bin/false -d "${REX_DATA_DIR}" "${REX_USER}" 2>/dev/null || true
    fi

    # Generate admin password
    ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)

    # Generate self-signed TLS certificate
    info "Generating TLS certificate..."
    mkdir -p "${REX_DATA_DIR}/certs"
    LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    openssl req -x509 -newkey rsa:2048 -keyout "${REX_DATA_DIR}/certs/key.pem" \
        -out "${REX_DATA_DIR}/certs/cert.pem" -days 90 -nodes \
        -subj "/CN=rex.local/O=REX-BOT-AI" \
        -addext "subjectAltName=DNS:rex.local,DNS:localhost,IP:127.0.0.1,IP:${LOCAL_IP}" \
        || warn "TLS certificate generation failed — HTTPS will not work"

    # Clone the full repo -- Docker needs the complete build context
    # (Dockerfile, rex/, requirements.txt, pyproject.toml, frontend/).
    if [ -f "$(pwd)/docker-compose.yml" ] && [ -d "$(pwd)/rex" ]; then
        info "Installing from local checkout..."
        cp -a "$(pwd)/." "${REX_INSTALL_DIR}/"
        rm -rf "${REX_INSTALL_DIR}/.git" "${REX_INSTALL_DIR}/node_modules" \
               "${REX_INSTALL_DIR}/frontend/node_modules" \
               "${REX_INSTALL_DIR}/.pytest_cache" \
               "${REX_INSTALL_DIR}/.ruff_cache" \
               "${REX_INSTALL_DIR}/.coverage" 2>/dev/null || true
    else
        info "Downloading REX-BOT-AI..."
        git clone --depth 1 https://github.com/Darth-Necro/REX-BOT-AI.git \
            "${REX_INSTALL_DIR}" 2>/dev/null || \
            die "Failed to clone repository" $EXIT_NETWORK_FAILURE
        rm -rf "${REX_INSTALL_DIR}/.git"
    fi

    # Write .env
    cat > "${REX_INSTALL_DIR}/.env" << ENVEOF
REX_MODE=basic
REX_LOG_LEVEL=info
REX_DASHBOARD_PORT=${REX_PORT}
REX_NETWORK_INTERFACE=auto
REX_SCAN_INTERVAL=300
REDIS_PASSWORD=$(openssl rand -hex 16)
REX_FEDERATION_ENABLED=false
ENVEOF

    # Set permissions
    chown -R "${REX_USER}:${REX_USER}" "${REX_DATA_DIR}" "${REX_LOG_DIR}"
    chmod 700 "${REX_DATA_DIR}"
    if compgen -G "${REX_DATA_DIR}/certs/*.pem" > /dev/null; then
        chmod 600 "${REX_DATA_DIR}/certs"/*.pem
    else
        warn "No .pem files found in ${REX_DATA_DIR}/certs — skipping chmod"
    fi

    # Pull and start services
    info "Starting REX services..."
    cd "${REX_INSTALL_DIR}"
    docker compose pull 2>/dev/null || true
    docker compose up -d 2>&1 | tail -5

    # Create systemd service
    cat > /etc/systemd/system/rex-bot-ai.service << SVCEOF
[Unit]
Description=REX-BOT-AI Autonomous Security Agent
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${REX_INSTALL_DIR}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable rex-bot-ai

    # Write install manifest
    cat > "${MANIFEST_FILE}" << MEOF
{
    "version": "${REX_VERSION}",
    "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "install_dir": "${REX_INSTALL_DIR}",
    "data_dir": "${REX_DATA_DIR}",
    "user": "${REX_USER}",
    "port": ${REX_PORT}
}
MEOF

    info "REX-BOT-AI installed"
}

# ============================================================
# Post-Install
# ============================================================
post_install() {
    # Detect IP
    LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

    echo ""
    echo "============================================"
    echo "  REX-BOT-AI installed successfully!"
    echo "============================================"
    echo ""
    echo "  Dashboard: https://${LOCAL_IP}:${REX_PORT}"
    echo "  Local URL: https://rex.local:${REX_PORT}"
    echo ""
    echo "  Admin Password: ${ADMIN_PASSWORD}" >&2
    echo "  (Write this down. It will not be shown again.)" >&2
    echo ""
    echo "  REX is awake and sniffing your network."
    echo "  Visit the dashboard to complete setup."
    echo ""
    echo "  Commands:"
    echo "    rex status    - Check REX status"
    echo "    rex scan      - Trigger network scan"
    echo "    rex sleep     - Put REX to sleep"
    echo "    rex wake      - Wake REX up"
    echo ""
    echo "  Logs: ${REX_LOG_DIR}/"
    echo "  Data: ${REX_DATA_DIR}/"
    echo "============================================"
}

# ============================================================
# Main
# ============================================================
main() {
    preflight "$@"
    install_deps
    install_rex
    post_install
}

main "$@"
