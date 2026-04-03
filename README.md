# REX-BOT-AI

```
    ^
   / \__
  (    @\___     ____  _______  __     ____   ____ _______
  /         O   |  _ \| ____\ \/ /    | __ ) / __ \__   __|
 /   (_____/    | |_) |  _|  \  / ____|  _ \| |  | | | |
/_____/   U     |  _ <| |___ /  \|____| |_) | |  | | | |
                |_| \_\_____|/_/\_\   |____/ \____/  |_|  AI
```

**v0.1.0-alpha** -- Local-first autonomous network security agent. Linux-primary (macOS/Windows/BSD PAL stubs are experimental). Multi-layer AI decision pipeline, prompt injection defense, per-service event bus isolation, and **Junkyard Dog mode** for maximum threat protection.

> This project is under active development and is **not ready for production use**. Do not rely on it as your sole network security solution.

---

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11-3.12](https://img.shields.io/badge/python-3.11%E2%80%933.12-blue.svg)](https://www.python.org/downloads/)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow.svg)]()

---

## Table of Contents

- [What This Is](#what-this-is)
- [Required Software](#required-software)
- [Installation](#installation)
- [Configuration](#configuration)
- [Starting REX](#starting-rex)
- [CLI Commands](#cli-commands)
- [Current State](#current-state)
- [Architecture](#architecture)
- [Security Invariants](#security-invariants)
- [Protection Modes](#protection-modes)
- [Contributing](#contributing)
- [License](#license)

---

## What This Is

REX-BOT-AI is an open-source autonomous AI security agent for home and small business networks. It uses a local LLM (via Ollama) to reason about network threats and takes defensive actions through a whitelisted command system.

All 13 modules are implemented with real logic. The core security pipeline (EYES scan, BRAIN classify, TEETH enforce, BARK notify) is wired through Redis Streams with per-service consumer groups. End-to-end Docker deployment is not yet verified.

---

## Required Software

REX will not start or will run in degraded mode without these dependencies. Install them **before** proceeding.

### System Requirements

| Software | Version | Required | Purpose | Install (Ubuntu/Debian) |
|----------|---------|----------|---------|-------------------------|
| **Python** | 3.11 or 3.12 | Yes | Runtime | `sudo apt install python3 python3-venv python3-pip` |
| **Git** | 2.x+ | Yes | Clone repo, knowledge base versioning | `sudo apt install git` |
| **Redis** | 7.x+ | Yes | Event bus between services | `sudo apt install redis-server` |
| **nmap** | 7.x+ | Recommended | Full network scanning (falls back to ARP-only without it) | `sudo apt install nmap` |
| **arp-scan** | 1.x+ | Recommended | ARP-based device discovery | `sudo apt install arp-scan` |
| **libpcap** | 1.x+ | Yes | Packet capture (required by scapy) | `sudo apt install libpcap-dev` |
| **Docker** | 24.x+ | Optional | Plugin sandbox, container deployment | See [Docker docs](https://docs.docker.com/engine/install/) |
| **Docker Compose** | 2.x+ | Optional | Full-stack deployment | Included with Docker Desktop or `sudo apt install docker-compose-v2` |

### Services (Must Be Running)

| Service | Required | Purpose | Default URL |
|---------|----------|---------|-------------|
| **Redis** | Yes | Event bus, pub/sub between all REX services | `redis://localhost:6379` |
| **Ollama** | Recommended | Local LLM for AI threat analysis (rules-only mode without it) | `http://localhost:11434` |
| **ChromaDB** | Optional | Vector store for knowledge base memory | `http://localhost:8000` |

### Platform Support

| Platform | Status |
|----------|--------|
| **Linux** (Ubuntu, Debian, Fedora) | Fully supported -- primary target |
| **macOS** | Experimental -- PAL stub exists, many features raise NotImplementedError |
| **Windows** | Experimental -- PAL stub exists, not functional |
| **FreeBSD** | Experimental -- PAL stub exists, not functional |

---

## Installation

### Step 1: Install system dependencies

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git \
    redis-server nmap arp-scan libpcap-dev curl
```

### Step 2: Start Redis

```bash
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Verify Redis is running
redis-cli ping
# Expected output: PONG
```

### Step 3: Install Ollama (recommended)

```bash
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (REX auto-selects based on your hardware)
ollama pull llama3.2

# Verify Ollama is running
curl -s http://localhost:11434/api/tags | head -1
```

### Step 4: Clone and install REX

```bash
git clone https://github.com/Darth-Necro/REX-BOT-AI.git
cd REX-BOT-AI

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip
python -m pip install --upgrade pip

# Install REX and all dependencies
pip install -e .

# Verify installation
python -m rex.core.cli --help
```

### Step 5: Install dev/test dependencies (optional)

Only needed if you plan to run tests or contribute:

```bash
pip install -e ".[dev]"
# Or use the requirements file:
pip install -r requirements-dev.txt

# Verify lint
python -m ruff check .

# Run tests
python -m pytest -q
```

---

## Configuration

### Quick start (minimal)

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```bash
# REQUIRED: Change the Redis password before first run
REDIS_PASSWORD=your_secure_password_here

# Optional: set your network interface (auto-detected if omitted)
REX_NETWORK_INTERFACE=auto
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REX_MODE` | `basic` | Operating mode |
| `REX_LOG_LEVEL` | `info` | Log verbosity: debug, info, warning, error |
| `REX_DATA_DIR` | `/etc/rex-bot-ai` | Data directory (needs write access) |
| `REX_DASHBOARD_PORT` | `8443` | Dashboard web UI port |
| `REX_DASHBOARD_HOST` | `0.0.0.0` | Dashboard bind address |
| `REX_REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `REX_OLLAMA_URL` | `http://localhost:11434` | Ollama LLM endpoint (localhost only) |
| `REX_OLLAMA_MODEL` | `auto` | LLM model (auto-selects based on hardware) |
| `REX_CHROMA_URL` | `http://localhost:8000` | ChromaDB vector store URL |
| `REX_NETWORK_INTERFACE` | `auto` | Network interface to monitor |
| `REX_SCAN_INTERVAL` | `300` | Seconds between periodic scans |
| `REX_PROTECTION_MODE` | `auto_block_critical` | Protection level (see below) |

### Data directory

REX stores its data in `REX_DATA_DIR` (default `/etc/rex-bot-ai`). Create it before first run:

```bash
sudo mkdir -p /etc/rex-bot-ai
sudo chown $USER:$USER /etc/rex-bot-ai
```

Or use a user-writable directory:

```bash
export REX_DATA_DIR="$HOME/.rex-bot-ai"
mkdir -p "$REX_DATA_DIR"
```

---

## Starting REX

### Option A: Local development (no Docker)

Make sure Redis is running, then:

```bash
cd REX-BOT-AI
source .venv/bin/activate

# Start REX (needs root for packet capture and firewall)
sudo .venv/bin/python -m rex.core.cli start
```

REX will:
1. Load configuration from `.env` and environment variables
2. Start all 10 services in order: Memory, Eyes, Scheduler, Interview, Brain, Bark, Teeth, Federation, Store, Dashboard
3. Begin monitoring your network

### Default credentials

On first boot, REX creates a default admin account:

| Field | Value |
|-------|-------|
| **Username** | `REX-BOT` |
| **Password** | `Woof` |

Log in via CLI:

```bash
rex login
# Username: REX-BOT (default)
# Password: Woof
```

**Change the default password** after first login:

```bash
curl -X POST http://localhost:8443/api/auth/change-password \
  -H "Authorization: Bearer $(cat ~/.rex-token)" \
  -H "Content-Type: application/json" \
  -d '{"old_password": "Woof", "new_password": "your-new-secure-password"}'
```

### Option B: Docker Compose (full stack)

This starts Redis, Ollama, ChromaDB, and REX together:

```bash
# Set your Redis password first
echo "REDIS_PASSWORD=$(openssl rand -base64 32)" > .env

# Start everything
docker compose up -d

# Check status
docker compose ps
docker compose logs -f rex
```

The dashboard and GUI will be available at `http://localhost:8443`.

---

## Web GUI (Default Interface)

REX ships with a built-in browser-based GUI. This is the **default and recommended way** to operate REX. The GUI is served automatically by the dashboard service -- no separate build step is needed.

### Accessing the GUI

After starting REX, open your browser to:

```
http://localhost:8443
```

Log in with the default credentials (`REX-BOT` / `Woof`), then change your password.

### GUI Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Overall status, device count, threats, protection mode, service health |
| **Devices** | Network device inventory, trust levels, device details |
| **Threats** | Threat events, investigations, severity breakdown |
| **Firewall** | Active firewall rules, rule builder |
| **Scheduler** | Patrol schedules, scan jobs, cron management |
| **Privacy** | Privacy audit, data inventory, encryption status |
| **Plugins** | Installed and bundled plugins |
| **Network Map** | Visual network topology |
| **Knowledge Base** | REX's learned knowledge, version history |
| **Settings** | Configuration, notifications, about |
| **Diagnostics** | Service health details, system info |
| **Onboarding** | First-run setup wizard |

### Rebuilding the Frontend (optional)

The compiled GUI is included in the repository. If you modify the React source code in `frontend/src/`, rebuild with:

```bash
cd frontend
npm install
node node_modules/vite/bin/vite.js build
```

This produces `frontend/dist/` which the dashboard serves automatically.

---

## Verify REX is Running

In a separate terminal:

```bash
source .venv/bin/activate

# Check service health
python -m rex.core.cli status

# If dashboard is running on HTTP (no TLS certs):
REX_API_URL=http://127.0.0.1:8443 python -m rex.core.cli status
```

Or just open `http://localhost:8443` in your browser.

### Stopping REX

```bash
# Graceful stop (use sudo if REX was started with sudo)
sudo .venv/bin/python -m rex.core.cli stop

# Or Ctrl+C in the terminal where REX is running

# Docker
docker compose down
```

---

## CLI Commands (Advanced / Headless)

The CLI is the expert and automation interface. All actions available in the GUI can also be performed via CLI:

```bash
rex start      # Start all services (blocks until Ctrl+C)
rex stop       # Stop all services gracefully
rex status     # Show service health
rex scan       # Trigger manual network scan
rex sleep      # Put REX into alert-sleep mode
rex wake       # Wake REX to full monitoring
rex junkyard   # Activate JUNKYARD DOG mode (BITE! removes threats)
rex patrol     # Schedule security patrols (--now or --schedule "cron")
rex login      # Authenticate with the REX API
rex diag       # Full diagnostic dump
rex backup     # Create data backup
rex privacy    # Run privacy audit
rex version    # Print version string
```

---

## Current State (Honest)

| Component | Status |
|-----------|--------|
| Platform Abstraction Layer (Linux) | Working -- 2300+ lines, real subprocess calls |
| Threat classifier (12 categories) | Working -- rule-based, no LLM required |
| Command executor (whitelisted) | Working -- zero shell=True, parameter validation |
| LLM client (localhost-only enforced) | Working -- Ollama integration with privacy boundary |
| Pydantic data models | Working -- Device, ThreatEvent, Decision, etc. |
| Redis event bus | Working -- per-service consumer groups, WAL fallback |
| Network scanner (ARP + nmap) | Working -- device discovery via PAL |
| DNS monitor | Working -- query analysis, DGA detection, Python 3.12+ safe |
| Device fingerprinter | Working -- MAC OUI, OS detection, type classification |
| Knowledge base (markdown) | Working -- REX-BOT-AI.md read/write/parse with git |
| Privacy/encryption module | Working -- Fernet secrets, audit tools |
| Agent security (scope, sanitizers) | Working -- prompt injection defense (44 patterns), IP normalization, action whitelist |
| Dashboard API (FastAPI) | Working -- 11 routers, 43 endpoints, typed event publishing |
| Dashboard frontend (React) | **Partial** -- fetches real state on mount, WebSocket sync wired |
| Notification channels | **Partial** -- channel classes exist, not integration-tested |
| Plugin system | **Minimal** -- SDK defined, sandbox is a dict not Docker |
| Orchestrator | Working -- per-service bus ownership, health monitor, auto-restart |
| Docker deployment | **Unverified** -- compose file exists, end-to-end not tested |
| Installer (install.sh) | **Unverified** -- clones full repo for Docker build context |
| Windows/macOS/BSD PAL | **Experimental** -- stub adapters, many methods raise NotImplementedError |
| Test suite | 4,289 tests, 0 failures, 0 lint errors |

---

## Architecture

REX is built as cooperating async services, each with its own EventBus instance and Redis consumer group:

```
EYES (scan) -> Redis -> BRAIN (classify) -> TEETH (block) -> BARK (notify)
                                   |
                              MEMORY (log to REX-BOT-AI.md)
```

**Service startup order:**

```
1. Memory     -- threat logs, knowledge base, vector store
2. Eyes       -- network scanner, DNS monitor, traffic capture
3. Scheduler  -- cron jobs, patrol schedules, power state
4. Interview  -- initial setup wizard
5. Brain      -- threat classifier, LLM router
6. Bark       -- notification channels (Discord, Telegram, email, Matrix)
7. Teeth      -- firewall manager, DNS blocker, device isolator
8. Federation -- multi-instance coordination
9. Store      -- plugin registry, sandbox
10. Dashboard  -- FastAPI web UI (depends on all others)
```

Each service owns its bus connection. Consumer groups are isolated (`rex:<service>:group`) so every subscribing service sees every event -- no message stealing between services.

All OS-specific operations go through the Platform Abstraction Layer (PAL). The LLM is hardcoded to localhost only -- network data never leaves the machine.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

---

## Security Invariants

These are enforced in code, not just policy:

- **No `shell=True`** anywhere in the codebase. Commands use a whitelist with parameter validators.
- **LLM is localhost-only**. `OllamaClient` raises `PrivacyViolationError` for non-localhost URLs.
- **Network data is sanitized** before reaching the LLM (hostnames, banners stripped of injection attempts).
- **Firewall safety**: gateway and REX IPs are hardcoded as untargetable, with IP normalization (zero-padded, IPv6-mapped, decimal forms all blocked).
- **Action whitelist**: the LLM cannot execute actions not in the registry regardless of its output.
- **Scope enforcement**: out-of-scope request patterns override security keyword matches to prevent disguised-request bypass.
- **CORS safety**: wildcard origins are stripped when `allow_credentials=True`.
- **WebSocket auth**: first-message auth only -- JWTs are never sent in URLs/query strings.
- **Password hashing**: bcrypt with SHA-256 pre-hashing to prevent 72-byte truncation attacks.
- **Restart anti-flapping**: sliding-window restart budget with exponential backoff prevents restart storms.
- **Credential storage**: plaintext fallback only when encrypted storage is unavailable; plaintext removed on migration.
- **Health fail-closed**: the `/api/health` endpoint returns 503 when the event bus is unreachable.
- **Plugin permissions**: registered plugins are restricted to declared permissions; unregistered tokens are rejected once any plugin is registered.

---

## Protection Modes

REX supports four protection modes that control how aggressively threats are handled:

| Mode | Description |
|------|-------------|
| `alert_only` | *ruff* -- Monitor and log only. No active blocking. |
| `auto_block_critical` | *woof* -- Auto-block CRITICAL and HIGH severity threats. Default mode. |
| `auto_block_all` | *WOOF!* -- Auto-block all detected threats regardless of severity. |
| `junkyard_dog` | *GRRRRR WOOF WOOF!* -- **BITE mode.** REX actively removes all threats from your network. No mercy. |

### Junkyard Dog Mode -- BITE!

When activated, REX becomes a junkyard dog -- the AI actively removes threats and secures your network:

- **BITE action** -- REX doesn't just block, it BITEs: block + quarantine + rate-limit all at once
- **Active threat removal** -- all threats are eliminated from your network immediately
- **Machines secured** -- devices and network are protected from outside threats
- **Owner notifications** -- you're notified of every attack and exactly what REX did about it
- **No escalation needed** -- every alert, log, or monitor event gets escalated to a full BITE
- **Aggressive bark** -- *GRRRRR WOOF WOOF!* REX communicates in fierce dog noises

Activate via CLI: `rex junkyard` or set `REX_PROTECTION_MODE=junkyard_dog` in your environment.

### Patrol Mode

Schedule REX to wake up on a timer, patrol the network, and go back to sleep:

```bash
rex patrol --now                        # Patrol right now
rex patrol --schedule "0 2 * * *"       # Every night at 2am
rex patrol --schedule "0 */6 * * *"     # Every 6 hours
rex patrol --schedule "0 0 * * 1"       # Every Monday at midnight
```

During a patrol, REX will:
- **Deep scan** the entire network for new/rogue devices
- **Run security audits** to find vulnerabilities and misconfigurations
- **Inspect all machines** for suspicious activity
- **Report findings** to the owner
- **Go back to sleep** when patrol is done

---

## Troubleshooting

### Port 8443 already in use

```bash
# Find what's using the port
sudo ss -ltnp | grep :8443

# Kill the process
sudo fuser -k 8443/tcp

# Or change the port
export REX_DASHBOARD_PORT=9443
```

### Redis not running

```bash
sudo systemctl start redis-server
redis-cli ping  # Should print: PONG
```

REX can run in degraded WAL-only mode without Redis, but all inter-service communication is lost.

### Permission denied (packet capture / firewall)

REX needs root privileges for packet capture (`NET_RAW`) and firewall management (`NET_ADMIN`):

```bash
sudo .venv/bin/python -m rex.core.cli start
```

### Ollama not available

REX falls back to rules-only classification (no LLM). Install Ollama to enable AI-powered analysis:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
```

### TLS / CLI connection issues

If dashboard runs without TLS certs (development mode), tell the CLI to use HTTP:

```bash
REX_API_URL=http://127.0.0.1:8443 python -m rex.core.cli status
```

---

## Contributing

This project needs help. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

Priority areas:
1. Verify end-to-end Docker Compose deployment with live events
2. Integration tests with live Redis in CI
3. Wire remaining frontend components to all dashboard API endpoints
4. Replace plugin sandbox dict with real Docker isolation
5. Complete Windows/macOS/BSD PAL adapters (currently experimental stubs with many NotImplementedError)

---

## License

MIT License. See [LICENSE](LICENSE).
