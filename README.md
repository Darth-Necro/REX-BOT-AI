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
- [Web GUI & Dashboard](#web-gui--dashboard)
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

This password is per instance/data directory. If you reset credentials or point `REX_DATA_DIR` to a different directory, that instance may have different credentials.

Log in via CLI:

```bash
rex login
# Username: REX-BOT (default)
# Password: Woof
```

**Change the default password** after first login:

```bash
curl -X POST http://localhost:8443/api/auth/change-password \
  -H "Authorization: Bearer $(jq -r 'to_entries[0].value' ~/.rex-tokens.json)" \
  -H "Content-Type: application/json" \
  -d '{"old_password": "Woof", "new_password": "your-new-secure-password"}'
```

CLI tokens are instance-aware and stored in `~/.rex-tokens.json` (keyed by API URL). Legacy single-instance `~/.rex-token` is only used as fallback.

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

## Web GUI & Dashboard

REX includes a browser-based dashboard -- a web page that runs on your computer and lets you control REX using your mouse and keyboard instead of typing commands. Think of it like a control panel you open in Chrome, Firefox, or any web browser. No coding knowledge is needed to use it.

> **What is a "Web GUI"?** GUI stands for "Graphical User Interface." A web GUI is just a website that runs locally on your computer (not on the internet). You open it in your browser like any other website, but it only works on your machine or local network.

---

### Step-by-Step: Getting the Dashboard Running

Follow these steps in order. Each step explains exactly what to do and what you should see.

---

#### Step 1: Open a Terminal

A terminal (also called "command line" or "console") is where you type text commands.

- **Ubuntu/Debian Linux**: Press `Ctrl + Alt + T` to open a terminal
- **macOS**: Open Spotlight (`Cmd + Space`), type `Terminal`, press Enter
- **Windows**: Open PowerShell or install [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) for Linux support

You should see a blinking cursor waiting for you to type. This is where you'll run all the commands below.

---

#### Step 2: Download REX

Copy and paste this into your terminal, then press Enter:

```bash
git clone https://github.com/Darth-Necro/REX-BOT-AI.git
```

**What this does:** Downloads the entire REX project to your computer.

**What you should see:** Text scrolling showing files being downloaded. When it's done, you'll see your cursor again.

Now move into the project folder:

```bash
cd REX-BOT-AI
```

---

#### Step 3: Set Up Python Environment

REX runs on Python. These commands create an isolated environment so REX doesn't conflict with other software:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -r requirements.txt
```

**Run each line one at a time.** After the `source` command, you should see `(.venv)` appear at the beginning of your terminal prompt -- this means you're in the REX environment.

> **Troubleshooting:** If `python3` is not found, install it: `sudo apt install python3 python3-venv python3-pip` (Ubuntu/Debian)

---

#### Step 4: Start Redis (Required Service)

Redis is a background service REX uses to communicate between its internal components. Start it:

```bash
sudo systemctl start redis-server
```

**What you should see:** Nothing (silence means success). If you get an error, install Redis first: `sudo apt install redis-server`

To check if Redis is running:

```bash
redis-cli ping
```

**You should see:** `PONG` -- this means Redis is working.

---

#### Step 5: Start Ollama (Optional -- for AI Chat)

Ollama runs a local AI model that powers REX's chat feature. This is optional -- REX works without it, but the "REX Chat" page won't be able to respond.

```bash
# Install Ollama (if not already installed)
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama
ollama serve &
```

**What you should see:** Ollama prints some startup messages. The `&` at the end runs it in the background so you can keep using the terminal.

---

#### Step 6: Start REX

Now start REX itself. You need `sudo` because REX monitors network traffic, which requires administrator permissions:

```bash
sudo .venv/bin/python -m rex.core.cli start
```

**What you should see:** REX prints a startup banner with a Black Great Dane ASCII art, then starts its 10 services one by one:

```
[1/10] Starting Memory...        OK
[2/10] Starting Eyes...           OK
[3/10] Starting Scheduler...      OK
...
[10/10] Starting Dashboard...     OK

Dashboard available at: http://localhost:8443
```

> **Alternative start commands:**
> ```bash
> rex start --mode gui       # Starts REX AND automatically opens your browser
> rex start --mode cli       # Starts REX without opening a browser
> rex start --mode headless  # Starts REX with minimal output (for servers)
> ```

---

#### Step 7: Open the Dashboard in Your Browser

Now the exciting part. Open your web browser (Chrome, Firefox, Edge, Safari -- any will work) and type this into the address bar at the top:

```
http://localhost:8443
```

Then press Enter.

> **What is `localhost`?** It means "this computer." You're not going to a website on the internet -- you're connecting to REX running on your own machine. `8443` is the port number (think of it like a door number on your computer).

**What you should see:** The REX login page with a Black Great Dane icon.

---

#### Step 8: First-Time Setup Wizard

If this is your first time, REX shows a **Setup Wizard** instead of the login page. It walks you through everything:

1. **Environment Check** -- REX tests your system and shows green checkmarks for what's working:
   - Redis: Should show a green checkmark
   - Ollama: Green if you started it in Step 5, yellow/red if not (that's OK)
   - ChromaDB: Optional, yellow is fine
   - API: Should show green

2. **Click "Continue"** to proceed through each step

3. **Login screen** appears when the wizard is done

---

#### Step 9: Log In

On the login page, enter these default credentials:

| Field | What to Type |
|-------|-------------|
| **Username** | `REX-BOT` |
| **Password** | `Woof` |

Click the **"Log In"** button.

**What you should see:** The main dashboard loads, showing REX (the Black Great Dane) and your network status.

> **Important:** Change your password right away! Go to **Settings** (in the left sidebar) > **Change Password**.

---

#### Step 10: You're In! Navigating the Dashboard

You're now looking at the REX dashboard. Here's how to use it:

**The Sidebar (left side of the screen):**
This is your main navigation menu. Click any item to go to that page. The currently active page is highlighted in cyan/blue.

**The Main Area (center/right of the screen):**
This shows the content for whichever page you selected in the sidebar.

**REX the Guard Dog (top right of Dashboard page):**
The animated Black Great Dane shows REX's current state. His expression and color change based on threat level:
- **Cyan/Blue eyes** = All clear, no threats
- **Amber/Yellow eyes** = Something suspicious detected
- **Red eyes** = Active threat detected
- **Orange + chains** = Junkyard Dog mode (maximum protection)

---

### What Each Page Does

#### Basic Mode Pages

These pages are always visible. They cover the essentials:

| Sidebar Item | What It Does | How to Use It |
|-------------|-------------|---------------|
| **Dashboard** | Your home base. Shows device count, active threats, blocked attacks (last 24 hours), uptime, threat trend charts, and severity breakdown. | Just look at it -- it updates automatically. Click on any alert to see details. |
| **REX Chat** | Talk to REX in plain English. Ask questions about your network or tell him to do things like "scan my network" or "what devices are connected?" | Type a message in the text box at the bottom and press Enter. REX responds like a chatbot. Requires Ollama to be running. |
| **Devices** | Shows every device REX has found on your network (phones, laptops, smart TVs, etc.) | Click any device to see its details (IP address, manufacturer, when it was first seen). Use the search bar to find specific devices. |
| **Threats** | Lists all security threats REX has detected, sorted by severity (Critical, High, Medium, Low, Info). | Click the colored filter chips at the top to show only certain severity levels. Click any threat to see full details. Use the **Resolve** or **False Positive** buttons to manage threats. |
| **Scheduler** | Control when REX runs scans and when it sleeps/wakes up. | Set wake and sleep times, view past scan history, or click "Patrol Now" to run a scan immediately. |
| **Diagnostics** | Technical information about REX's health -- which services are running, system resources, logs. | Useful for troubleshooting. The "Copy Diagnostics" button copies everything to your clipboard for sharing. |
| **Settings** | Central hub for all configuration. Links to sub-pages for system config, notifications, password change, and more. | Click any card to go to that settings area. |

#### Advanced Mode Pages

To see these pages, click the **mode toggle** at the very bottom of the sidebar. It says "Advanced mode" -- click it. More items appear in the sidebar:

| Sidebar Item | What It Does | How to Use It |
|-------------|-------------|---------------|
| **Network Map** | Visual diagram of your network showing all devices grouped by network segment. | Click any device node to see its details. Use the refresh button to re-scan. |
| **Firewall** | View and manage firewall rules that block or allow network traffic. | Click "Add Rule" to create a new firewall rule. Fill in the IP address, direction (inbound/outbound), and action (block/allow). The **Panic Mode** button blocks all traffic in an emergency. |
| **Knowledge Base** | REX's learned knowledge stored as Markdown text. Like REX's notebook. | Read what REX has learned. Edit the text and click Save. View version history and revert to older versions if needed. |
| **Plugins** | Extensions that add features to REX. Shows installed and available plugins. | Click "Install" on any available plugin. Click "Remove" to uninstall. |
| **Federation** | Connect multiple REX instances together to share threat intelligence. | Click "Enable Federation" to turn it on. Connected peers appear in the list below. Useful if you have REX running on multiple networks. |
| **Agent Actions** | Shows every action REX is allowed to take, organized by category. | Browse actions to understand what REX can do. Filter by domain (network, firewall, system, etc.) using the tab buttons. Shows risk level and whether confirmation is required. |
| **Services** | Detailed view of each internal REX service and its health status. | Green = healthy, amber = degraded, red = error. Shows dependency chains (which services depend on which). |
| **Privacy** | Everything about your data privacy -- where data is stored, what goes in/out, encryption status. | Scroll down to see outbound connections, data inventory, and encryption compliance. Click "Run Audit" for a privacy score. |
| **System Config** | Fine-tune REX's behavior -- how often it scans, what protection mode to use, sleep/wake schedule. | Adjust the settings and click "Save Changes." Changes take effect immediately. |

---

### Switching Between Basic and Advanced Mode

At the very bottom of the left sidebar, you'll see a button that says either **"Advanced mode"** or **"Basic mode"**:

- **Click it** to toggle between the two views
- **Basic mode** shows fewer pages -- ideal if you just want to monitor your network without complexity
- **Advanced mode** shows all pages -- for power users who want full control

The mode you choose is remembered, so you don't need to switch every time you log in.

---

### Common Tasks Walk-Through

#### "I want to see what devices are on my network"
1. Click **Devices** in the sidebar
2. Wait a moment for the list to populate
3. Each row shows a device with its IP address, MAC address, and manufacturer
4. Click any device to see full details in a panel on the right

#### "I want to check if there are any threats"
1. Click **Threats** in the sidebar
2. The list shows all detected threats, newest first
3. Use the colored filter buttons (Critical, High, Medium, etc.) to narrow the list
4. Click any threat to see what happened and what REX did about it
5. Use **Resolve** to mark a threat as handled, or **False Positive** if it's not a real threat

#### "I want to talk to REX"
1. Click **REX Chat** in the sidebar
2. Type a message like "What devices are on my network?" or "Run a scan"
3. Press Enter or click the send button
4. REX responds in the chat (requires Ollama to be running)

#### "I want to change how often REX scans"
1. Click **Settings** in the sidebar
2. Click the **System Configuration** card
3. Change the "Scan Interval" value (in seconds -- e.g., 60 = every minute)
4. Click **Save Changes**

#### "I want to block a device"
1. Click **Devices** in the sidebar
2. Find the device you want to block
3. Click on it to open its details
4. Click the **Block** button

#### "I want to change my password"
1. Click **Settings** in the sidebar
2. Click the **Change Password** card
3. Enter your current password and new password
4. Click **Change Password**

---

### Accessing the Dashboard from Another Device

You can open the REX dashboard from any device on the same network (your phone, tablet, another computer):

1. **Find your computer's IP address:**
   ```bash
   hostname -I
   ```
   This shows something like `192.168.1.100`

2. **On the other device**, open a browser and go to:
   ```
   http://192.168.1.100:8443
   ```
   (Replace `192.168.1.100` with your actual IP address)

3. **Log in** with the same username and password

> **Security note:** REX is designed for local network use only. Never expose port 8443 to the public internet. If you need remote access, use a VPN.

---

### Docker Setup (Alternative -- for Experienced Users)

If you prefer Docker, this starts everything (Redis, Ollama, ChromaDB, and REX) in one command:

```bash
# Set a Redis password
echo "REDIS_PASSWORD=$(openssl rand -base64 32)" > .env

# Start the full stack
docker compose up -d

# Open the dashboard
xdg-open http://localhost:8443    # Linux
open http://localhost:8443         # macOS
```

Stop everything with: `docker compose down`

---

### Troubleshooting the GUI

| Problem | Solution |
|---------|----------|
| **Browser shows "Connection refused"** | REX isn't running. Go back to Step 6 and start it. Check that the Dashboard service started successfully. |
| **Browser shows "Page not found" or blank page** | Make sure you typed `http://localhost:8443` exactly (not `https`, not a different port). |
| **Login page appears but login fails** | Make sure you're using the correct credentials: username `REX-BOT`, password `Woof` (capital W). If you changed the password and forgot it, see the CLI `rex` reset options. |
| **Dashboard loads but shows "Waiting for backend connection"** | Redis might not be running. Open a terminal and run: `redis-cli ping` -- you should see `PONG`. |
| **REX Chat says "brain isn't connected"** | Ollama isn't running. Start it with: `ollama serve &` |
| **Pages show "--" or "No data"** | This is normal on first start. REX needs a few minutes to scan your network and populate data. Click "Patrol Now" on the Scheduler page to trigger a scan. |
| **Cannot access from phone/tablet** | Make sure both devices are on the same WiFi network. Use your computer's IP address (not `localhost`). Check that no firewall is blocking port 8443. |

---

### Rebuilding the Frontend (for Developers Only)

The compiled GUI is included in the repository. Most users never need to do this. If you modify the React source code in `frontend/src/`, rebuild with:

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
rex start      # Start all services (auto-detects GUI/CLI mode)
rex gui        # Open dashboard in browser (starts REX if not running)
rex stop       # Stop all services (polls for actual exit, reports if hung)
rex setup      # First-time setup: create desktop shortcut
rex status     # Show service health
rex scan       # Trigger manual network scan
rex sleep      # Put REX into alert-sleep mode
rex wake       # Wake REX to full monitoring
rex junkyard   # Activate JUNKYARD DOG mode (BITE! removes threats)
rex patrol     # Schedule security patrols (--now or --schedule "cron")
rex login      # Authenticate with the REX API
rex diag       # Full diagnostic dump
rex backup     # Create atomic data backup (fails cleanly, no partial archive left behind)
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
| Dashboard frontend (React) | **Alpha** -- compiled and served, pages for login/devices/threats/firewall/scheduler/privacy/plugins/diagnostics/settings/network/KB/onboarding. Some pages may have incomplete backend wiring. |
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
