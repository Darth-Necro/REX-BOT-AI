# REX-BOT-AI Setup Guide

A step-by-step guide to get REX running on your network.

---

## Step 1: Check Prerequisites

Before starting, verify you have:

```bash
python3 --version       # Must be 3.11+
docker compose version  # Must be Docker Compose v2
```

**System requirements:**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 2 GB | 8 GB (for LLM features) |
| Disk | 10 GB free | 20 GB free |
| OS | Linux, macOS, WSL2 | Ubuntu 22.04+, Debian 12+ |
| CPU | x86_64 or aarch64 | -- |

> **Note:** Native Windows is not supported. Use WSL2 instead.

---

## Step 2: Clone the Repository

```bash
git clone https://github.com/Darth-Necro/REX-BOT-AI.git
cd REX-BOT-AI
```

---

## Step 3: Configure Environment

Copy the example config and set a Redis password:

```bash
cp .env.example .env
```

**You must change the Redis password before first run.** Generate a secure one:

```bash
# Generate a random password
openssl rand -base64 32
```

Edit `.env` and replace `CHANGE_ME_BEFORE_FIRST_RUN` with your generated password:

```bash
# .env -- minimum required change
REDIS_PASSWORD=your-generated-password-here
```

### Optional Configuration

All settings in `.env` have sensible defaults. Adjust if needed:

| Setting | Default | Description |
|---------|---------|-------------|
| `REX_MODE` | `basic` | `basic` (simplified UI) or `advanced` (full control) |
| `REX_DASHBOARD_PORT` | `8443` | HTTPS port for the dashboard |
| `REX_SCAN_INTERVAL` | `300` | Seconds between network scans (5 min) |
| `OLLAMA_MODEL` | `auto` | LLM model, or `auto` to detect based on hardware |
| `REX_NETWORK_INTERFACE` | `auto` | Network interface to monitor, or `auto` to detect |

### Notification Channels (Optional)

Configure any of these in `.env` to receive alerts outside the dashboard:

- **Discord:** Set `DISCORD_WEBHOOK_URL`
- **Telegram:** Set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`
- **Email:** Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `NOTIFICATION_EMAIL`
- **Matrix:** Set `MATRIX_HOMESERVER`, `MATRIX_ROOM_ID`, `MATRIX_ACCESS_TOKEN`

You can also configure notifications later from the dashboard Settings page.

---

## Step 4: Start REX

Choose one of these installation methods:

### Option A: Docker Compose (Recommended)

```bash
docker compose up -d
```

This starts 4 services:

| Service | Port | Purpose |
|---------|------|---------|
| **REX** | 8443 | Dashboard, API, network scanner |
| **Redis** | 6379 (localhost) | Event bus and caching |
| **Ollama** | 11434 (localhost) | Local LLM inference |
| **ChromaDB** | 8000 (localhost) | Vector store for knowledge base |

Verify all services are healthy:

```bash
docker compose ps
```

All services should show `healthy` status within 60 seconds.

### Option B: Automated Installer

```bash
bash install.sh
```

This creates a systemd service, installs dependencies, generates TLS certificates, and starts REX automatically. After installation:

```bash
sudo systemctl status rex-bot-ai    # Check status
sudo systemctl enable rex-bot-ai    # Enable auto-start on boot
```

### Option C: Development Install

For contributors and developers:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -r requirements-dev.txt

# Start infrastructure services
docker compose up -d redis ollama chromadb

# Run REX directly
rex start
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for full development setup.

---

## Step 5: Pull an LLM Model

REX uses a local LLM for threat analysis. If Ollama has no models yet, pull one:

```bash
# For machines with 8+ GB RAM (recommended)
docker compose exec ollama ollama pull llama3:8b

# For machines with 4-8 GB RAM
docker compose exec ollama ollama pull phi3:mini

# For machines with limited RAM (2-4 GB)
docker compose exec ollama ollama pull gemma:2b
```

> **Tip:** If `OLLAMA_MODEL=auto` (the default), REX auto-selects the best model for your hardware. You can skip this step and REX will recommend a model on first boot.

> **No GPU?** REX works fine on CPU-only machines. LLM responses will be slower but functional. With `< 4 GB RAM`, REX falls back to rules-only mode (no LLM) and still provides threat detection.

---

## Step 6: Access the Dashboard

Open your browser:

```
https://localhost:8443
```

**Accept the self-signed certificate warning.** REX generates a self-signed TLS cert at `/etc/rex-bot-ai/certs/`. You can replace it with your own certificate later.

### Find Your Admin Password

The initial admin password is displayed in the startup logs:

```bash
# Docker Compose
docker compose logs rex | grep "Admin Password"

# Direct install
rex start   # Password shown in startup output
```

You'll see:

```
============================================
REX-BOT-AI Initial Admin Password:
Abc123-Xyz789-Qrs456-Def012
============================================
```

**Save this password immediately.** It is shown once on first boot. Change it after your first login from Settings.

Log in with:
- **Username:** `admin`
- **Password:** The password from the logs

---

## Step 7: Complete the Onboarding Interview

On first login, REX presents a 6-question setup wizard (~2 minutes):

1. **Network type** -- Home, small office, or lab?
2. **Technical level** -- Basic (simplified) or Advanced (full control)?
3. **Protection mode** -- How aggressive should REX be?
   - `alert_only` -- Log threats, never auto-block
   - `auto_block_critical` -- Auto-block critical/high severity only (recommended)
   - `auto_block_all` -- Auto-block everything detected
4. **Notifications** -- Which channels to send alerts to
5. **Scan frequency** -- How often to scan (default: every 5 minutes)
6. **Known devices** -- Pre-trust specific devices

You can restart the interview anytime from Settings, or via the API: `POST /api/interview/restart`.

---

## Step 8: Review Your First Scan

After onboarding, REX runs a full network scan. Within 30-60 seconds the Devices page shows:

- **IP and MAC addresses** of every discovered device
- **Hostname** (if discoverable via DNS/mDNS)
- **Hardware vendor** (from OUI/MAC lookup)
- **Open ports** and running services
- **OS fingerprint** (best guess)
- **Trust level** (default: 50/100, adjustable)

Devices with concerning characteristics (unusual ports, known vulnerable services, missing hostnames) are flagged automatically.

---

## What Happens Next

After the first scan, REX enters continuous monitoring mode:

| Activity | Timing |
|----------|--------|
| **Baseline learning** | First 24-48 hours -- watches normal device behavior |
| **DNS monitoring** | Continuous -- captures DNS queries for suspicious domains |
| **Traffic analysis** | Continuous -- detects anomalies against baselines |
| **Network rescans** | Every 5 min (configurable) -- detects new devices and changes |
| **Threat classification** | Real-time -- 12 threat categories with 4-layer decision pipeline |

---

## Understanding Alerts

REX categorizes threats by severity:

| Severity | Color | Meaning | Default Action |
|----------|-------|---------|----------------|
| Critical | Red | Active attack or compromise | Auto-block (if enabled) |
| High | Orange | Strong malicious indicators | Auto-block (if enabled) |
| Medium | Yellow | Suspicious, needs investigation | Alert only |
| Low | Blue | Minor anomaly, likely benign | Log only |
| Info | Gray | Informational (new device, scan done) | Log only |

Each alert includes a description, reasoning (which pipeline layer decided), confidence score, action taken, and source device.

**Responding to alerts:**
- **Resolve** -- Mark as handled
- **False positive** -- Teach REX to reduce future noise
- **View details** -- See raw network evidence
- **Take action** -- Manually block, quarantine, or rate-limit a device

---

## Basic vs Advanced Mode

| Feature | Basic | Advanced |
|---------|-------|----------|
| Dashboard | Simplified, plain-language | Full technical detail |
| Auto-blocking | Critical threats only | Configurable thresholds |
| Knowledge base | Auto-managed | Direct Markdown editing |
| Notifications | Summaries | Raw event data |
| Plugins | Hidden | Full management |
| Federation | Hidden | Configurable |
| Custom firewall rules | No | Yes |

Switch modes anytime from Settings or via CLI: `PUT /api/config/mode`.

---

## CLI Reference

All commands available via `rex` (or `python -m rex.core.cli`):

```bash
rex start                  # Start all services (blocks until Ctrl+C)
rex start --log-level debug # Start with verbose logging
rex stop                   # Stop running instance gracefully
rex status                 # Show service health, device count, threat count
rex scan                   # Trigger immediate network scan
rex scan --quick false     # Deep scan (all ports, slower)
rex scan --target 192.168.1.50  # Scan specific IP only
rex sleep                  # Enter low-power mode (lightweight monitoring)
rex wake                   # Return to full monitoring
rex diag                   # Diagnostic dump (OS, CPU, RAM, GPU, Docker)
rex backup                 # Backup data to /etc/rex-bot-ai/backups/
rex privacy                # Run privacy audit
rex version                # Print version
```

---

## Key Directories and Ports

| Path | Purpose |
|------|---------|
| `/etc/rex-bot-ai/` | Data root (knowledge base, config, WAL) |
| `/etc/rex-bot-ai/certs/` | TLS certificate and key |
| `/etc/rex-bot-ai/knowledge/` | Knowledge base Markdown files |
| `/etc/rex-bot-ai/plugins/` | Third-party plugins |
| `/etc/rex-bot-ai/backups/` | Backup archives |
| `/var/log/rex-bot-ai/` | Log files |

| Port | Service | Exposed To |
|------|---------|------------|
| 8443 | Dashboard / API | All interfaces |
| 6379 | Redis | Localhost only |
| 11434 | Ollama | Localhost only |
| 8000 | ChromaDB | Localhost only |

---

## GPU Acceleration (Optional)

For NVIDIA GPU support with Ollama, uncomment the GPU section in `docker-compose.yml`:

```yaml
# In the ollama service, uncomment:
deploy:
  resources:
    reservations:
      devices:
        - driver: nvidia
          count: 1
          capabilities: [gpu]
```

Then restart: `docker compose down && docker compose up -d`

---

## Troubleshooting

**Services not starting:**
```bash
docker compose ps          # Check service status
docker compose logs rex    # Check REX logs
docker compose logs redis  # Check Redis logs
```

**Cannot detect network devices:**
- REX needs `CAP_NET_RAW` and `CAP_NET_ADMIN` (granted automatically in Docker)
- Without Docker, run with `sudo` or set capabilities: `sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)`
- Some managed switches block ARP scanning

**LLM features not working:**
- Check Ollama: `docker compose ps ollama` (should be `healthy`)
- Pull a model: `docker compose exec ollama ollama pull llama3:8b`
- REX works without LLM -- falls back to rule-based detection only

**Dashboard not loading:**
- Verify the service is up: `curl -k https://localhost:8443/api/health`
- Check port conflicts: `ss -tlnp | grep 8443`
- Check logs: `docker compose logs rex`

**Redis connection refused:**
- Ensure `REDIS_PASSWORD` in `.env` matches what Redis expects
- Reset Redis: `docker compose down && docker volume rm rex-bot-ai_redis-data && docker compose up -d`

**High CPU usage:**
- Reduce scan frequency in Settings or `.env` (`REX_SCAN_INTERVAL=600`)
- Use a smaller LLM model (`OLLAMA_MODEL=phi3:mini`)
- Enable sleep mode: `rex sleep`

**Forgot admin password:**
- Delete the password file and restart to regenerate: `rm /etc/rex-bot-ai/.admin_password && docker compose restart rex`

---

## Further Reading

- [Architecture](./ARCHITECTURE.md) -- System design, module descriptions, data flows
- [Security Model](./SECURITY.md) -- Threat model, prompt injection defense, privacy guarantees
- [API Reference](./API-REFERENCE.md) -- All 43 REST endpoints and WebSocket spec
- [Plugin SDK](./PLUGIN-SDK.md) -- Build custom security plugins
- [Contributing](./CONTRIBUTING.md) -- Development setup, code style, PR process
- [Dev Testing](./DEV-TESTING.md) -- Running tests with Ollama integration
