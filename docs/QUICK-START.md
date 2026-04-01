# REX-BOT-AI Quick Start Guide

Get REX-BOT-AI running in 5 minutes.

---

## Prerequisites

- **Python 3.11+** (check with `python3 --version`)
- **Docker and Docker Compose v2** (check with `docker compose version`)
- **Linux, macOS, or WSL2** (native Windows support is experimental)
- **4 GB RAM minimum** (8 GB recommended for LLM features)
- **10 GB free disk** (for Ollama models and data)

---

## Installation

### One-Liner Install

```bash
git clone https://github.com/Darth-Necro/REX-BOT-AI.git && cd REX-BOT-AI && make install
```

Or manually:

```bash
git clone https://github.com/Darth-Necro/REX-BOT-AI.git
cd REX-BOT-AI
bash install.sh
```

### Docker Install (Recommended for Production)

```bash
git clone https://github.com/Darth-Necro/REX-BOT-AI.git
cd REX-BOT-AI
docker compose up -d
```

This starts all services: REX core, Redis, Ollama, and ChromaDB.

### Development Install

```bash
git clone https://github.com/Darth-Necro/REX-BOT-AI.git
cd REX-BOT-AI
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -r requirements-dev.txt
```

---

## What Happens on First Boot

When REX starts for the first time, it performs the following sequence:

1. **Infrastructure check**: Verifies Redis, Ollama, and ChromaDB connectivity. Missing services trigger graceful degradation (see docs/ARCHITECTURE.md for details).

2. **Hardware detection**: Detects CPU, RAM, GPU, and selects the appropriate LLM model tier:
   - **Minimal** (< 4 GB RAM): Rules only, no LLM
   - **Standard** (4-16 GB RAM): Small models (phi3:mini, gemma:2b)
   - **Full** (16+ GB RAM or GPU): Larger models (llama3:8b, mistral:7b)

3. **LLM model pull**: If Ollama is available and no models are present, REX recommends a model to pull. You can pull it manually:

   ```bash
   docker compose exec ollama ollama pull llama3:8b
   ```

4. **Credential generation**: Creates a random admin password and JWT secret. The initial password is displayed in the startup logs:

   ```
   ============================================
   REX-BOT-AI Initial Admin Password:
   Abc123-Xyz789-Qrs456-Def012
   ============================================
   Change this after your first login.
   ```

5. **Network detection**: Auto-detects your network interface, gateway, and subnet.

6. **First scan**: Runs an initial ARP scan to discover devices on your network.

7. **Interview starts**: The onboarding wizard begins, guiding you through initial configuration.

---

## Accessing the Dashboard

Open your browser and navigate to:

```
https://localhost:8443
```

Accept the self-signed certificate warning (or add your own certificate in `/etc/rex-bot-ai/certs/`).

Log in with:
- **Username**: `admin`
- **Password**: The password shown in the startup logs

---

## The Onboarding Interview

On first access, REX presents an onboarding interview with 6 questions. This takes about 2 minutes.

### What to Expect

1. **Network type**: Is this a home network, small office, or lab?
2. **Technical level**: Basic (simplified interface, conservative defaults) or Advanced (full control, detailed logs)?
3. **Protection aggressiveness**: How should REX handle threats?
   - Alert only (never block anything automatically)
   - Auto-block critical (block only critical/high severity threats automatically)
   - Auto-block all (block all detected threats automatically)
4. **Notification preferences**: How should REX alert you? (Dashboard, Discord, Telegram, email, etc.)
5. **Scan frequency**: How often should REX scan the network? (Default: every 5 minutes)
6. **Known devices**: Do you want to pre-trust any devices?

You can restart the interview at any time from Settings.

---

## First Scan Results

After the onboarding interview completes, REX immediately runs a full network scan. Within 30-60 seconds you will see:

- **Device inventory**: All devices found on your network with:
  - IP and MAC addresses
  - Hostname (if discoverable)
  - Hardware vendor (from OUI lookup)
  - Open ports
  - OS fingerprint (best guess)
  - Trust level (default: 50/100)

- **Initial risk assessment**: Any devices with concerning characteristics (unusual ports, known vulnerable services, missing hostnames) are flagged.

- **Network map**: Visual representation of your network topology.

### What REX Is Doing in the Background

After the first scan, REX begins:

- **Learning baselines**: Watching each device's normal behavior (ports used, destinations contacted, traffic volume, active hours). This takes 24-48 hours to build reliable baselines.
- **DNS monitoring**: Passively capturing DNS queries to detect suspicious domain access.
- **Traffic analysis**: Monitoring traffic patterns for anomalies.
- **Periodic scanning**: Re-scanning the network at your configured interval to detect new devices and changes.

---

## Understanding Alerts

REX categorizes threats by severity:

| Severity   | Color  | Meaning                                        | Default Action          |
|------------|--------|------------------------------------------------|-------------------------|
| Critical   | Red    | Active attack or compromise detected           | Auto-block (if enabled) |
| High       | Orange | Strong indicators of malicious activity        | Auto-block (if enabled) |
| Medium     | Yellow | Suspicious behavior requiring investigation    | Alert only              |
| Low        | Blue   | Minor anomaly, likely benign                   | Log only                |
| Info       | Gray   | Informational event (new device, scan complete)| Log only                |

Each alert includes:

- **Description**: What was detected.
- **Reasoning**: Why REX made this decision (including which pipeline layer).
- **Confidence**: How confident REX is in the detection (0-100%).
- **Action taken**: What REX did (or recommends doing).
- **Source device**: Which device triggered the alert.

### Responding to Alerts

- **Resolve**: Mark the alert as handled.
- **False positive**: Tell REX this was a mistake. REX learns from false positives to reduce future noise.
- **View details**: See the full event data, including raw network evidence.
- **Take action**: Manually block, quarantine, or rate-limit a device.

---

## Basic vs Advanced Mode

### Basic Mode

Designed for non-technical users:

- Simplified dashboard with clear, plain-language alerts
- Conservative auto-blocking (critical threats only)
- Fewer configuration options exposed
- Knowledge base is auto-managed by REX
- Summary notifications (not detailed technical logs)

### Advanced Mode

Designed for security professionals and power users:

- Full dashboard with detailed technical data
- Configurable auto-blocking thresholds
- Direct knowledge base editing (Markdown)
- Detailed notifications with raw event data
- Access to all API endpoints
- Plugin management
- Federation configuration
- Custom scan schedules and firewall rules

You can switch between modes at any time from Settings.

---

## Getting Help

### Dashboard Help

Click the help icon in the dashboard header for contextual help on any page.

### CLI Commands

```bash
# Check REX status
rex status

# Run a manual scan
rex scan

# Start all services
rex start

# Stop all services
rex stop

# Put REX into sleep mode
rex sleep

# Wake REX to full monitoring
rex wake

# Run diagnostics
rex diag

# Create a data backup
rex backup

# Run a privacy audit
rex privacy

# Print version
rex version
```

### Documentation

- [Architecture](./ARCHITECTURE.md) -- System design and data flows
- [Security Model](./SECURITY.md) -- How REX protects itself and your network
- [Plugin SDK](./PLUGIN-SDK.md) -- Build custom plugins
- [API Reference](./API-REFERENCE.md) -- REST API documentation
- [Contributing](./CONTRIBUTING.md) -- Development setup and contribution guide

### Community

- **GitHub Issues**: Report bugs and request features
- **GitHub Discussions**: Ask questions and share configurations
- **Discord**: Real-time community support (link in repository README)

### Troubleshooting

**REX cannot detect devices:**
- Ensure REX has CAP_NET_RAW capability or is running as root.
- Check that the network interface is correctly detected (`rex status`).
- Some managed switches block ARP scanning.

**LLM features not working:**
- Check that Ollama is running: `docker compose ps ollama`
- Pull a model: `docker compose exec ollama ollama pull llama3:8b`
- REX falls back to rules-only mode when Ollama is unavailable.

**Dashboard not loading:**
- Check the port (default 8443): `curl -k https://localhost:8443/api/health`
- Check logs: `docker compose logs rex`

**High CPU usage:**
- Reduce scan frequency in Settings.
- Use a smaller LLM model.
- Enable sleep mode during low-activity hours.
