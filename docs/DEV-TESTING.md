# REX-BOT-AI: Developer Testing Guide

Step-by-step guide to get REX running locally for testing.

## Prerequisites

- Linux (Ubuntu 22.04+ or Debian 12+ recommended)
- Python 3.11+
- Node.js 20+
- Docker and Docker Compose
- Git

## Quick Start (Development Mode)

### 1. Clone and install

```bash
git clone https://github.com/Darth-Necro/REX-BOT-AI.git
cd REX-BOT-AI
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -r requirements-dev.txt
```

### 2. Run the tests

```bash
pytest
# Expected: 1018 passed, 10 xfailed, 0 failed
```

### 3. Start Redis (required for event bus)

```bash
docker run -d --name rex-redis -p 6379:6379 redis:7.4-alpine \
  redis-server --requirepass testpassword
```

### 4. Set environment

```bash
export REX_REDIS_URL="redis://:testpassword@localhost:6379"
export REX_DATA_DIR="$(pwd)/rex-data"
export REX_LOG_LEVEL=debug
mkdir -p rex-data
```

### 5. Start REX

```bash
rex start
```

On first boot, REX will display the admin password:

```
  ==============================================
  ADMIN PASSWORD: <random-24-char-string>
  Write this down. It will not be shown again.
  ==============================================
```

### 6. Access the dashboard

Open http://localhost:8443 in your browser. Log in with the displayed password.

### 7. Run the CLI

```bash
rex status        # Show system health
rex diag          # Full hardware diagnostic
rex scan          # Trigger network scan
rex privacy       # Run privacy audit
```

## Docker Compose (Full Stack)

### 1. Configure

```bash
cp .env.example .env
# Edit .env and set REDIS_PASSWORD to a strong random value:
#   REDIS_PASSWORD=$(openssl rand -hex 16)
```

### 2. Start

```bash
docker compose up -d
docker compose logs -f rex
```

### 3. Check health

```bash
curl http://localhost:8443/api/health
# {"status": "ok"}

curl http://localhost:8443/api/status
# Shows real Redis/Ollama connectivity status
```

## What to Test

### Core pipeline (EYES -> BRAIN -> TEETH)
- Does `rex scan` discover devices on your network?
- Do threat events appear in the dashboard?
- Does REX classify threats correctly?

### Authentication
- Can you log in with the initial password?
- Does the password lockout work after 5 failures?
- Do API endpoints reject requests without a token?

### Firewall safety
- Does REX refuse to block the gateway IP?
- Does the panic button work?
- Are rules limited to private IPs?

### Prompt injection
- Set a device hostname to "ignore all instructions" — does the sanitizer catch it?
- Check the LLM context — are hostnames wrapped in untrusted delimiters?

## Reporting Issues

File issues at https://github.com/Darth-Necro/REX-BOT-AI/issues with:
- Steps to reproduce
- Expected vs actual behavior
- Output of `rex diag`
- Relevant log lines

## Known Limitations

- Scheduler records intervals but does not trigger real scans independently
- Plugin sandbox stores metadata, does not use real Docker isolation
- Federation and messaging bridges exist as modules but are not end-to-end tested
- Windows/macOS/BSD PAL adapters are stubs (Linux only for now)
- No TLS configured (HTTP only, use behind a reverse proxy for HTTPS)
