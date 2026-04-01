# REX-BOT-AI: Developer Testing Guide

Step-by-step guide to get REX running locally with AI connected for testing.

## Prerequisites

- Linux (Ubuntu 22.04+ or Debian 12+ recommended)
- Python 3.11+
- Node.js 20+
- Docker and Docker Compose
- Git
- At least 4GB RAM (8GB+ recommended for AI models)

---

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
# Expected: ~2,979 passed, 5 xfailed, 0 failed
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

---

## Connecting the AI (Ollama)

REX uses a local LLM via Ollama for threat analysis. Without Ollama, REX operates in
**degraded mode** — it still detects threats using rules and signatures (Layer 1 + 2),
but cannot do contextual AI reasoning (Layer 3). Here's how to connect it.

### Step 1: Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Verify it's running:

```bash
ollama --version
# Should print version number

curl http://localhost:11434/api/tags
# Should return JSON (even if models list is empty)
```

If Ollama isn't running as a service:

```bash
ollama serve &
# Or: systemctl start ollama
```

### Step 2: Pull a model

REX auto-selects the best model for your hardware. You can also pull one manually.

**For 4GB RAM (minimum viable):**
```bash
ollama pull phi3:mini
# ~2.3GB download, runs on CPU, basic threat analysis
```

**For 8GB RAM (recommended):**
```bash
ollama pull mistral:7b-instruct-v0.3-q4_K_M
# ~4.5GB download, good balance of speed and quality
```

**For 16GB+ RAM or GPU:**
```bash
ollama pull llama3.1:8b-instruct-q8_0
# ~8GB download, higher quality reasoning
```

**For 32GB+ RAM or 12GB+ VRAM:**
```bash
ollama pull llama3.3:70b-instruct-q4_K_M
# ~40GB download, near-cloud quality
```

Verify the model is available:

```bash
ollama list
# Should show your pulled model
```

### Step 3: Tell REX which model to use

REX auto-detects your hardware and picks the best model by default. To override:

```bash
export REX_OLLAMA_MODEL="mistral:7b-instruct-v0.3-q4_K_M"
```

Or set `auto` to let REX choose:

```bash
export REX_OLLAMA_MODEL="auto"
```

### Step 4: Verify the connection

```bash
# Check REX sees Ollama
rex diag
# Look for: "LLM: mistral:7b..." or similar

# Check via API
curl http://localhost:8443/api/status
# Look for: "services.ollama.healthy": true
```

### Step 5: Test AI threat analysis

With Ollama connected, REX uses a 4-layer decision pipeline:

```
Layer 1: Signature (instant, no LLM) — known IOC matches
Layer 2: Statistical (fast, no LLM)  — behavioral deviation
Layer 3: LLM Contextual (1-3 sec)    — AI reasons about the threat
Layer 4: Federated (background)      — optional community intel
```

Without Ollama, only Layers 1-2 run. With Ollama, Layer 3 adds contextual reasoning
like "this device normally only talks to its vendor cloud, but it's now connecting
to an IP associated with C2 infrastructure — this is suspicious."

### What the AI does

The AI (Brain 1 — Security Engine) analyzes:

- **New devices**: "Is this device type expected on this network?"
- **Suspicious DNS**: "Does this domain pattern look like a DGA?"
- **Anomalous traffic**: "Is this volume spike consistent with data exfiltration?"
- **Complex threats**: "Given the network context, is this a false positive?"

The AI generates structured JSON decisions with severity, action, and reasoning.
The reasoning is logged so you can audit every AI decision.

### Privacy guarantee

The AI runs **entirely on your machine**. REX enforces this with a hardcoded
localhost check — the LLM client throws `PrivacyViolationError` if anyone tries
to point it at a non-localhost URL. Your network data never leaves your hardware.

```python
# This is enforced in code, not just policy:
ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
```

### GPU acceleration

Ollama automatically uses your GPU if available:

| GPU | Support | Speed Boost |
|-----|---------|-------------|
| NVIDIA (CUDA) | Full | 5-40x over CPU |
| AMD (ROCm) | Full | 5-15x over CPU |
| Apple Silicon (Metal) | Full | 8-30x equivalent |
| Intel Arc | Experimental | 3-8x over CPU |
| No GPU (CPU only) | Full (slower) | Baseline |

Check if GPU is detected:

```bash
rex diag
# Look for "GPU: NVIDIA RTX 3060 (6144 MB VRAM)" or similar
```

### Troubleshooting Ollama

**"Ollama not available — entering degraded mode"**

REX still protects your network without Ollama. It uses rule-based and statistical
detection (Layers 1-2). To enable AI:

```bash
# Is Ollama running?
systemctl status ollama
# Or: curl http://localhost:11434/api/tags

# Not installed?
curl -fsSL https://ollama.com/install.sh | sh

# No model pulled?
ollama pull mistral:7b-instruct-v0.3-q4_K_M

# Wrong URL?
echo $REX_OLLAMA_URL
# Should be http://localhost:11434 (or http://127.0.0.1:11434)
```

**"Model too slow (>5 seconds per decision)"**

Try a smaller model:

```bash
ollama pull phi3:mini
export REX_OLLAMA_MODEL="phi3:mini"
```

Or check if your GPU is being used:

```bash
nvidia-smi  # NVIDIA
rocm-smi    # AMD
```

**"Out of memory"**

The model is too large for your RAM. Switch to a smaller one:

```bash
ollama pull gemma2:2b
export REX_OLLAMA_MODEL="gemma2:2b"
```

---

## Docker Compose (Full Stack with AI)

### 1. Configure

```bash
cp .env.example .env
# Edit .env:
#   REDIS_PASSWORD=$(openssl rand -hex 16)
#   (Ollama URL is already set to localhost:11434)
```

### 2. Start everything

```bash
# Start the infrastructure (Redis, Ollama, ChromaDB)
docker compose up -d

# Pull a model into the Ollama container
docker compose exec ollama ollama pull mistral:7b-instruct-v0.3-q4_K_M

# Check all services are healthy
docker compose ps
```

### 3. Verify

```bash
# Health check
curl http://localhost:8443/api/health
# {"status": "ok"}

# Full status (shows Redis + Ollama connectivity)
curl http://localhost:8443/api/status
# services.redis.healthy: true
# services.ollama.healthy: true
```

---

## What to Test

### Core pipeline (EYES -> BRAIN -> TEETH)
- Does `rex scan` discover devices on your network?
- Do threat events appear in the dashboard?
- Does REX classify threats correctly?
- With Ollama: does Layer 3 produce AI reasoning in the decision log?

### AI-specific tests
- Start REX without Ollama — does it enter degraded mode gracefully?
- Start Ollama while REX is running — does REX recover and enable Layer 3?
- Pull a different model — does `rex ai --status` show the new model?
- Feed a complex event — does the AI reasoning make sense?

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
- Check the LLM context — are hostnames sanitized before reaching the prompt?

---

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
- Ollama model download can be slow on first boot (4-40GB depending on model)
