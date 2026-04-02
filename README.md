# REX-BOT-AI

```  ^
    / \__
   (    @\___     ____  _______  __     ____   ____ _______
   /         O   |  _ \| ____\ \/ /    | __ ) / __ \__   __|
  /   (_____/    | |_) |  _|  \  / ____|  _ \| |  | | | |
 /_____/   U     |  _ <| |___ /  \|____| |_) | |  | | | |
                 |_| \_\_____|/_/\_\   |____/ \____/  |_|  AI
```

**v0.1.0-alpha** -- Local-first autonomous network security agent. Linux-primary, with experimental macOS/Windows/BSD support. Multi-layer AI decision pipeline, prompt injection defense, and per-service event bus isolation.

> This project is under active development and is **not ready for production use**. Do not rely on it as your sole network security solution.

---

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11–3.12](https://img.shields.io/badge/python-3.11%E2%80%933.12-blue.svg)](https://www.python.org/downloads/)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow.svg)]()

---

## What This Is

REX-BOT-AI is an open-source autonomous AI security agent for home and small business networks. It uses a local LLM (via Ollama) to reason about network threats and takes defensive actions through a whitelisted command system.

All 13 modules are implemented with real logic. The core security pipeline (EYES scan, BRAIN classify, TEETH enforce, BARK notify) is wired through Redis Streams with per-service consumer groups. End-to-end Docker deployment is not yet verified.

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
| Windows/macOS/BSD PAL | **Experimental** -- core methods implemented, many features raise NotImplementedError |
| Test suite | 4,062 tests, 0 failures, 22 warnings |

## Architecture

REX is built as cooperating async services, each with its own EventBus instance and Redis consumer group:

```
EYES (scan) -> Redis -> BRAIN (classify) -> TEETH (block) -> BARK (notify)
                                   |
                              MEMORY (log to REX-BOT-AI.md)
```

Each service owns its bus connection. Consumer groups are isolated (`rex:<service>:group`) so every subscribing service sees every event -- no message stealing between services.

All OS-specific operations go through the Platform Abstraction Layer (PAL). The LLM is hardcoded to localhost only -- network data never leaves the machine.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Security Invariants

These are enforced in code, not just policy:

- **No `shell=True`** anywhere in the codebase. Commands use a whitelist with parameter validators.
- **LLM is localhost-only**. `OllamaClient` raises `PrivacyViolationError` for non-localhost URLs.
- **Network data is sanitized** before reaching the LLM (hostnames, banners stripped of injection attempts).
- **Firewall safety**: gateway and REX IPs are hardcoded as untargetable, with IP normalization (zero-padded, IPv6-mapped, decimal forms all blocked).
- **Action whitelist**: the LLM cannot execute actions not in the registry regardless of its output.
- **Scope enforcement**: out-of-scope request patterns override security keyword matches to prevent disguised-request bypass.
- **CORS safety**: wildcard origins are stripped when `allow_credentials=True`.
- **WebSocket auth**: first-message auth only — JWTs are never sent in URLs/query strings.
- **Password hashing**: bcrypt with SHA-256 pre-hashing to prevent 72-byte truncation attacks.
- **Restart anti-flapping**: sliding-window restart budget with exponential backoff prevents restart storms.
- **Credential storage**: plaintext fallback only when encrypted storage is unavailable; plaintext removed on migration.

## Development Setup

```bash
git clone https://github.com/Darth-Necro/REX-BOT-AI.git
cd REX-BOT-AI
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -r requirements-dev.txt

# Run tests
pytest

# Lint
ruff check rex/ tests/
```

## CLI Commands

```bash
rex start      # Start all services (blocks until Ctrl+C)
rex stop       # Stop all services gracefully
rex status     # Show service health
rex scan       # Trigger manual network scan
rex sleep      # Put REX into alert-sleep mode
rex wake       # Wake REX to full monitoring
rex diag       # Full diagnostic dump
rex backup     # Create data backup
rex privacy    # Run privacy audit
rex version    # Print version string
```

## Contributing

This project needs help. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

Priority areas:
1. Verify end-to-end Docker Compose deployment with live events
2. Integration tests with live Redis in CI
3. Wire remaining frontend components to all dashboard API endpoints
4. Replace plugin sandbox dict with real Docker isolation
5. Implement Windows/macOS/BSD PAL adapters

## License

MIT License. See [LICENSE](LICENSE).
