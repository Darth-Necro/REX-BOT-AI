# REX-BOT-AI

```
    / \__
   (    @\___     ____  _______  __     ____   ____ _______
   /         O   |  _ \| ____\ \/ /    | __ ) / __ \__   __|
  /   (_____/    | |_) |  _|  \  / ____|  _ \| |  | | | |
 /_____/   U     |  _ <| |___ /  \|____| |_) | |  | | | |
                 |_| \_\_____|/_/\_\   |____/ \____/  |_|  AI
```

**v0.1.0-alpha** -- Local-first autonomous network security agent with Linux PAL, multi-layer AI decision pipeline, prompt injection defense, and 84% test coverage.

> This project is under active development and is **not ready for production use**. Do not rely on it as your sole network security solution.

---

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow.svg)]()

---

## What This Is

REX-BOT-AI is an open-source autonomous AI security agent for home and small business networks. It uses a local LLM (via Ollama) to reason about network threats and takes defensive actions through a whitelisted command system.

All 13 modules are implemented with real logic. The core security pipeline (EYES scan, BRAIN classify, TEETH enforce, BARK notify) is wired through Redis Streams. End-to-end Docker deployment is not yet verified.

## Current State (Honest)

| Component | Status |
|-----------|--------|
| Platform Abstraction Layer (Linux) | Working -- 2300 lines, real subprocess calls |
| Threat classifier (12 categories) | Working -- rule-based, no LLM required |
| Command executor (whitelisted) | Working -- zero shell=True, parameter validation |
| LLM client (localhost-only enforced) | Working -- Ollama integration with privacy boundary |
| Pydantic data models | Working -- Device, ThreatEvent, Decision, etc. |
| Redis event bus | Working -- publish/subscribe with WAL fallback |
| Network scanner (ARP + nmap) | Working -- device discovery via PAL |
| DNS monitor | Working -- query analysis, DGA detection |
| Device fingerprinter | Working -- MAC OUI, OS detection, type classification |
| Knowledge base (markdown) | Working -- REX-BOT-AI.md read/write/parse with git |
| Privacy/encryption module | Working -- Fernet secrets, audit tools |
| Agent security (scope, sanitizers) | Working -- prompt injection defense (30+ patterns), action whitelist |
| Dashboard API (FastAPI) | Working -- 11 routers, 44 endpoints, honest responses |
| Dashboard frontend (React) | **Partial** -- fetches real state on mount, not fully wired |
| Notification channels | **Partial** -- channel classes exist, not integration-tested |
| Plugin system | **Minimal** -- SDK defined, sandbox is a dict not Docker |
| Orchestrator | Working -- service lifecycle, health monitor, auto-restart |
| Docker deployment | **Unverified** -- compose file exists, end-to-end not tested |
| Installer (install.sh) | **Unverified** -- path alignment with Docker volumes pending |
| Windows/macOS/BSD PAL | **Stubs only** -- every method raises NotImplementedError |
| Test coverage | **84%** -- 2,979 tests (306 security pentests), 10 xfail |

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

## Architecture

REX is built as cooperating async services communicating via Redis Streams:

```
EYES (scan) -> Redis -> BRAIN (classify) -> TEETH (block) -> BARK (notify)
                                   |
                              MEMORY (log to REX-BOT-AI.md)
```

All OS-specific operations go through the Platform Abstraction Layer (PAL). The LLM is hardcoded to localhost only -- network data never leaves the machine.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Security Invariants

These are enforced in code, not just policy:

- **No `shell=True`** anywhere in the codebase. Commands use a whitelist with parameter validators.
- **LLM is localhost-only**. `OllamaClient` raises `PrivacyViolationError` for non-localhost URLs.
- **Network data is sanitized** before reaching the LLM (hostnames, banners stripped of injection attempts).
- **Firewall safety**: gateway and REX IPs are hardcoded as untargetable.
- **Action whitelist**: the LLM cannot execute actions not in the registry regardless of its output.

## Contributing

This project needs help. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

Priority areas:
1. Verify end-to-end Docker Compose deployment with live events
2. Integration tests with live Redis in CI
3. Wire frontend to all dashboard API endpoints
4. Replace plugin sandbox dict with real Docker isolation
5. Implement Windows/macOS/BSD PAL adapters

## License

MIT License. See [LICENSE](LICENSE).
