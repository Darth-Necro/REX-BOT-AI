# REX-BOT-AI

```
    / \__
   (    @\___     ____  _______  __     ____   ____ _______
   /         O   |  _ \| ____\ \/ /    | __ ) / __ \__   __|
  /   (_____/    | |_) |  _|  \  / ____|  _ \| |  | | | |
 /_____/   U     |  _ <| |___ /  \|____| |_) | |  | | | |
                 |_| \_\_____|/_/\_\   |____/ \____/  |_|  AI
```

**BETA** -- Local-first network security agent with Linux PAL, agent-policy foundation, and local LLM integration.

> This project is under active development. Do not rely on it as your sole network security solution.

---

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Status: Beta](https://img.shields.io/badge/status-beta-yellow.svg)]()

---

## What This Is

REX-BOT-AI aims to be an open-source autonomous AI security agent for home and small business networks. It uses a local LLM (via Ollama) to reason about network threats and takes defensive actions through a whitelisted command system.

The project has substantial low-level modules (Linux platform adapter, threat classifier, command executor, privacy enforcement) but the product surface (dashboard, installer, end-to-end orchestration) is incomplete.

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
| Agent security (scope, sanitizers) | Working -- prompt injection defense, action whitelist |
| Dashboard API (FastAPI) | **Stubbed** -- endpoints exist but return hard-coded data |
| Dashboard frontend (React) | **Skeleton** -- components exist but not wired to real data |
| Notification channels | **Partial** -- channel classes exist, not integration-tested |
| Plugin system | **Minimal** -- SDK defined, no real plugin execution |
| Orchestrator | **Partial** -- starts services but not fully lifecycle-managed |
| Docker deployment | **Broken** -- networking and entrypoint issues being fixed |
| Installer (install.sh) | **Broken** -- curl pipe mode does not work correctly |
| Windows/macOS/BSD PAL | **Stubs only** -- every method raises NotImplementedError |
| Test coverage | **~13%** -- critical paths tested, most modules untested |

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

## Known Limitations (Alpha)

Before using REX-BOT-AI, be aware of these current limitations:

- **Linux only**: macOS, Windows, and BSD platform adapters are stubs (`NotImplementedError`). Only Linux is supported.
- **Single admin user**: No role-based access control. One admin account with bcrypt + JWT auth.
- **No plugin signing**: Plugins are loaded without cryptographic integrity verification. The plugin sandbox is not yet real container isolation.
- **External DNS leakage**: The command executor whitelist includes `whois` and `dig`, which send queries to external DNS/WHOIS servers. This is a known exception to the "no external connections" privacy claim.
- **End-to-end integration not fully validated**: Individual services are tested, but the full `docker compose up` -> event pipeline has not been integration-tested.
- **Test coverage ~52%**: Critical security paths are well-tested (252 pentest tests), but overall coverage is below the 70% target.
- **Dashboard partially stubbed**: Some API endpoints return placeholder data. The React frontend is functional but not feature-complete.

**Do not rely on REX-BOT-AI as your sole network security solution.**

## Contributing

This project needs help. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

Priority areas:
1. Wire dashboard API to real service data (replace hard-coded responses)
2. Integration tests for the EYES->BRAIN->TEETH pipeline
3. Frontend login flow and WebSocket authentication
4. Fix Docker Compose networking for end-to-end deployment
5. Grow test coverage beyond 13%

## License

MIT License. See [LICENSE](LICENSE).
