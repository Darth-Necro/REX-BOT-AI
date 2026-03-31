# REX-BOT-AI

```
    / \__
   (    @\___     ____  _______  __     ____   ____ _______
   /         O   |  _ \| ____\ \/ /    | __ ) / __ \__   __|
  /   (_____/    | |_) |  _|  \  / ____|  _ \| |  | | | |
 /_____/   U     |  _ <| |___ /  \|____| |_) | |  | | | |
                 |_| \_\_____|/_/\_\   |____/ \____/  |_|  AI
```

**REX-BOT-AI is an open-source AI security agent that protects your home or business network. One click. Zero configuration. Always watching.**

---

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

---

## Install

```bash
curl -sSL https://install.rexbot.ai | bash
```

Or install manually:

```bash
git clone https://github.com/REX-BOT-AI/rex-bot-ai.git
cd rex-bot-ai
pip install -e .
rex start
```

## Quick Start

1. **Install REX** -- run the one-liner above or clone the repo.
2. **Launch** -- `rex start` boots up the dashboard, scanner, and AI engine.
3. **Open the dashboard** -- navigate to `https://localhost:8443` in your browser.

That is it. REX auto-detects your network interface, starts scanning, and begins learning what "normal" looks like on your network.

## Features

| Feature                        | Status         |
|--------------------------------|----------------|
| Network discovery and mapping  | Implemented    |
| Real-time traffic analysis     | Implemented    |
| AI threat classification       | Implemented    |
| Local LLM via Ollama           | Implemented    |
| Web dashboard (HTTPS)          | Implemented    |
| Automated incident response    | Implemented    |
| DNS sinkhole                   | Implemented    |
| Honeypot services              | Implemented    |
| Vulnerability scanning         | Implemented    |
| Notification system            | Implemented    |
| Vector memory (ChromaDB)       | Implemented    |
| Plugin system                  | In Progress    |
| Multi-node mesh                | In Progress    |
| Mobile companion app           | Planned        |
| SIEM integration (Wazuh/ELK)   | Planned        |
| Hardware appliance image       | Planned        |

## Architecture

REX-BOT-AI is built as a set of cooperating async services orchestrated by a central engine:

```
                     +------------------+
                     |   Web Dashboard  |
                     |  (FastAPI/HTTPS) |
                     +--------+---------+
                              |
                     +--------+---------+
                     |    REX Engine     |
                     |  (Orchestrator)   |
                     +--------+---------+
                              |
          +-------------------+-------------------+
          |           |           |                |
   +------+---+ +----+----+ +---+------+  +------+------+
   | Network  | |  Threat | |  AI/LLM  |  | Notification|
   | Scanner  | | Detector| | (Ollama) |  |   Service   |
   +------+---+ +----+----+ +---+------+  +-------------+
          |           |           |
   +------+-----------+-----------+------+
   |              Redis Bus              |
   +----------------+-------------------+
                    |
          +---------+---------+
          |  ChromaDB Vector  |
          |     Memory        |
          +-------------------+
```

- **REX Engine** -- coordinates all subsystems, manages scheduling, and handles lifecycle.
- **Network Scanner** -- uses Scapy and Nmap for host discovery, port scanning, and traffic capture.
- **Threat Detector** -- rule engine plus AI classification for anomaly detection.
- **AI/LLM** -- local inference via Ollama; analyzes packets, classifies threats, generates reports.
- **Redis Bus** -- pub/sub event bus and state cache shared across all services.
- **ChromaDB** -- vector store for long-term memory, threat signatures, and pattern matching.
- **Web Dashboard** -- HTTPS-only FastAPI application for monitoring, configuration, and alerts.
- **Notification Service** -- multi-channel alerts via Discord, Telegram, Matrix, Email, and more.

## Configuration

Copy the example environment file and adjust values as needed:

```bash
cp .env.example .env
```

All configuration can also be managed through the web dashboard after first launch.

See the [docs/](docs/) directory for detailed configuration reference.

## Development

```bash
# Clone and install in development mode
git clone https://github.com/REX-BOT-AI/rex-bot-ai.git
cd rex-bot-ai
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .

# Run tests
pytest

# Lint and type check
ruff check .
mypy rex/
```

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) before opening a pull request.

1. Fork the repository.
2. Create a feature branch from `main`.
3. Write tests for your changes.
4. Ensure `pytest`, `ruff check .`, and `mypy rex/` all pass.
5. Open a pull request with a clear description.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
