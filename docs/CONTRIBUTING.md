# Contributing to REX-BOT-AI

Thank you for your interest in contributing to REX-BOT-AI. This document covers everything you need to get started.

---

## Development Environment Setup

### Prerequisites

- Python 3.11 or 3.12 (3.13 not yet supported)
- Docker and Docker Compose v2
- Node.js 18+ and npm (for frontend development)
- Git
- Redis 7+ (runs in Docker, or install locally for faster iteration)

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/Darth-Necro/REX-BOT-AI.git
cd REX-BOT-AI

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e .
pip install -r requirements-dev.txt

# Install frontend dependencies (uses .npmrc for registry config)
cd frontend && npm install && cd ..

# Note: The frontend uses ESLint v9 flat config (eslint.config.js, not .eslintrc).
# See frontend/eslint.config.js for details.

# Start infrastructure (Redis, Ollama, ChromaDB)
docker compose up -d redis ollama chromadb

# Verify everything works
make test
make lint
```

### Makefile Targets

| Target           | Description                                       |
|------------------|---------------------------------------------------|
| `make help`      | Show all available targets                        |
| `make build`     | Build all Docker images                           |
| `make up`        | Start all services in Docker                      |
| `make down`      | Stop all services                                 |
| `make test`      | Run all tests with pytest                         |
| `make test-cov`  | Run tests with coverage report                    |
| `make lint`      | Run ruff linter and formatter check               |
| `make lint-fix`  | Auto-fix lint issues                              |
| `make typecheck` | Run mypy type checking                            |
| `make dev`       | Start API server with hot reload                  |
| `make dev-frontend` | Start Vite frontend dev server                 |
| `make clean`     | Remove build artifacts and Docker volumes         |
| `make compile-check` | Verify all Python files compile               |
| `make security-check` | Check for shell=True and hardcoded secrets   |

---

## Project Structure

```
rex-bot-ai/
  rex/                      # Python backend (all services)
    bark/                   #   Notification engine
      bridges/              #     Channel implementations (Discord, Telegram, etc.)
      channels/             #     Channel configuration
      formatter.py          #     Alert formatting
      manager.py            #     Channel management
      service.py            #     BaseService implementation
    brain/                  #   AI decision engine
      baseline.py           #     Behavioral baseline learning
      classifier.py         #     Signature-based threat classifier
      decision.py           #     4-layer decision pipeline
      llm.py                #     Ollama client, sanitizer, LLM router
      prompts.py            #     LLM prompt templates
      service.py            #     BaseService implementation
    core/                   #   Orchestrator and security boundaries
      agent/                #     Command executor, action validator, sanitizers
      cli.py                #     Typer CLI (rex start, rex status, etc.)
      health.py             #     Health aggregation
      mode_manager.py       #     Operating mode management
      orchestrator.py       #     Service lifecycle manager
      privacy/              #     Privacy controls
      tier_detector.py      #     Hardware tier detection
    dashboard/              #   FastAPI REST API and WebSocket
      app.py                #     Application factory
      auth.py               #     JWT authentication
      deps.py               #     Dependency injection
      routers/              #     API route handlers
      websocket.py          #     WebSocket manager
    eyes/                   #   Network monitoring
      device_store.py       #     In-memory device inventory
      dns_monitor.py        #     Passive DNS capture
      fingerprinter.py      #     Device fingerprinting (OUI, banners)
      port_scanner.py       #     TCP/UDP port scanning
      scanner.py            #     ARP-based device discovery
      service.py            #     BaseService implementation
      traffic.py            #     Traffic anomaly detection
    federation/             #   Peer-to-peer threat intel sharing
    interview/              #   Onboarding wizard
      engine.py             #     Interview state machine
      processor.py          #     Answer processing
      question_bank.py      #     Adaptive question bank
      service.py            #     BaseService implementation
    memory/                 #   Knowledge base and threat log
      knowledge.py          #     Git-versioned KB management
      templates/            #     Jinja2 templates for KB generation
      threat_log.py         #     Structured threat history
      vector_store.py       #     ChromaDB semantic search
      versioning.py         #     Git operations
      service.py            #     BaseService implementation
    pal/                    #   Platform Abstraction Layer
      base.py               #     Abstract adapter interface
      linux.py              #     Linux implementation
      macos.py              #     macOS implementation
      bsd.py                #     BSD implementation
      windows.py            #     Windows implementation
      detector.py           #     Platform and hardware detection
      docker_helper.py      #     Docker operations
    scheduler/              #   Time-based task management
      cron.py               #     Cron expression parsing
      power.py              #     Power state management
      scan_scheduler.py     #     Scan timing logic
      service.py            #     BaseService implementation
    shared/                 #   Layer 0 foundation
      bus.py                #     Redis Streams EventBus + SQLite WAL
      config.py             #     Centralized configuration
      constants.py          #     Stream names, timeouts, limits
      enums.py              #     All enumeration types
      errors.py             #     Exception hierarchy
      events.py             #     Typed event classes
      models.py             #     Pydantic domain models
      service.py            #     BaseService abstract class
      types.py              #     Type aliases
      utils.py              #     Utility functions
    store/                  #   Plugin management
      manager.py            #     Plugin lifecycle
      registry.py           #     Plugin registry client
      sandbox.py            #     Docker-based sandboxing
      sdk/                  #     Plugin SDK
        base_plugin.py      #       RexPlugin abstract base class
        plugin_api.py       #       REST API for plugins
      service.py            #     BaseService implementation
  frontend/                 # React 18 dashboard SPA
    src/
      api/                  #   REST API client
      components/           #   Reusable UI components
      stores/               #   State management
      views/                #   Page-level components
      ws/                   #   WebSocket client
  tests/                    # Test suite
  docs/                     # Documentation (you are here)
  scripts/                  # Utility scripts
  docker-compose.yml        # Multi-service orchestration
  Dockerfile                # REX container image
  Makefile                  # Build and development targets
  pyproject.toml            # Python project configuration
  requirements.txt          # Production dependencies
  requirements-dev.txt      # Development dependencies
```

---

## Code Style

### Python

- **Linter and formatter**: Ruff (configured in `pyproject.toml`).
- **Target version**: Python 3.11.
- **Line length**: 100 characters.
- **Rule sets**: pycodestyle, pyflakes, isort, pep8-naming, pyupgrade, flake8-bugbear, flake8-bandit, flake8-print, flake8-simplify, flake8-type-checking, ruff-specific.

Run the linter:

```bash
make lint        # Check for issues
make lint-fix    # Auto-fix
```

### Type Hints

All functions must have complete type annotations. REX uses `mypy --strict` for type checking.

```python
# Good
async def evaluate_event(self, event: ThreatEvent) -> Decision:
    ...

# Bad -- missing return type and parameter types
async def evaluate_event(self, event):
    ...
```

Run the type checker:

```bash
make typecheck
```

### Docstrings

All public classes, methods, and functions must have docstrings. Use the NumPy/Sphinx style:

```python
async def publish(self, stream: StreamName, event: RexEvent) -> str:
    """Publish an event to a Redis stream.

    The stream is capped at ``STREAM_MAX_LEN`` entries using
    approximate trimming.

    Parameters
    ----------
    stream:
        Target Redis stream key.
    event:
        The event to publish.

    Returns
    -------
    str
        The Redis stream message ID (e.g. ``"1234567890-0"``).

    Raises
    ------
    RexBusUnavailableError
        If the event could not be written to Redis.
    """
```

### Module Header

Every module should start with a docstring explaining its purpose, layer, and imports:

```python
"""Brief description of what this module does.

Layer N -- imports only from stdlib, <external deps>, and sibling shared modules.

Detailed explanation of the module's responsibilities and usage.
"""
```

### Import Ordering

Ruff's `isort` rule handles import ordering automatically. The convention is:

1. `from __future__ import annotations`
2. Standard library
3. Third-party packages
4. `rex.shared.*` (Layer 0)
5. Other `rex.*` modules

---

## Testing Requirements

### Framework

- **Test runner**: pytest with pytest-asyncio
- **Async mode**: Auto (configured in `pyproject.toml`)
- **Markers**: `slow` (for tests over 5 seconds), `integration` (requires Redis/Ollama/Docker)

### Coverage Minimum

All pull requests must maintain at least **70% code coverage**. Run the coverage report:

```bash
make test-cov
```

The HTML report is generated in `htmlcov/`.

### Test Organization

- Tests mirror the source structure: `tests/test_shared/`, `tests/test_brain/`, etc.
- Unit tests should not require external services. Mock Redis, Ollama, and Docker.
- Integration tests (marked with `@pytest.mark.integration`) may require running infrastructure.

### Writing Tests

```python
# tests/test_brain/test_decision.py
import pytest
from rex.brain.decision import DecisionEngine
from rex.shared.enums import DecisionAction, ThreatSeverity
from rex.shared.models import ThreatEvent


@pytest.fixture
def engine(mock_classifier, mock_baseline):
    """Create a DecisionEngine with mocked dependencies."""
    return DecisionEngine(
        llm_router=None,  # No LLM -- tests L1/L2 only
        classifier=mock_classifier,
        baseline=mock_baseline,
    )


@pytest.mark.asyncio
async def test_critical_threat_blocked(engine):
    """Critical threats with high confidence should produce BLOCK decisions."""
    event = ThreatEvent(
        threat_type="c2_communication",
        severity="critical",
        description="Known C2 domain contacted",
        confidence=0.95,
    )
    decision = await engine.evaluate_event(event)
    assert decision.action == DecisionAction.BLOCK
    assert decision.layer == 1
    assert decision.auto_executed is True
```

### Test Markers

```python
@pytest.mark.slow
async def test_full_scan_cycle():
    """This test takes 30+ seconds."""
    ...

@pytest.mark.integration
async def test_redis_publish():
    """Requires a running Redis instance."""
    ...
```

Run tests excluding slow/integration:

```bash
python -m pytest tests/ -m "not slow and not integration"
```

---

## Pull Request Process

### 1. Fork and Branch

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/rex-bot-ai.git
cd REX-BOT-AI
git remote add upstream https://github.com/Darth-Necro/REX-BOT-AI.git

# Create a feature branch
git checkout -b feature/my-improvement
```

### 2. Make Changes

- Follow the code style guidelines above.
- Add tests for new functionality.
- Update documentation if behavior changes.

### 3. Test

```bash
make lint
make typecheck
make test-cov
make security-check
make compile-check
```

All of these must pass before submitting.

### 4. Commit

Write clear, descriptive commit messages:

```
Add behavioral baseline deviation scoring to Brain L2

The statistical layer now computes a weighted deviation score
between a device's current behavior and its learned baseline.
Deviation scores above 0.3 are flagged in the decision reasoning.
```

### 5. Submit

```bash
git push origin feature/my-improvement
```

Open a pull request on GitHub. Include:

- A clear description of what the PR does and why.
- Test output showing all tests pass.
- Coverage report if adding significant new code.
- Link to any related issues.

### 6. Review

- At least one maintainer must approve the PR.
- All CI checks must pass.
- Coverage must not drop below 70%.
- No new `shell=True` usage, hardcoded secrets, or disabled security controls.

---

## Security Considerations for Contributors

When contributing code, keep these security invariants in mind:

1. **Never use `shell=True`** in subprocess calls. Always use `asyncio.create_subprocess_exec` with an explicit argv list. The `make security-check` target verifies this.

2. **Never send raw network data to external APIs**. If you add an external integration, all network-derived data must pass through the `DataSanitizer` first.

3. **Validate all inputs**. Use Pydantic models for API request bodies. Use typed validators for command parameters.

4. **Never hardcode secrets**. Use environment variables or the config system. The `make security-check` target looks for common patterns.

5. **Maintain the localhost-only LLM invariant** for Brain 1 (security analysis). Brain 2 (assistant) may use external providers, but only with sanitized data.

6. **Add injection pattern tests** when modifying the network data sanitizer or web content sanitizer.

7. **Log security-relevant events** at WARNING or higher. Include enough context for audit, but never log raw credentials or full packet captures.

8. **Respect the permission model** in plugin API code. Always check permissions before returning data.

---

## Architecture Decision Records (ADR)

When making significant architectural decisions, document them as ADR files in `docs/adr/`:

### Format

```markdown
# ADR-NNN: Title

## Status
Proposed | Accepted | Deprecated | Superseded by ADR-MMM

## Context
What is the problem or situation that requires a decision?

## Decision
What is the decision that was made?

## Consequences
What are the positive and negative outcomes of this decision?
```

### When to Write an ADR

- Adding a new service or module
- Changing the event bus protocol or stream format
- Modifying the security model
- Changing the LLM provider strategy
- Modifying the plugin sandbox model
- Adding a new external dependency

### Examples of Past Decisions

- **ADR-001**: Use Redis Streams over RabbitMQ for the event bus (simplicity, no broker management).
- **ADR-002**: Localhost-only LLM enforcement (privacy guarantee).
- **ADR-003**: SQLite WAL fallback when Redis is unavailable (zero event loss).
- **ADR-004**: Four-layer decision pipeline with hard 10-second timeout (latency predictability).
- **ADR-005**: Docker-based plugin sandboxing over process-level isolation (stronger boundaries).

---

## Code of Conduct

This project follows the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

**In summary**: Be respectful, inclusive, and constructive. Harassment, discrimination, and personal attacks are not tolerated. Focus on the technical merits of contributions. Assume good intent. Give and accept constructive feedback gracefully.

Violations can be reported to the project maintainers. All reports are reviewed and responded to in confidence.

The full text of the Contributor Covenant is available at: https://www.contributor-covenant.org/version/2/1/code_of_conduct/
