# REX-BOT-AI v0.1.0-alpha — Public Alpha Release

## What This Is

A **developer preview / public alpha** of REX-BOT-AI, a local-first autonomous network security agent. This release is for testing and feedback, not production security.

## Who This Is For

- Security enthusiasts who want to test a local AI-powered network monitor
- Developers interested in contributing to the project
- Home lab users who want to experiment with automated threat detection

## Supported Platforms

| Platform | Status |
|----------|--------|
| Linux (Ubuntu 22.04+, Debian 12+, Fedora 39+) | Supported |
| Python 3.11, 3.12 | Supported |
| Python 3.13+ | Not supported |
| macOS | Experimental (PAL stubs, many features missing) |
| Windows (WSL) | Experimental (use Ubuntu WSL) |
| Docker | Compose file provided, not fully verified |

## What Works

- Network device discovery (ARP + nmap)
- Threat detection and classification (12 categories, rule-based)
- AI-powered analysis via local Ollama LLM
- Dashboard with 26 pages (browser-based GUI, dark red/black theme)
- Forced first-run password creation (no default passwords)
- Auth state machine with `rex reset-auth` CLI recovery
- Firewall rule management (Linux iptables/nftables)
- 4 protection modes including Junkyard Dog
- REX Chat (AI assistant)
- ChromaDB vector memory (requires chromadb-client 1.5.7+)
- Privacy audit and data encryption
- Threat trend charts and severity breakdown

## What Does NOT Work / Is Experimental

- Docker end-to-end deployment (not verified on clean machines)
- Notification channels (Discord, Telegram, Email, Matrix — classes exist but not integration-tested)
- Federation (peer-to-peer threat sharing — opt-in, not battle-tested)
- Plugin system (SDK defined, sandbox partially implemented)
- Windows/macOS/BSD support (stub adapters only)
- K9-Engine local LLM (not tested end-to-end)

## Security Disclaimer

**Do not rely on REX-BOT-AI as your sole network security solution.** This is alpha software under active development. It may have bugs, miss threats, or produce false positives. Use it alongside, not instead of, established security tools.

## How to Report Security Issues

Email: security@rexbot.ai (or open a GitHub Issue for non-sensitive matters)

## Known Issues

See [GitHub Issues](https://github.com/Darth-Necro/REX-BOT-AI/issues) for the current list.
