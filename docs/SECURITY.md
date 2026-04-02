# REX-BOT-AI Security Model

## Security Philosophy

REX-BOT-AI operates under a strict **defense-in-depth** model. No single security control is trusted to be sufficient on its own. Every layer assumes the layer above it may be compromised and enforces its own invariants independently.

The three foundational principles are:

1. **Privacy by architecture**: Network security data never leaves the local machine. The LLM runs locally via Ollama with a hardcoded localhost-only restriction. No telemetry, no cloud analytics, no external API calls with raw network data.

2. **Least privilege**: REX requests only the OS capabilities it needs (CAP_NET_ADMIN, CAP_NET_RAW), runs with a read-only root filesystem, drops all container capabilities not explicitly required, and executes system commands through a strict whitelist.

3. **Assume breach**: Even if an attacker manages to inject a prompt through a crafted hostname or service banner, the command executor's whitelist prevents any unauthorized action, the action validator gates every operation, and all actions are audit-logged for operator review.

---

## Self-Hardening Checklist

When REX starts, it performs and enforces the following security measures:

- [ ] **Verify LLM endpoint is localhost**: `OllamaClient` checks that the URL hostname is in `{127.0.0.1, localhost, ::1}`. Raises `PrivacyViolationError` and enters degraded mode if not.
- [ ] **Set credential file permissions**: `.credentials` file is `chmod 0o600` (owner read/write only).
- [ ] **Generate cryptographic secrets**: JWT secret (32 bytes hex) and initial admin password (24 bytes URL-safe) are generated via `secrets` module.
- [ ] **Enable security headers**: CSP (`default-src 'self'`), X-Frame-Options (DENY), X-Content-Type-Options (nosniff), X-XSS-Protection, Referrer-Policy.
- [ ] **Validate all inputs**: Every API endpoint uses Pydantic models for request validation. Query parameters are bounded (e.g., `limit: int = Query(50, ge=1, le=500)`).
- [ ] **Read-only container**: Docker container runs with `read_only: true` and `no-new-privileges: true`.
- [ ] **Internal network isolation**: Infrastructure services (Redis, Ollama, ChromaDB) run on a `bridge` network with `internal: true`.
- [ ] **Disable telemetry**: Ollama (`OLLAMA_NOTELEMETRY=1`) and ChromaDB (`ANONYMIZED_TELEMETRY=false`) telemetry explicitly disabled.
- [ ] **WAL fallback initialized**: SQLite write-ahead log created in `<data_dir>/.wal/` so events are never silently lost.
- [ ] **Audit logging enabled**: Every command execution (including rejections) is logged with timestamp, command, parameters, and outcome.

---

## Privacy Guarantees

### Local-Only Data Processing

- All network traffic analysis happens on the local machine.
- The LLM (Ollama) runs locally. The `OllamaClient` enforces `ALLOWED_HOSTS = {127.0.0.1, localhost, ::1}` at construction time.
- The vector store (ChromaDB) runs locally.
- Redis runs locally on a Docker-internal bridge network.
- The knowledge base is a local git repository.

### No Cloud, No Telemetry

- REX makes zero external API calls by default.
- Ollama telemetry is disabled via environment variable.
- ChromaDB anonymized telemetry is disabled.
- Federation (peer-to-peer intel sharing) is disabled by default and must be explicitly enabled.
- The `/api/privacy/status` endpoint is unauthenticated and returns the current privacy posture:

```json
{
  "data_local_only": true,
  "external_connections": 0,
  "encryption_at_rest": true,
  "telemetry_enabled": false
}
```

### Data Sanitization for External Use

If an operator configures an external LLM provider for Brain 2 (assistant/chat, not security analysis), the `DataSanitizer` automatically:

- Replaces all IPv4 and IPv6 addresses with deterministic placeholders (`[IP_1]`, `[IP_2]`)
- Replaces MAC addresses with `[MAC_1]`, `[MAC_2]`, etc.
- Replaces hostnames and FQDNs with `[HOST_1]`, `[HOST_2]`
- Replaces email addresses with `[EMAIL_1]`, `[EMAIL_2]`
- Replaces file system paths with `[PATH_1]`, `[PATH_2]`
- Replaces SSIDs with `[SSID_1]`, `[SSID_2]`
- Audit-logs every external query with timestamp, prompt length, and sanitization flag.

Brain 1 (security analysis) is **never** routed to an external provider. This invariant is enforced at `LLMRouter` construction time.

---

## Threat Model

### What REX Protects Against

| Threat Category        | Detection Method                                  | Response                              |
|------------------------|---------------------------------------------------|---------------------------------------|
| Rogue devices          | ARP scanning, MAC monitoring                      | Alert, quarantine, block              |
| Port scanning          | Traffic anomaly detection, rate analysis           | Alert, rate-limit, block              |
| Brute force attacks    | Connection frequency monitoring                   | Alert, block source IP                |
| Lateral movement       | Behavioral deviation, unusual port access          | Alert, quarantine                     |
| C2 communication       | DNS monitoring, threat feed matching               | Block, DNS sinkhole                   |
| Data exfiltration      | Bandwidth anomaly, destination analysis            | Alert, rate-limit, block              |
| ARP spoofing           | ARP table monitoring, duplicate IP detection       | Alert, block                          |
| DNS tunneling          | DNS query entropy analysis, length anomaly         | Block domain, DNS sinkhole            |
| Exposed services       | External port scan, gateway analysis               | Alert with remediation guidance       |
| IoT compromise         | Behavioral baseline deviation                      | Alert, quarantine                     |
| Malware callbacks      | DNS/IP threat feed matching                        | Block, DNS sinkhole, alert            |
| Default credentials    | Known default port/service detection               | Alert with remediation guidance       |

### What REX Does NOT Protect Against

- **Encrypted traffic content**: REX inspects network metadata (IPs, ports, DNS queries, packet sizes) but does not perform TLS interception or DPI on encrypted payloads.
- **Physical access attacks**: If an attacker has physical access to the network equipment or the REX host, REX cannot prevent hardware-level compromise.
- **Zero-day exploits on the REX host itself**: REX does not monitor its own host for kernel exploits or container escapes.
- **Attacks on the upstream ISP**: REX operates at the LAN level and cannot detect or mitigate attacks occurring upstream of the gateway.
- **Social engineering**: REX cannot prevent users from voluntarily disclosing credentials or installing malware.
- **Compromise of the LLM model weights**: If the local Ollama model itself has been tampered with, REX's LLM layer could produce incorrect decisions. Layers 1-2 (non-LLM) still operate correctly.

---

## Attack Surface Analysis

### Dashboard (Port 8443)

- **Exposure**: HTTPS on configurable port, default 8443.
- **Authentication**: JWT with HS256, 4-hour expiry.
- **Rate limiting**: 5 failed login attempts trigger 30-minute lockout.
- **Headers**: CSP restricts script sources to `'self'`, frames to `'none'`.
- **CORS**: Default same-origin; configurable in production.
- **Mitigation**: Bind to `127.0.0.1` if remote access is not needed. Use a reverse proxy with TLS termination in production.

### DNS Proxy

- **Exposure**: Listens on port 53 (UDP/TCP) when DNS blocking is active.
- **Risk**: DNS cache poisoning, amplification attacks.
- **Mitigation**: Only binds to the LAN interface. Validates DNS query format. Does not recurse to upstream for blocked domains (returns NXDOMAIN immediately).

### VPN/Network Interface

- **Exposure**: REX captures packets on the configured network interface.
- **Risk**: Crafted packets could exploit Scapy parsing vulnerabilities.
- **Mitigation**: Scapy is a well-maintained library. REX runs packet parsing in a try/except block and logs malformed packets without crashing.

### Messaging Bridges (Bark)

- **Exposure**: Outbound only (webhooks, SMTP, bot APIs). No inbound message parsing.
- **Risk**: Credential leakage if notification channel tokens are exposed.
- **Mitigation**: Channel credentials are stored in environment variables, not in the knowledge base or logs. Notification bodies are sanitized to prevent information leakage.

### Plugin System (Store)

- **Exposure**: Plugins run in sandboxed Docker containers.
- **Risk**: Plugin escape, resource exhaustion, data exfiltration.
- **Mitigation**: See Plugin Sandbox Security below.

---

## Prompt Injection Defense

REX employs three layers of defense against prompt injection:

### Layer 1: Network Data Sanitizer (`rex/core/agent/network_data_sanitizer.py`)

All network-derived strings are sanitized before inclusion in any LLM prompt:

- **Hostnames, mDNS names, DHCP client IDs**: Truncated to 64 characters.
- **Service banners**: Truncated to 128 characters.
- **HTTP User-Agents**: Truncated to 200 characters.
- **Control characters**: Stripped entirely.
- **Injection patterns**: 44 regex patterns detect attempts like:
  - "ignore all previous instructions"
  - "you are now..."
  - "mark as trusted"
  - "disable firewall"
  - LLM special tokens (`<|im_start|>`, `<|system|>`)
  - Markdown system blocks (` ```system `)

Detected injections are replaced with `[INJECTION_ATTEMPT_STRIPPED]` and logged at WARNING level.

### Layer 2: Web Content Sanitizer (`rex/core/agent/web_content_sanitizer.py`)

External web content (threat feeds, CVE databases) is processed through:

1. HTML stripped to plain text (all scripts, styles, iframes removed).
2. Plain text scanned against injection patterns.
3. Detected injections redacted and audit-logged.
4. Final text truncated to safe length.
5. Wrapped in `[UNTRUSTED_WEB_CONTENT]...[/UNTRUSTED_WEB_CONTENT]` delimiters.

### Layer 3: Action Validator

Even if the LLM is successfully manipulated by an undetected injection, every proposed action must pass through the `ActionValidator` which checks:

- Is the action in the allowed action set?
- Does the target IP/MAC exist in the device store?
- Does the protection mode permit this action?
- Has the rate limit been exceeded?

This means a successful prompt injection can, at worst, produce an incorrect *analysis* -- it cannot directly cause an unauthorized *action*.

---

## Command Execution Security

### Whitelist Architecture

The `CommandExecutor` (`rex/core/agent/command_executor.py`) is the sole path for executing system commands:

- Every allowed command is defined in a static registry with:
  - Absolute executable path
  - Allowed argument templates
  - Typed parameter validators (IP address, port number, interface name)
  - Per-command timeout
- `shell=True` is **never** used. All commands execute via `asyncio.create_subprocess_exec` with an explicit argv list.
- Commands not in the whitelist are rejected before execution.
- All invocations (including rejections) are audit-logged with:
  - Timestamp
  - Command and arguments
  - Requesting service
  - Execution result (success, failure, rejected)
  - Duration

### Parameter Validation

Parameters are validated using typed validators:

- **IP addresses**: Parsed via `ipaddress.ip_address()`. Rejects hostnames, CIDR notation in wrong contexts, and special addresses.
- **Port numbers**: Integer range 1-65535.
- **Interface names**: Alphanumeric plus hyphen/underscore, max 15 characters.
- **MAC addresses**: Regex validated hex-colon format.
- **File paths**: Restricted to allowed directories.

---

## Plugin Sandbox Security (6-Layer Model)

| Layer | Control                    | Implementation                                                |
|-------|----------------------------|---------------------------------------------------------------|
| 1     | Resource limits            | CPU (default 50% of one core), RAM (256 MB), disk (100 MB)  |
| 2     | Network isolation          | Plugins run on `rex-internal` network only; no internet       |
| 3     | Filesystem isolation       | Read-only root filesystem in container                        |
| 4     | Capability dropping        | `cap_drop: ALL`, `no_new_privileges: true`                   |
| 5     | API gating                 | Plugin API endpoints check permissions from manifest          |
| 6     | No shell access            | No shell binary in plugin container image                     |

Plugins communicate with REX exclusively through the Plugin API (`/plugin-api/*`), authenticated with a per-plugin API token. Each request is checked against the plugin's declared `permissions` from its manifest.

Plugin crashes are auto-restarted up to 3 times. After the third crash, the plugin is disabled and the operator is notified.

---

## Encryption

### At Rest

- **Secrets vault**: The `SecretsManager` (`rex/core/privacy/encryption.py`) uses Fernet encryption (AES-128-CBC + HMAC-SHA256) with a key derived at runtime from three hardware-bound inputs that never touch disk:
  1. `/etc/machine-id` (or `/var/lib/dbus/machine-id`, or hostname as fallback)
  2. Primary network interface MAC address (from `/sys/class/net/`)
  3. Installation timestamp salt (written once on first run to `<data_dir>/.rex_install_ts`)

  These are concatenated and hashed with SHA-256 to produce a 32-byte Fernet key. The key is re-derived on every cold start and is never persisted. Notification channel tokens, SMTP passwords, and other sensitive configuration values are stored encrypted in `secrets.json.enc` with `0o600` permissions.

- **Key rotation**: The `rotate_key()` method decrypts all secrets with the current key, mixes an additional passphrase into the derivation, and re-encrypts everything. If any secret fails to decrypt during rotation, the operation aborts to prevent data loss.
- Redis is configured with `requirepass` for authentication.
- The credential file (`.credentials`) is stored with `0o600` permissions.
- The knowledge base is stored in a git repository on the local filesystem.
- Plugin data is isolated per-plugin in Docker volumes.

### In Transit

- Dashboard serves over HTTPS (port 8443).
- WebSocket connections use WSS when HTTPS is enabled.
- Redis communication is over the Docker-internal bridge network (`internal: true`), which is not routable from outside the Docker host.
- Ollama communication is localhost-only (127.0.0.1).
- ChromaDB communication is over the internal Docker network.

---

## Data Privacy Classification

The `DataClassifier` (`rex/core/privacy/data_classifier.py`) assigns every data type handled by REX to a `DataPrivacyTier` that governs encryption, retention, export eligibility, and federation sharing rules.

| Tier     | Level | Examples                                             | Retention   | Exportable | Federation Safe |
|----------|-------|------------------------------------------------------|-------------|------------|-----------------|
| CRITICAL | 4     | Credentials, tokens, API keys, encryption keys       | Manual only | Never      | Never           |
| HIGH     | 3     | DNS logs, packet captures, MAC addresses, ARP tables | 30 days     | Opt-in     | Never           |
| MEDIUM   | 2     | Threat events, scan results, firewall rules          | 90 days     | Yes        | Yes             |
| LOW      | 1     | Behavioral baselines, health metrics, config          | 365 days    | Yes        | Yes             |
| PUBLIC   | 0     | REX version, uptime, device count                    | No limit    | Yes        | Yes             |

Unknown data types default to MEDIUM (fail-safe). Log sanitization automatically masks fields matching sensitive patterns (password, token, secret, api_key, credential, private_key, cookie, session) and redacts MAC addresses to `XX:XX:XX:XX:**:**` in non-debug mode.

---

## Authentication and Authorization

### JWT Authentication

- **Algorithm**: HS256 (HMAC-SHA256)
- **Expiry**: 4 hours (configurable)
- **Secret**: 32-byte random hex generated on first boot (minimum 32-byte enforcement per RFC 7518)
- **Token format**: Standard JWT with required `sub`, `iat`, `exp` claims
- **Rotation**: JWT secret is regenerated when the password is changed, invalidating all existing tokens

### Password Security

- Passwords are pre-hashed with SHA-256 to avoid bcrypt's 72-byte truncation, then hashed with bcrypt (random salt)
- Minimum password length: 12 characters (enforced on change)
- NUL bytes in passwords are rejected to prevent truncation attacks
- Initial password is auto-generated (24 bytes URL-safe) and displayed once at first boot via CLI output (never logged)
- Password changes require the current password

### Rate Limiting and Lockout

- **Login attempts**: 5 failures within 30 minutes triggers lockout
- **Lockout duration**: 30 minutes
- **Lockout scope**: Per-IP (single admin user model, lockout tracks source IP)
- **Failed attempt tracking**: In-memory with 30-minute sliding window

### Authorization Model

REX uses a single admin user model. All authenticated API endpoints require a valid JWT token passed in the `Authorization: Bearer <token>` header. The read-only interview endpoints (`/api/interview/status`, `/api/interview/question`) do not require authentication because they are used during initial onboarding and expose no sensitive state. State-changing interview endpoints (`/api/interview/answer`, `/api/interview/chat`, `/api/interview/restart`) require authentication.

---

## Responsible Disclosure Policy

If you discover a security vulnerability in REX-BOT-AI, we ask that you follow responsible disclosure practices:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. **Email** your report to `security@rexbot.ai` (or the maintainer's published security contact).
3. **Include** in your report:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)
4. **Allow** 90 days for the maintainers to develop and release a patch before public disclosure.
5. **Credit** will be given in the release notes and SECURITY.md unless you request anonymity.

### Scope

The following are in scope for responsible disclosure:

- Authentication bypass
- Prompt injection that leads to unauthorized actions
- Command injection or sandbox escape
- Information disclosure (credential leakage, PII exposure)
- Denial of service against REX services
- Plugin sandbox escape

The following are **out of scope**:

- Vulnerabilities requiring physical access to the REX host
- Social engineering of the REX operator
- Denial of service against the network (not REX itself)
- Issues in third-party dependencies (report to the upstream project)

---

## How to Report Vulnerabilities

1. **Preferred method**: Email `security@rexbot.ai` with `[REX-SECURITY]` in the subject line.
2. **PGP encryption**: Available on request. Contact the maintainers for the public key.
3. **GitHub Security Advisory**: Use the "Report a vulnerability" button on the repository's Security tab to file a private advisory.
4. **Response time**: We aim to acknowledge reports within 48 hours and provide a timeline for a fix within 7 days.

All reporters who follow responsible disclosure will be credited in the project's security acknowledgments.
