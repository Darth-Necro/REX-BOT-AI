# REX-BOT-AI Plugin SDK

## What REX Plugins Can Do

REX plugins extend the system's capabilities without modifying core code. A plugin can:

- **React to events**: Receive threat detections, device discoveries, and other events from the REX event bus and take action.
- **Run on a schedule**: Execute periodic tasks (e.g., check for firmware updates, audit DNS configurations, scan for default credentials).
- **Read device inventory**: Query the current list of monitored devices with their status, open ports, and trust levels.
- **Access the knowledge base**: Read sections of REX's knowledge base for context.
- **Send alerts**: Push notifications through REX-BARK (Discord, Telegram, email, etc.).
- **Request enforcement actions**: Ask REX to block IPs, quarantine devices, or add firewall rules (subject to operator approval).
- **Store persistent data**: Use plugin-local key-value storage that survives restarts.

Plugins run in sandboxed Docker containers with resource limits and network isolation. They communicate with REX exclusively through the Plugin API.

---

## Plugin Manifest Format

Every plugin must include a `rex-plugin.yaml` manifest file in its root directory.

```yaml
# rex-plugin.yaml -- Plugin metadata and configuration

# REQUIRED: Globally unique identifier (lowercase, hyphens, no spaces)
plugin_id: "my-credential-checker"

# REQUIRED: Human-readable name
name: "Default Credential Checker"

# REQUIRED: SemVer version string
version: "1.0.0"

# REQUIRED: Author or organization
author: "Your Name"

# REQUIRED: Short description (max 200 characters)
description: "Monitors devices for known default credentials and alerts the operator."

# OPTIONAL: SPDX license identifier
license: "MIT"

# OPTIONAL: Minimum REX version required
min_rex_version: "1.0.0"

# REQUIRED: List of permissions the plugin needs
# REX will show these to the operator before installation
permissions:
  - "devices:read"        # Read device inventory
  - "kb:read"             # Read knowledge base sections
  - "alerts:write"        # Send alert notifications
  # - "firewall:write"    # Request firewall rule changes (uncomment if needed)
  # - "actions:request"   # Request enforcement actions (uncomment if needed)

# OPTIONAL: Resource limits (defaults shown)
resources:
  cpu: 0.5            # Max CPU cores (0.5 = 50% of one core)
  memory: "256m"      # Max RAM
  disk: "100m"        # Max disk usage

# OPTIONAL: Event hooks the plugin subscribes to
hooks:
  events:
    - "device_discovered"
    - "threat_detected"
  schedule: "*/30 * * * *"    # Cron expression: every 30 minutes

# OPTIONAL: Configuration schema for user-configurable settings
config_schema:
  check_interval_minutes:
    type: integer
    default: 30
    description: "How often to check for default credentials"
  credential_list_url:
    type: string
    default: ""
    description: "URL to a custom default credential list (optional)"

# OPTIONAL: Platform compatibility
compatibility:
  platforms:
    - "linux"
    - "macos"
  architectures:
    - "x86_64"
    - "aarch64"
```

### Manifest Fields Reference

| Field              | Required | Type          | Description                                                    |
|--------------------|----------|---------------|----------------------------------------------------------------|
| `plugin_id`        | Yes      | string        | Unique identifier. Lowercase, hyphens allowed, no spaces.      |
| `name`             | Yes      | string        | Display name shown in the dashboard.                           |
| `version`          | Yes      | string        | SemVer version (e.g., `1.0.0`, `2.1.0-beta`).                |
| `author`           | Yes      | string        | Author name or organization.                                   |
| `description`      | Yes      | string        | Brief description, max 200 characters.                         |
| `license`          | No       | string        | SPDX license identifier (e.g., `MIT`, `GPL-3.0-only`).       |
| `min_rex_version`  | No       | string        | Minimum compatible REX version.                                |
| `permissions`      | Yes      | list[string]  | Capabilities the plugin requests. See Permission Model below.  |
| `resources`        | No       | object        | CPU, memory, and disk limits for the sandbox container.        |
| `hooks`            | No       | object        | Event subscriptions and cron schedule.                         |
| `config_schema`    | No       | object        | User-configurable settings with types and defaults.            |
| `compatibility`    | No       | object        | Platform and architecture constraints.                         |

---

## RexPlugin Base Class API Reference

All plugins must subclass `RexPlugin` and implement the abstract methods.

```python
from rex.store.sdk.base_plugin import RexPlugin

class MyPlugin(RexPlugin):
    """My custom REX plugin."""

    async def on_event(self, event_type: str, event_data: dict) -> dict | None:
        ...

    async def on_schedule(self) -> dict | None:
        ...

    async def on_install(self) -> None:
        ...

    async def on_configure(self, config: dict) -> None:
        ...

    def get_status(self) -> dict:
        ...
```

### Abstract Methods (Must Implement)

#### `on_event(event_type: str, event_data: dict) -> dict | None`

Called when an event matching the plugin's `hooks.events` list is received.

**Parameters:**
- `event_type` -- The event type string (e.g., `"threat_detected"`, `"device_discovered"`).
- `event_data` -- The event payload dict containing event-specific data.

**Returns:**
- `dict` -- An action request for REX to execute (see Action Request Format below).
- `None` -- Take no action.

```python
async def on_event(self, event_type: str, event_data: dict) -> dict | None:
    if event_type == "device_discovered":
        device = event_data
        if self._has_default_credentials(device):
            await self.send_alert(
                severity="high",
                message=f"Device {device['hostname']} has default credentials on port {device['open_ports']}"
            )
            return {"action": "alert", "reason": "Default credentials detected"}
    return None
```

#### `on_schedule() -> dict | None`

Called on the cron schedule defined in `hooks.schedule`.

**Returns:**
- `dict` -- An action request.
- `None` -- Take no action.

```python
async def on_schedule(self) -> dict | None:
    devices = await self.get_devices()
    for device in devices:
        if self._needs_credential_check(device):
            await self._check_credentials(device)
    return None
```

#### `on_install() -> None`

Called once when the plugin is first installed. Use this for one-time setup.

```python
async def on_install(self) -> None:
    await self.log("Default Credential Checker installed")
    await self.store("last_check", "never")
```

#### `on_configure(config: dict) -> None`

Called when the operator updates plugin configuration through the dashboard.

**Parameters:**
- `config` -- Dict of configuration values matching the `config_schema` in the manifest.

```python
async def on_configure(self, config: dict) -> None:
    self.check_interval = config.get("check_interval_minutes", 30)
    self.credential_list_url = config.get("credential_list_url", "")
    await self.log(f"Configuration updated: interval={self.check_interval}m")
```

#### `get_status() -> dict`

Return the current health and status of the plugin. Must include a `healthy` boolean key.

```python
def get_status(self) -> dict:
    return {
        "healthy": True,
        "devices_checked": self._devices_checked,
        "vulnerabilities_found": self._vulns_found,
        "last_check": self._last_check_time,
    }
```

### Helper Methods (Provided by Runtime)

These methods are available to all plugins. They communicate with REX through the Plugin API and are subject to the plugin's declared permissions.

#### `get_devices() -> list[dict]`

Fetch the current device inventory. Requires `devices:read` permission.

```python
devices = await self.get_devices()
for device in devices:
    print(device["mac_address"], device["hostname"], device["open_ports"])
```

#### `get_kb_section(section: str) -> Any`

Read a section of the knowledge base. Requires `kb:read` permission.

```python
network_info = await self.get_kb_section("network_topology")
```

#### `send_alert(severity: str, message: str) -> bool`

Send an alert through REX-BARK. Requires `alerts:write` permission.

**Parameters:**
- `severity` -- One of: `"critical"`, `"high"`, `"medium"`, `"low"`, `"info"`.
- `message` -- Alert message text.

**Returns:** `True` if the alert was queued successfully.

```python
await self.send_alert(
    severity="high",
    message="Camera at 192.168.1.50 is using admin/admin credentials"
)
```

#### `request_action(action_type: str, params: dict) -> dict`

Request REX to perform an enforcement action. Requires `actions:request` permission. The action goes through operator approval unless auto-execution criteria are met.

**Parameters:**
- `action_type` -- One of: `"block"`, `"quarantine"`, `"rate_limit"`, `"alert"`.
- `params` -- Action-specific parameters (IP, MAC, reason, etc.).

**Returns:** Dict with `status` key (`"approved"`, `"pending_approval"`, `"denied"`).

```python
result = await self.request_action("quarantine", {
    "mac": "aa:bb:cc:dd:ee:ff",
    "reason": "Default credentials detected"
})
```

#### `log(message: str, level: str = "info") -> None`

Write a structured log entry through REX's logging system.

```python
await self.log("Checking device 192.168.1.50 for default credentials")
await self.log("Credential check failed: connection refused", level="warning")
```

#### `store(key: str, value: Any) -> None`

Persist data to plugin-local key-value storage. Survives container restarts.

```python
await self.store("checked_devices", ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"])
```

#### `retrieve(key: str) -> Any`

Retrieve data from plugin-local storage.

```python
checked = await self.retrieve("checked_devices")
```

---

## Plugin API Endpoints (REST)

Plugins communicate with REX through the Plugin API at `/plugin-api/*`. All requests require the `X-Plugin-Token` header.

| Method | Path                              | Description                              |
|--------|-----------------------------------|------------------------------------------|
| GET    | `/plugin-api/devices`             | List devices (filtered by permissions)   |
| GET    | `/plugin-api/events`              | Get subscribed event stream              |
| POST   | `/plugin-api/alerts`              | Submit an alert through BARK             |
| POST   | `/plugin-api/actions`             | Request an enforcement action            |
| GET    | `/plugin-api/knowledge-base/{section}` | Read a KB section                   |
| POST   | `/plugin-api/log`                 | Submit a structured log entry            |
| PUT    | `/plugin-api/store/{key}`         | Store plugin-local data                  |
| GET    | `/plugin-api/store/{key}`         | Retrieve plugin-local data               |

---

## Permission Model

Permissions are declared in the plugin manifest and shown to the operator before installation.

| Permission          | Grants Access To                                              |
|---------------------|---------------------------------------------------------------|
| `devices:read`      | Read device inventory (MACs, IPs, hostnames, ports, status)   |
| `devices:write`     | Update device trust levels and tags                           |
| `kb:read`           | Read knowledge base sections                                  |
| `kb:write`          | Write to the knowledge base (rare, requires explicit approval)|
| `alerts:write`      | Send notifications through REX-BARK                           |
| `firewall:read`     | Read current firewall rules                                   |
| `firewall:write`    | Request firewall rule changes (subject to approval)           |
| `actions:request`   | Request enforcement actions (block, quarantine, rate-limit)   |
| `network:read`      | Read network topology and traffic summaries                   |
| `threats:read`      | Read the threat log                                           |
| `schedule:read`     | Read scan and power schedule                                  |
| `config:read`       | Read REX configuration (redacted secrets)                     |
| `storage:local`     | Use plugin-local key-value storage                            |

Plugins cannot request permissions beyond this set. Any API call for an unpermitted resource returns `403 Forbidden`.

---

## Tutorial: Building a Default Credential Checker Plugin

This step-by-step tutorial walks through building a plugin that monitors newly discovered devices for common default credentials.

### Step 1: Create the Project Structure

```
rex-default-credential-checker/
  rex-plugin.yaml
  plugin.py
  credentials.json
  Dockerfile
  requirements.txt
```

### Step 2: Write the Manifest

```yaml
# rex-plugin.yaml
plugin_id: "default-credential-checker"
name: "Default Credential Checker"
version: "1.0.0"
author: "REX Community"
description: "Alerts when devices are found with known default credentials."
license: "MIT"
permissions:
  - "devices:read"
  - "alerts:write"
  - "storage:local"
hooks:
  events:
    - "device_discovered"
  schedule: "0 */6 * * *"   # Every 6 hours
resources:
  cpu: 0.25
  memory: "128m"
config_schema:
  ports_to_check:
    type: string
    default: "22,23,80,443,8080"
    description: "Comma-separated list of ports to check for default credentials"
```

### Step 3: Write the Plugin Code

```python
# plugin.py
import json
import socket
from rex.store.sdk.base_plugin import RexPlugin


# Common default credentials by service
DEFAULT_CREDS = {
    22:   [("admin", "admin"), ("root", "root"), ("root", "toor")],
    23:   [("admin", "admin"), ("admin", "password"), ("root", "")],
    80:   [("admin", "admin"), ("admin", "1234"), ("admin", "password")],
    443:  [("admin", "admin")],
    8080: [("admin", "admin"), ("tomcat", "tomcat")],
}


class DefaultCredentialChecker(RexPlugin):
    """Check new devices for default credentials on common services."""

    def __init__(self):
        self._devices_checked = 0
        self._vulns_found = 0
        self._ports_to_check = [22, 23, 80, 443, 8080]

    async def on_install(self) -> None:
        await self.log("Default Credential Checker installed successfully")
        await self.store("total_checks", 0)
        await self.store("total_vulns", 0)

    async def on_configure(self, config: dict) -> None:
        ports_str = config.get("ports_to_check", "22,23,80,443,8080")
        self._ports_to_check = [int(p.strip()) for p in ports_str.split(",")]
        await self.log(f"Configuration updated: checking ports {self._ports_to_check}")

    async def on_event(self, event_type: str, event_data: dict) -> dict | None:
        """Check newly discovered devices for default credentials."""
        if event_type != "device_discovered":
            return None

        ip = event_data.get("ip_address")
        hostname = event_data.get("hostname", "unknown")
        open_ports = event_data.get("open_ports", [])

        if not ip or not open_ports:
            return None

        # Check each open port against default credentials
        vulnerable_ports = []
        for port in open_ports:
            if port in self._ports_to_check and port in DEFAULT_CREDS:
                if await self._check_port(ip, port):
                    vulnerable_ports.append(port)

        if vulnerable_ports:
            self._vulns_found += 1
            await self.send_alert(
                severity="high",
                message=(
                    f"Device '{hostname}' ({ip}) has default credentials "
                    f"on port(s): {vulnerable_ports}. "
                    f"Change these immediately to prevent unauthorized access."
                ),
            )
            return {
                "action": "alert",
                "reason": f"Default credentials on {ip}:{vulnerable_ports}",
            }

        self._devices_checked += 1
        return None

    async def on_schedule(self) -> dict | None:
        """Periodic full scan of all known devices."""
        devices = await self.get_devices()
        await self.log(f"Scheduled check: scanning {len(devices)} devices")

        for device in devices:
            ip = device.get("ip_address")
            open_ports = device.get("open_ports", [])
            if ip and open_ports:
                for port in open_ports:
                    if port in self._ports_to_check and port in DEFAULT_CREDS:
                        if await self._check_port(ip, port):
                            await self.send_alert(
                                severity="high",
                                message=(
                                    f"Device '{device.get('hostname', ip)}' ({ip}) "
                                    f"still has default credentials on port {port}."
                                ),
                            )
        # Persist stats
        total = (await self.retrieve("total_checks") or 0) + len(devices)
        await self.store("total_checks", total)
        return None

    def get_status(self) -> dict:
        return {
            "healthy": True,
            "devices_checked": self._devices_checked,
            "vulnerabilities_found": self._vulns_found,
        }

    async def _check_port(self, ip: str, port: int) -> bool:
        """Attempt to connect with default credentials. Returns True if vulnerable."""
        # Simplified check: just test if the port accepts a TCP connection.
        # A real implementation would attempt SSH/HTTP/Telnet login.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
```

### Step 4: Create the Dockerfile

```dockerfile
FROM python:3.12-slim
WORKDIR /plugin
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "-m", "plugin"]
```

### Step 5: Create requirements.txt

```
rex-bot-ai-sdk>=1.0.0
```

### Step 6: Test Locally

```bash
# From the REX project root
cd plugins/default-credential-checker/

# Run the plugin in test mode
python -m pytest test_plugin.py -v

# Or test with the REX CLI
rex plugin test ./default-credential-checker/
```

### Step 7: Install in REX

```bash
# Install from local directory
rex plugin install ./default-credential-checker/

# Or from the registry
rex plugin install default-credential-checker
```

---

## Sandbox Restrictions

Plugins **cannot**:

- Access the host filesystem (read-only root, no volume mounts to host paths)
- Access the internet (container runs on `rex-internal` network only)
- Access other plugins' data or containers
- Spawn child processes or execute shell commands
- Access the Docker socket
- Escalate privileges (`no_new_privileges: true`, `cap_drop: ALL`)
- Exceed declared resource limits (CPU, RAM, disk)
- Call Plugin API endpoints not covered by their declared permissions
- Modify REX configuration or core behavior directly

Violations result in the request being rejected (403) and an audit log entry.

---

## Testing Plugins Locally

### Unit Testing

```python
# test_plugin.py
import pytest
from plugin import DefaultCredentialChecker


@pytest.fixture
def plugin():
    return DefaultCredentialChecker()


@pytest.mark.asyncio
async def test_on_event_ignores_non_device_events(plugin):
    result = await plugin.on_event("threat_detected", {"threat_type": "port_scan"})
    assert result is None


@pytest.mark.asyncio
async def test_on_event_skips_devices_without_ports(plugin):
    result = await plugin.on_event("device_discovered", {
        "ip_address": "192.168.1.50",
        "hostname": "camera",
        "open_ports": [],
    })
    assert result is None


@pytest.mark.asyncio
async def test_get_status(plugin):
    status = plugin.get_status()
    assert status["healthy"] is True
    assert "devices_checked" in status
```

### Integration Testing with REX

```bash
# Start REX in development mode
make dev

# Install the plugin
rex plugin install ./my-plugin/

# Check plugin status
rex plugin status my-plugin

# View plugin logs
rex plugin logs my-plugin

# Uninstall
rex plugin remove my-plugin
```

---

## Submitting to the Plugin Registry

1. **Ensure your plugin passes all tests** and linting.
2. **Create a GitHub repository** for your plugin.
3. **Tag a release** following SemVer (e.g., `v1.0.0`).
4. **Submit a pull request** to the [REX Plugin Registry](https://github.com/REX-BOT-AI/plugin-registry) with:
   - Your `rex-plugin.yaml` manifest
   - A link to your repository
   - A brief description of what the plugin does
   - Screenshots or logs demonstrating functionality
5. **Review process**: Maintainers will review the plugin for:
   - Security: No excessive permissions, no suspicious code
   - Quality: Tests pass, documentation exists
   - Usefulness: Solves a real problem for REX users
6. **Approval**: Once approved, the plugin appears in `GET /api/plugins/available` and can be installed via the dashboard or CLI.
