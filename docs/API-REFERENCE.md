# REX-BOT-AI API Reference

Base URL: `https://localhost:8443`

> **Note:** The dashboard binds to `127.0.0.1` by default. To allow LAN access, set `REX_DASHBOARD_HOST=0.0.0.0` in your environment or `.env` file. The initial admin password is randomly generated per-install and displayed once at first boot in the terminal output.

All endpoints return JSON. Errors use standard HTTP status codes with a JSON body:

```json
{
  "detail": "Human-readable error message"
}
```

Interactive API documentation is available at:
- Swagger UI: `https://localhost:8443/api/docs`
- ReDoc: `https://localhost:8443/api/redoc`

---

## Table of Contents

- [Authentication](#authentication)
- [Status and Health](#status-and-health)
- [Devices](#devices)
- [Threats](#threats)
- [Knowledge Base](#knowledge-base)
- [Interview](#interview)
- [Configuration](#configuration)
- [Plugins](#plugins)
- [Firewall](#firewall)
- [Notifications](#notifications)
- [Schedule](#schedule)
- [WebSocket](#websocket)
- [Privacy](#privacy)

---

## Authentication

### Login

Authenticate and receive a JWT token.

```
POST /api/auth/login
```

**Auth required:** No

**Request body:**

```json
{
  "password": "your-admin-password"
}
```

**Response (200):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 14400
}
```

**Error responses:**

| Code | Detail                                                |
|------|-------------------------------------------------------|
| 401  | `"Invalid credentials. 4 attempts remaining."`        |
| 429  | `"Too many failed attempts. Locked for 30 minutes."`  |

**Usage:**

Include the token in subsequent requests:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Change Password

```
POST /api/auth/change-password
```

**Auth required:** Yes

**Request body:**

```json
{
  "old_password": "current-password",
  "new_password": "new-password-min-8-chars"
}
```

**Response (200):**

```json
{
  "status": "changed"
}
```

**Error responses:**

| Code | Detail                                    |
|------|-------------------------------------------|
| 400  | `"Current password is incorrect"`          |
| 400  | `"New password must be at least 8 characters"` |
| 401  | `"Not authenticated"`                      |

---

## Status and Health

### System Status

Returns aggregate system status including all service health, device count, and threat summary.

```
GET /api/status
```

**Auth required:** No

**Response (200):**

```json
{
  "status": "operational",
  "version": "1.0.0",
  "timestamp": "2026-03-31T12:00:00Z",
  "power_state": "awake",
  "services": {
    "core": {"healthy": true},
    "eyes": {"healthy": true},
    "brain": {"healthy": true, "degraded": false},
    "teeth": {"healthy": true},
    "memory": {"healthy": true},
    "bark": {"healthy": true},
    "scheduler": {"healthy": true}
  },
  "device_count": 12,
  "active_threats": 2,
  "threats_blocked_24h": 7,
  "llm_status": "ready",
  "uptime_seconds": 86420
}
```

### Health Check

Simple health check for load balancers and monitoring.

```
GET /api/health
```

**Auth required:** No

**Response (200):**

```json
{
  "status": "ok"
}
```

---

## Devices

### List All Devices

```
GET /api/devices/
```

**Auth required:** Yes

**Response (200):**

```json
{
  "devices": [
    {
      "device_id": "dev_a1b2c3d4",
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "ip_address": "192.168.1.50",
      "hostname": "living-room-camera",
      "vendor": "Hikvision",
      "os_guess": "Linux 4.x",
      "device_type": "iot_camera",
      "open_ports": [80, 554, 8000],
      "services": ["HTTP", "RTSP"],
      "status": "online",
      "trust_level": 60,
      "risk_score": 0.35,
      "first_seen": "2026-03-28T10:15:00Z",
      "last_seen": "2026-03-31T11:58:00Z",
      "tags": ["iot", "camera"]
    }
  ],
  "total": 1
}
```

### Get Device by MAC

```
GET /api/devices/{mac}
```

**Auth required:** Yes

**Parameters:**

| Name | In   | Type   | Description                                |
|------|------|--------|--------------------------------------------|
| mac  | path | string | MAC address (colon-separated, e.g. `aa:bb:cc:dd:ee:ff`) |

**Response (200):**

```json
{
  "device_id": "dev_a1b2c3d4",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.1.50",
  "hostname": "living-room-camera",
  "vendor": "Hikvision",
  "os_guess": "Linux 4.x",
  "device_type": "iot_camera",
  "open_ports": [80, 554, 8000],
  "services": ["HTTP", "RTSP"],
  "status": "online",
  "trust_level": 60,
  "risk_score": 0.35,
  "first_seen": "2026-03-28T10:15:00Z",
  "last_seen": "2026-03-31T11:58:00Z",
  "tags": ["iot", "camera"]
}
```

**Error responses:**

| Code | Detail                       |
|------|------------------------------|
| 404  | `"Device {mac} not found"`   |

### Update Device Trust Level

```
POST /api/devices/{mac}/trust
```

**Auth required:** Yes

**Parameters:**

| Name  | In    | Type    | Description                      |
|-------|-------|---------|----------------------------------|
| mac   | path  | string  | MAC address                      |
| level | query | integer | Trust level 0-100 (default: 50)  |

**Response (200):**

```json
{
  "mac": "aa:bb:cc:dd:ee:ff",
  "trust_level": 80,
  "updated": true
}
```

### Block/Quarantine Device

```
POST /api/devices/{mac}/block
```

**Auth required:** Yes

**Parameters:**

| Name | In   | Type   | Description |
|------|------|--------|-------------|
| mac  | path | string | MAC address |

**Response (200):**

```json
{
  "mac": "aa:bb:cc:dd:ee:ff",
  "action": "block",
  "status": "requested",
  "delivered": true
}
```

### Trigger Network Scan

```
POST /api/devices/scan
```

**Auth required:** Yes

**Response (200):**

```json
{
  "status": "scan_started"
}
```

---

## Threats

### List Threats

```
GET /api/threats/
```

**Auth required:** Yes

**Query parameters:**

| Name     | Type    | Default | Description                               |
|----------|---------|---------|-------------------------------------------|
| limit    | integer | 50      | Max results (1-500)                       |
| severity | string  | null    | Filter by severity (critical, high, etc.) |

**Response (200):**

```json
{
  "threats": [
    {
      "event_id": "evt_x1y2z3",
      "timestamp": "2026-03-31T11:45:00Z",
      "source_device_id": "dev_a1b2c3d4",
      "source_ip": "192.168.1.50",
      "destination_ip": "203.0.113.50",
      "destination_port": 443,
      "protocol": "TCP",
      "threat_type": "c2_communication",
      "severity": "critical",
      "description": "Device contacted known C2 domain evil.example.com",
      "confidence": 0.92,
      "indicators": ["evil.example.com", "203.0.113.50"],
      "decision": {
        "decision_id": "dec_m1n2o3",
        "action": "block",
        "reasoning": "[L1-signature] c2_communication -- 92% confidence",
        "layer": 1,
        "auto_executed": true
      }
    }
  ],
  "total": 1
}
```

### Get Threat by ID

```
GET /api/threats/{threat_id}
```

**Auth required:** Yes

**Response (200):** Same structure as a single item from the list endpoint.

**Error responses:**

| Code | Detail                              |
|------|-------------------------------------|
| 404  | `"Threat {threat_id} not found"`    |

### Resolve Threat

```
PUT /api/threats/{threat_id}/resolve
```

**Auth required:** Yes

**Query parameters:**

| Name       | Type   | Default    | Description              |
|------------|--------|------------|--------------------------|
| resolution | string | "resolved" | Resolution note          |

**Response (200):**

```json
{
  "threat_id": "evt_x1y2z3",
  "status": "resolved",
  "resolution": "resolved"
}
```

### Mark as False Positive

```
PUT /api/threats/{threat_id}/false-positive
```

**Auth required:** Yes

**Response (200):**

```json
{
  "threat_id": "evt_x1y2z3",
  "status": "false_positive"
}
```

False positive feedback is used by the Brain to improve future detection accuracy.

---

## Knowledge Base

### Get Full Knowledge Base

```
GET /api/knowledge-base/
```

**Auth required:** Yes

**Response (200):**

```json
{
  "content": "# REX-BOT-AI Knowledge Base\n\n## Network Topology\n...",
  "version": "a3f5c2d",
  "last_updated": "2026-03-31T10:00:00Z"
}
```

### Get Knowledge Base Section

```
GET /api/knowledge-base/section/{section_name}
```

**Auth required:** Yes

**Parameters:**

| Name         | In   | Type   | Description                                      |
|--------------|------|--------|--------------------------------------------------|
| section_name | path | string | Section name (e.g., `network_topology`, `devices`)|

**Response (200):**

```json
{
  "section": "network_topology",
  "data": "## Network Topology\n\nSubnet: 192.168.1.0/24\nGateway: 192.168.1.1\n..."
}
```

### Update Knowledge Base

Replace the entire knowledge base content. Available in Advanced Mode only.

```
PUT /api/knowledge-base/
```

**Auth required:** Yes

**Request body:**

```json
{
  "content": "# REX-BOT-AI Knowledge Base\n\n## Network Topology\n..."
}
```

**Response (200):**

```json
{
  "status": "updated"
}
```

### Get Version History

```
GET /api/knowledge-base/history
```

**Auth required:** Yes

**Query parameters:**

| Name  | Type    | Default | Description        |
|-------|---------|---------|---------------------|
| limit | integer | 50      | Max commits to return (1+) |

**Response (200):**

```json
{
  "commits": [
    {
      "hash": "a3f5c2d",
      "message": "Auto-update: added 3 new devices",
      "timestamp": "2026-03-31T10:00:00Z",
      "author": "rex-bot-ai"
    }
  ],
  "total": 1
}
```

### Revert to Version

```
POST /api/knowledge-base/revert/{commit_hash}
```

**Auth required:** Yes

**Parameters:**

| Name        | In   | Type   | Description               |
|-------------|------|--------|---------------------------|
| commit_hash | path | string | Git commit hash to revert to |

**Response (200):**

```json
{
  "status": "reverted",
  "commit": "a3f5c2d"
}
```

---

## Interview

### Get Interview Status

```
GET /api/interview/status
```

**Auth required:** No (pre-onboarding)

**Response (200):**

```json
{
  "complete": false,
  "progress": {
    "total": 6,
    "answered": 2,
    "remaining": 4
  },
  "mode": "basic"
}
```

### Get Current Question

```
GET /api/interview/question
```

**Auth required:** No (pre-onboarding)

**Response (200):**

```json
{
  "question": {
    "id": "q_network_type",
    "text": "What type of network is REX protecting?",
    "type": "single_choice",
    "options": [
      {"value": "home", "label": "Home Network"},
      {"value": "small_office", "label": "Small Office"},
      {"value": "lab", "label": "Lab / Test Environment"}
    ]
  },
  "complete": false
}
```

When all questions are answered:

```json
{
  "question": null,
  "complete": true
}
```

### Submit Answer

```
POST /api/interview/answer
```

**Auth required:** No (pre-onboarding)

**Request body:**

```json
{
  "question_id": "q_network_type",
  "answer": "home"
}
```

**Response (200):**

```json
{
  "next_question": {
    "id": "q_tech_level",
    "text": "What is your technical experience level?",
    "type": "single_choice",
    "options": [
      {"value": "basic", "label": "Basic (simplified interface)"},
      {"value": "advanced", "label": "Advanced (full control)"}
    ]
  },
  "complete": false
}
```

### Chat with REX

```
POST /api/interview/chat
```

**Auth required:** Yes

**Request body:**

```json
{
  "message": "What devices are on my network?"
}
```

**Response (200):**

```json
{
  "reply": "Based on recent scans, I see 12 devices on your network...",
  "source": "llm"
}
```

When Ollama is not available, returns a fallback response with `"source": "fallback"`.

### Restart Interview

```
POST /api/interview/restart
```

**Auth required:** Yes

**Response (200):**

```json
{
  "status": "restarted"
}
```

---

## Configuration

### Get Configuration

```
GET /api/config/
```

**Auth required:** Yes

**Response (200):**

```json
{
  "mode": "basic",
  "protection_mode": "auto_block_critical",
  "scan_interval": 300
}
```

### Update Configuration

```
PUT /api/config/
```

**Auth required:** Yes

**Request body:**

```json
{
  "protection_mode": "auto_block_all",
  "scan_interval": 120
}
```

**Response (200):**

```json
{
  "status": "updated",
  "config": {
    "protection_mode": "auto_block_all",
    "scan_interval": 120
  }
}
```

### Set Operating Mode

```
PUT /api/config/mode
```

**Auth required:** Yes

**Request body:**

```json
{
  "mode": "advanced"
}
```

**Response (200):**

```json
{
  "status": "updated",
  "mode": "advanced"
}
```

Valid modes: `basic`, `advanced`.

---

## Plugins

### List Installed Plugins

```
GET /api/plugins/installed
```

**Auth required:** Yes

**Response (200):**

```json
{
  "plugins": [
    {
      "plugin_id": "default-credential-checker",
      "name": "Default Credential Checker",
      "version": "1.0.0",
      "author": "REX Community",
      "status": "running",
      "healthy": true,
      "permissions": ["devices:read", "alerts:write"]
    }
  ],
  "total": 1
}
```

### List Available Plugins

```
GET /api/plugins/available
```

**Auth required:** Yes

**Response (200):**

```json
{
  "plugins": [
    {
      "plugin_id": "dns-privacy-auditor",
      "name": "DNS Privacy Auditor",
      "version": "2.0.1",
      "author": "REX Community",
      "description": "Audits DNS query patterns for privacy leaks",
      "permissions": ["network:read", "alerts:write"],
      "downloads": 1250
    }
  ],
  "total": 1
}
```

### Install Plugin

```
POST /api/plugins/install/{plugin_id}
```

**Auth required:** Yes

**Parameters:**

| Name      | In   | Type   | Description               |
|-----------|------|--------|---------------------------|
| plugin_id | path | string | Plugin identifier          |

**Response (200):**

```json
{
  "status": "installing",
  "plugin_id": "dns-privacy-auditor"
}
```

**Error responses:**

| Code | Detail                                   |
|------|------------------------------------------|
| 404  | `"Plugin not found in registry"`          |
| 409  | `"Plugin already installed"`              |
| 503  | `"Docker not available for sandboxing"`   |

### Remove Plugin

```
DELETE /api/plugins/{plugin_id}
```

**Auth required:** Yes

**Response (200):**

```json
{
  "status": "removed",
  "plugin_id": "dns-privacy-auditor"
}
```

---

## Firewall

### List Firewall Rules

```
GET /api/firewall/rules
```

**Auth required:** Yes

**Response (200):**

```json
{
  "rules": [
    {
      "rule_id": "rule_abc123",
      "created_at": "2026-03-31T11:50:00Z",
      "ip": "203.0.113.50",
      "mac": null,
      "direction": "both",
      "action": "drop",
      "reason": "[L1-signature] c2_communication -- blocked by REX Brain",
      "expires_at": null,
      "created_by": "brain"
    }
  ],
  "total": 1
}
```

### Add Firewall Rule

```
POST /api/firewall/rules
```

**Auth required:** Yes

**Request body:**

```json
{
  "ip": "203.0.113.100",
  "direction": "both",
  "reason": "Manual block: suspicious external IP"
}
```

**Parameters:**

| Name      | Type   | Default | Description                               |
|-----------|--------|---------|-------------------------------------------|
| ip        | string | (required) | Target IP address                      |
| direction | string | "both"  | Traffic direction: `inbound`, `outbound`, `both` |
| reason    | string | ""      | Human-readable reason for the rule        |

**Response (200):**

```json
{
  "status": "added",
  "ip": "203.0.113.100",
  "direction": "both"
}
```

### Remove Firewall Rule

```
DELETE /api/firewall/rules/{rule_id}
```

**Auth required:** Yes

**Response (200):**

```json
{
  "status": "removed",
  "rule_id": "rule_abc123"
}
```

### Panic Button (Emergency)

Remove ALL REX-managed firewall rules immediately. This restores the network to its pre-REX state.

```
POST /api/firewall/panic
```

**Auth required:** Yes

**Response (200):**

```json
{
  "status": "all_rules_removed",
  "warning": "Network returned to pre-REX state"
}
```

**Use this when:** REX's firewall rules are causing legitimate connectivity problems and you need to restore access immediately.

### Restore After Panic

Restore normal firewall operation after a panic button press.

```
POST /api/firewall/panic/restore
```

**Auth required:** Yes

**Response (200):**

```json
{
  "status": "restored",
  "note": "Normal firewall operation resumed"
}
```

---

## Notifications

### Get Notification Settings

```
GET /api/notifications/settings
```

**Auth required:** Yes

**Response (200):**

```json
{
  "channels": {
    "discord": {
      "enabled": true,
      "webhook_url": "https://discord.com/api/webhooks/..."
    },
    "telegram": {
      "enabled": false,
      "bot_token": "",
      "chat_id": ""
    },
    "email": {
      "enabled": false,
      "smtp_host": "",
      "smtp_port": 587,
      "recipient": ""
    }
  },
  "quiet_hours": null,
  "detail_level": "summary"
}
```

### Update Notification Settings

```
PUT /api/notifications/settings
```

**Auth required:** Yes

**Request body:**

```json
{
  "channels": {
    "discord": {
      "enabled": true,
      "webhook_url": "https://discord.com/api/webhooks/123/abc"
    }
  },
  "quiet_hours": {
    "start": "23:00",
    "end": "07:00"
  },
  "detail_level": "full"
}
```

**Response (200):**

```json
{
  "status": "updated"
}
```

### Test Notification Channel

Send a test notification through a specific channel.

```
POST /api/notifications/test/{channel}
```

**Auth required:** Yes

**Parameters:**

| Name    | In   | Type   | Description                                        |
|---------|------|--------|----------------------------------------------------|
| channel | path | string | Channel name: `discord`, `telegram`, `email`, `matrix`, `pushover` |

**Response (200):**

```json
{
  "status": "sent",
  "channel": "discord"
}
```

**Error responses:**

| Code | Detail                                    |
|------|-------------------------------------------|
| 400  | `"Channel not configured"`                 |
| 502  | `"Failed to deliver test notification"`    |

---

## Schedule

### Get Schedule

```
GET /api/schedule/
```

**Auth required:** Yes

**Response (200):**

```json
{
  "scans": [
    {
      "type": "full_scan",
      "interval_seconds": 300,
      "next_run": "2026-03-31T12:05:00Z"
    }
  ],
  "power": {
    "state": "awake",
    "next_wake": null,
    "next_sleep": "2026-03-31T23:00:00Z"
  }
}
```

### Update Schedule

```
PUT /api/schedule/
```

**Auth required:** Yes

**Request body:**

```json
{
  "scan_interval": 600,
  "sleep_schedule": {
    "start": "23:00",
    "end": "06:00",
    "mode": "alert_sleep"
  }
}
```

**Response (200):**

```json
{
  "status": "updated"
}
```

### Trigger Sleep

Put REX into ALERT_SLEEP mode immediately.

```
POST /api/schedule/sleep
```

**Auth required:** Yes

**Response (200):**

```json
{
  "status": "sleeping",
  "mode": "alert_sleep"
}
```

In ALERT_SLEEP mode, scan frequency is reduced and non-critical background tasks are paused. Critical threat detection remains active.

### Trigger Wake

Wake REX to full AWAKE mode immediately.

```
POST /api/schedule/wake
```

**Auth required:** Yes

**Response (200):**

```json
{
  "status": "awake",
  "mode": "awake"
}
```

---

## WebSocket

### Connection

```
ws://localhost:8443/ws
```

Or with TLS:

```
wss://localhost:8443/ws
```

### Authentication

WebSocket connections use **first-message auth** to prevent JWT leakage into
server/proxy access logs. Do NOT pass the token as a query parameter.

After the connection opens, the client must send an auth message within 5 seconds:

```json
{
  "type": "auth",
  "token": "<jwt-token>"
}
```

If the token is missing, invalid, or not received within the timeout, the server
closes the connection with code `4001` (missing token) or `4003` (invalid token).

### Client-to-Server Messages

#### Subscribe to Channels

```json
{
  "type": "subscribe",
  "channels": ["threats", "devices", "logs"]
}
```

#### Unsubscribe from Channels

```json
{
  "type": "unsubscribe",
  "channels": ["logs"]
}
```

#### Ping

```json
{
  "type": "ping"
}
```

### Server-to-Client Messages

#### Pong

```json
{
  "type": "pong"
}
```

#### Threat Event

```json
{
  "type": "threats",
  "event": "threat_detected",
  "data": {
    "event_id": "evt_x1y2z3",
    "threat_type": "c2_communication",
    "severity": "critical",
    "source_ip": "192.168.1.50",
    "description": "Device contacted known C2 domain",
    "confidence": 0.92
  }
}
```

#### Device Update

```json
{
  "type": "devices",
  "event": "device_discovered",
  "data": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.1.50",
    "hostname": "new-device",
    "vendor": "Apple"
  }
}
```

#### Status Update

```json
{
  "type": "status",
  "data": {
    "device_count": 13,
    "active_threats": 1,
    "uptime_seconds": 86500
  }
}
```

#### Error

```json
{
  "type": "error",
  "message": "Invalid JSON"
}
```

### Default Subscriptions

New connections are automatically subscribed to: `status`, `threats`, `devices`.

### Available Channels

| Channel    | Events                                          |
|------------|-------------------------------------------------|
| `status`   | System status updates, service health changes   |
| `threats`  | New threat detections, resolution updates       |
| `devices`  | Device discoveries, state changes, departures   |
| `actions`  | Enforcement actions executed or failed           |
| `logs`     | Real-time log stream (Advanced Mode)             |
| `scans`    | Scan start/complete events                       |

---

## Privacy

### Privacy Status

Public endpoint that reports REX's current privacy posture. No authentication required.

```
GET /api/privacy/status
```

**Auth required:** No

**Response (200):**

```json
{
  "data_local_only": true,
  "external_connections": 0,
  "encryption_at_rest": true,
  "telemetry_enabled": false
}
```

| Field                 | Type    | Description                                           |
|-----------------------|---------|-------------------------------------------------------|
| `data_local_only`     | boolean | All data processing happens locally                   |
| `external_connections`| integer | Number of active external API connections              |
| `encryption_at_rest`  | boolean | Data is encrypted at rest                             |
| `telemetry_enabled`   | boolean | Whether any telemetry is being sent                   |

### Privacy Audit

Run a full privacy audit and return a structured report. Requires authentication.

```
GET /api/privacy/audit
```

**Auth required:** Yes

**Response (200):**

```json
{
  "ollama_localhost_only": true,
  "no_external_connections": true,
  "encryption_configured": true,
  "findings": []
}
```

---

## Common Error Codes

| Code | Meaning                | Common Causes                                       |
|------|------------------------|-----------------------------------------------------|
| 400  | Bad Request            | Invalid request body, missing required field         |
| 401  | Unauthorized           | Missing or expired JWT token                         |
| 403  | Forbidden              | Valid token but insufficient permissions             |
| 404  | Not Found              | Resource does not exist                              |
| 409  | Conflict               | Resource already exists (e.g., duplicate plugin)     |
| 422  | Unprocessable Entity   | Validation error (Pydantic)                          |
| 429  | Too Many Requests      | Rate limit exceeded (login lockout)                  |
| 500  | Internal Server Error  | Unexpected server error                              |
| 502  | Bad Gateway            | External service unreachable (Ollama, notification)  |
| 503  | Service Unavailable    | Required service not running (Redis, Docker)         |

---

## Rate Limits

| Endpoint                        | Limit                                    |
|---------------------------------|------------------------------------------|
| `POST /api/auth/login`   | 5 attempts per 30 minutes (then lockout) |
| `POST /api/devices/scan`        | 1 per 60 seconds                         |
| `POST /api/firewall/panic`      | 1 per 60 seconds                         |
| `POST /api/notifications/test/*`| 1 per channel per 60 seconds             |
| All other endpoints             | No explicit limit (protected by auth)    |
