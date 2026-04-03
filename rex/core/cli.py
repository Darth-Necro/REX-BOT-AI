"""REX CLI -- Typer-based command-line interface.

Provides all rex commands: start, stop, status, scan, sleep, wake, diag, version.
The ``start`` command initializes the full orchestrator and runs until SIGINT/SIGTERM.
"""

from __future__ import annotations

import asyncio
import logging

# TLS verification is ENABLED by default.  For local development with
# self-signed certs, set REX_DEV_INSECURE=1 in the environment.
# This flag is intentionally narrow: it only disables TLS certificate
# verification for CLI -> local dashboard requests, NOT for any other
# HTTP client in the codebase.  MUST NOT be used in production or alpha deployments.
import os as _os
import sys
import warnings
from datetime import UTC

import typer

from rex.shared.constants import VERSION

_DEV_INSECURE = _os.environ.get("REX_DEV_INSECURE", "").strip() in ("1", "true", "yes")
if _DEV_INSECURE:
    logging.getLogger(__name__).warning(
        "REX_DEV_INSECURE is set — TLS certificate verification DISABLED for CLI commands. "
        "Do NOT use this in production or alpha deployments."
    )
    # Suppress only the specific httpx/urllib3 warning for unverified HTTPS
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def _redact_url(url: str) -> str:
    """Redact password from a URL for safe display (e.g. redis://:***@host)."""
    from urllib.parse import urlparse, urlunparse

    try:
        parsed = urlparse(url)
        if parsed.password:
            # Replace password with '***', preserve username if present
            netloc = f"{parsed.username or ''}:***@{parsed.hostname}"
            if parsed.port:
                netloc += f":{parsed.port}"
            return urlunparse(parsed._replace(netloc=netloc))
    except Exception:
        pass
    return url

app = typer.Typer(
    name="rex",
    help="REX-BOT-AI -- Open-source autonomous AI security agent.",
    no_args_is_help=True,
)

# Default to HTTPS -- REX uses self-signed TLS on port 8443.
# Override via REX_API_URL env var if needed.
_DEFAULT_API_URL = _os.environ.get("REX_API_URL", "").strip() or "https://localhost:8443"


def _setup_logging(level: str = "info") -> None:
    """Configure structured logging."""
    numeric = getattr(logging, level.upper(), None)
    if numeric is None:
        numeric = logging.INFO
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )


@app.command()
def start(
    log_level: str = typer.Option("info", help="Log level: debug, info, warning, error"),
) -> None:
    """Start all REX services (blocks until Ctrl+C)."""
    _setup_logging(log_level)

    typer.echo(r"""
        ^
       / \__
      (    @\___     ____  _______  __     ____   ____ _______
      /         O   |  _ \| ____\ \/ /    | __ ) / __ \__   __|
     /   (_____/    | |_) |  _|  \  / ____|  _ \| |  | | | |
    /_____/   U     |  _ <| |___ /  \|____| |_) | |  | | | |
                    |_| \_\_____|/_/\_\   |____/ \____/  |_|  AI
""" + f"                                                       v{VERSION}" + r"""
                    *woof woof* ... Starting up!
""")

    from rex.shared.config import get_config
    config = get_config()
    typer.echo(f"  Mode:   {config.mode.value}")
    typer.echo(f"  Data:   {config.data_dir}")
    typer.echo(f"  Redis:  {_redact_url(config.redis_url)}")
    typer.echo(f"  Ollama: {config.ollama_url}")
    typer.echo("")

    # Pre-initialize auth to show first-boot password to the user
    from rex.dashboard.auth import AuthManager
    auth_mgr = AuthManager(data_dir=config.data_dir)

    initial_pw = asyncio.run(auth_mgr.initialize())
    if initial_pw:
        # Display password on stderr only, so it is never captured in
        # stdout pipes or redirected logs.
        import sys
        print("  " + "=" * 46, file=sys.stderr)
        print(f"  ADMIN PASSWORD: {initial_pw}", file=sys.stderr)
        print("  Write this down. It will not be shown again.", file=sys.stderr)
        print("  " + "=" * 46, file=sys.stderr)
        print("", file=sys.stderr)

    from rex.core.orchestrator import ServiceOrchestrator

    async def _run() -> None:
        orch = ServiceOrchestrator()
        await orch.initialize()
        await orch.run()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        typer.echo(r"""
        ^
       / \__
      (  - @\___   *yaaawn* ... REX is going to sleep.
      /         O  Goodbye!
     /   (_____/
    /_____/   U
""")


@app.command()
def stop() -> None:
    """Stop all REX services gracefully (sends SIGTERM to running instance)."""
    import os
    import signal

    from rex.shared.config import get_config
    pidfile = str(get_config().data_dir / "rex-bot-ai.pid")
    if os.path.exists(pidfile):
        with open(pidfile) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        typer.echo(r"""
        ^
       / \__
      (  - @\___   *ruff* Sent stop signal to REX (PID """ + str(pid) + r""")
      /         O  *woof* ... going down...
     /   (_____/
    /_____/   U
""")
    else:
        typer.echo(r"""
        ^
       / \__
      (  ? @\___   *whimper* REX does not appear to be running.
      /         O  (no PID file found)
     /   (_____/
    /_____/   U
""")


@app.command()
def status() -> None:
    """Show health status of all REX services."""
    import httpx
    typer.echo(r"""
        ^
       / \__
      (    @\___   REX-BOT-AI v""" + VERSION + r"""
      /         O  *ruff* Status report!
     /   (_____/
    /_____/   U
""")
    typer.echo("")
    try:
        headers: dict[str, str] = {}
        token = _get_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = httpx.get(
            f"{_DEFAULT_API_URL}/api/status",
            timeout=5,
            verify=not _DEV_INSECURE,
            headers=headers,
        )
        data = resp.json()
        typer.echo(f"  Status:     {data.get('status', 'unknown')}")
        # Full fields are only present when authenticated
        if "device_count" in data:
            typer.echo(f"  Devices:    {data['device_count']}")
        if "active_threats" in data:
            typer.echo(f"  Threats:    {data['active_threats']}")
        if "llm_status" in data:
            typer.echo(f"  LLM:        {data['llm_status']}")
        if "power_state" in data:
            typer.echo(f"  Power:      {data['power_state']}")
        if not token:
            typer.echo("  (Login with 'rex login' for full status details)")
        typer.echo("")
        services = data.get("services", {})
        for name, info in services.items():
            healthy = info.get("healthy", False)
            mark = "OK" if healthy else "FAIL"
            degraded = " (degraded)" if info.get("degraded") else ""
            typer.echo(f"  rex-{name:12s} [{mark}]{degraded}")
    except Exception as exc:
        typer.echo("  Cannot reach REX dashboard. Is REX running?")
        if "CERTIFICATE_VERIFY_FAILED" in str(exc) or "SSL" in str(exc):
            typer.echo("  TLS verification failed. For self-signed certs, set REX_DEV_INSECURE=1")
        typer.echo("  Start with: rex start")


@app.command()
def version() -> None:
    """Print the REX-BOT-AI version string."""
    typer.echo(r"""
        ^
       / \__
      (    @\___     ____  _______  __     ____   ____ _______
      /         O   |  _ \| ____\ \/ /    | __ ) / __ \__   __|
     /   (_____/    | |_) |  _|  \  / ____|  _ \| |  | | | |
    /_____/   U     |  _ <| |___ /  \|____| |_) | |  | | | |
                    |_| \_\_____|/_/\_\   |____/ \____/  |_|  AI
""" + f"                                                       v{VERSION}" + r"""
                    *woof!*
""")


@app.command()
def login(
    username: str = typer.Option("admin", help="Username"),
    password: str = typer.Option(..., prompt=True, hide_input=True, help="Password"),
) -> None:
    """Authenticate with the REX API and save token for future CLI commands."""
    import os

    import httpx

    try:
        resp = httpx.post(
            f"{_DEFAULT_API_URL}/api/auth/login",
            json={"password": password},
            timeout=10,
            verify=not _DEV_INSECURE,
        )
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("access_token", "") or data.get("token", "")
            if token:
                token_file = os.path.expanduser("~/.rex-token")
                with open(token_file, "w") as f:
                    f.write(token)
                os.chmod(token_file, 0o600)
                typer.echo(r"""
        ^
       / \__
      (    @\___   *WOOF WOOF!* Login successful!
      /         O  Token saved to ~/.rex-token
     /   (_____/
    /_____/   U
""")
            else:
                typer.echo("  *ruff?* Login response did not contain a token.")
        else:
            typer.echo(f"  *GRRR* Login failed: {resp.status_code} {resp.text}")
    except Exception as e:
        typer.echo(f"  *whimper* Cannot reach REX API: {e}")


@app.command()
def scan(
    quick: bool = typer.Option(True, help="Quick scan (top 100 ports) vs deep (all ports)"),
    target: str = typer.Option("", help="Specific IP to scan (default: entire network)"),
) -> None:
    """Trigger an immediate network scan."""
    scan_type = "quick" if quick else "deep"
    msg = f"*ruff ruff* Triggering {scan_type} network scan"
    if target:
        msg += f" on {target}"
    typer.echo(r"""
        ^
       / \__
      (    @\___   """ + msg + r"""
      /         O  *sniff sniff* ... scanning ...
     /   (_____/
    /_____/   U
""")
    try:
        import httpx
        body: dict[str, str] = {"scan_type": scan_type}
        if target:
            body["target"] = target
        resp = httpx.post(
            f"{_DEFAULT_API_URL}/api/devices/scan",
            json=body,
            timeout=10,
            verify=not _DEV_INSECURE,
            headers={"Authorization": f"Bearer {_get_token()}"},
        )
        data = resp.json()
        typer.echo(f"  {data.get('status', 'unknown')}")
        if data.get("delivered"):
            typer.echo("  *WOOF!* Scan command delivered to event bus.")
    except Exception as e:
        typer.echo(f"  *whimper* Cannot reach REX: {e}")


@app.command()
def sleep() -> None:
    """Put REX into ALERT_SLEEP mode (lightweight watchdog only)."""
    typer.echo("  *woof* Requesting ALERT_SLEEP mode...")
    try:
        import httpx
        resp = httpx.post(
            f"{_DEFAULT_API_URL}/api/schedule/sleep",
            timeout=5,
            verify=not _DEV_INSECURE,
            headers={"Authorization": f"Bearer {_get_token()}"},
        )
        data = resp.json()
        typer.echo(f"  Status: {data.get('status', 'unknown')}")
        if data.get("delivered"):
            typer.echo(r"""
        ^
       / \__
      (  - @\___   *woof* ... zzz ... REX is sleeping
      /         O  with one ear open.
     /   (_____/   Lightweight monitoring active.
    /_____/   U
""")
        else:
            typer.echo(f"  *ruff?* Detail: {data.get('detail', 'No response')}")
    except Exception as e:
        typer.echo(f"  *whimper* Cannot reach REX: {e}")


@app.command()
def wake() -> None:
    """Wake REX to full AWAKE mode."""
    typer.echo("  *ruff ruff* Requesting AWAKE mode...")
    try:
        import httpx
        resp = httpx.post(
            f"{_DEFAULT_API_URL}/api/schedule/wake",
            timeout=5,
            verify=not _DEV_INSECURE,
            headers={"Authorization": f"Bearer {_get_token()}"},
        )
        data = resp.json()
        typer.echo(f"  Status: {data.get('status', 'unknown')}")
        if data.get("delivered"):
            typer.echo(r"""
        ^
       / \__
      (  O @\___   *WOOF WOOF!* REX is awake!
      /         O  Full monitoring and protection active.
     /   (_____/   *GRRR* ... watching everything!
    /_____/   U
""")
        else:
            typer.echo(f"  *ruff?* Detail: {data.get('detail', 'No response')}")
    except Exception as e:
        typer.echo(f"  *whimper* Cannot reach REX: {e}")


@app.command()
def junkyard() -> None:
    """Activate JUNKYARD DOG mode -- REX BITEs and removes all active threats."""
    typer.echo(r"""
        ^
       / \__
      (!O @\___    *WOOF WOOF GRRRRR!*
      /         O  JUNKYARD DOG MODE ACTIVATED!
     /   (_____/
    /_____/   U
     |||||||||
     CHAIN~~~~

  *GRRRRR* REX is now a JUNKYARD DOG!
  *WOOF!* BITE mode active -- REX will:
    - BITE and REMOVE all active threats from your network
    - Block, quarantine, and rate-limit attackers simultaneously
    - Secure all machines from outside threats
    - Notify owner of every attack and what REX did about it
  *GRRRRR WOOF WOOF!* ... No mercy! No intruder gets out alive!
""")
    try:
        import httpx
        resp = httpx.post(
            f"{_DEFAULT_API_URL}/api/config/protection-mode",
            json={"mode": "junkyard_dog"},
            timeout=5,
            verify=not _DEV_INSECURE,
            headers={"Authorization": f"Bearer {_get_token()}"},
        )
        data = resp.json()
        typer.echo(f"  Status: {data.get('status', 'unknown')}")
        if data.get("mode") == "junkyard_dog":
            typer.echo(
                "  *WOOF WOOF GRRRRR!* Junkyard Dog mode is ACTIVE."
                " REX will eliminate all threats!"
            )
    except Exception as e:
        typer.echo(f"  *whimper* Cannot reach REX: {e}")


@app.command()
def patrol(
    schedule: str = typer.Option(
        "",
        help="Cron schedule (e.g. '0 2 * * *' for 2am daily, '0 */4 * * *' every 4h)",
    ),
    now: bool = typer.Option(False, help="Run a patrol immediately"),
) -> None:
    """Schedule REX to patrol -- run security audits and inspect the network on a timer."""
    if now:
        typer.echo(r"""
        ^
       / \__
      (  O @\___   *WOOF WOOF!* REX is going on patrol!
      /         O  *sniff sniff* Inspecting the network...
     /   (_____/
    /_____/   U
""")
        try:
            import httpx
            # Trigger a full scan + audit
            resp = httpx.post(
                f"{_DEFAULT_API_URL}/api/devices/scan",
                json={"scan_type": "deep"},
                timeout=10,
                verify=not _DEV_INSECURE,
                headers={"Authorization": f"Bearer {_get_token()}"},
            )
            data = resp.json()
            typer.echo(f"  *ruff* Scan: {data.get('status', 'unknown')}")

            # Run privacy audit
            resp2 = httpx.get(
                f"{_DEFAULT_API_URL}/api/privacy/audit",
                timeout=10,
                verify=not _DEV_INSECURE,
                headers={"Authorization": f"Bearer {_get_token()}"},
            )
            audit = resp2.json()
            findings = audit.get("findings_count", "?")
            typer.echo(f"  *ruff ruff* Audit findings: {findings}")
            typer.echo("  *WOOF!* Patrol complete! Network inspected and secured.")
        except Exception as e:
            typer.echo(f"  *whimper* Cannot reach REX: {e}")
        return

    if not schedule:
        typer.echo(r"""
        ^
       / \__
      (    @\___   *ruff?* Please provide a schedule or use --now
      /         O
     /   (_____/   Examples:
    /_____/   U      rex patrol --now              (patrol right now)
                     rex patrol --schedule "0 2 * * *"   (2am daily)
                     rex patrol --schedule "0 */6 * * *"  (every 6 hours)
                     rex patrol --schedule "0 0 * * 1"   (midnight Monday)
""")
        return

    typer.echo(r"""
        ^
       / \__
      (    @\___   *WOOF!* Patrol scheduled!
      /         O  Schedule: """ + schedule + r"""
     /   (_____/   *ruff ruff* REX will wake up, scan the network,
    /_____/   U    run audits, and go back to sleep.
""")
    try:
        import httpx
        resp = httpx.post(
            f"{_DEFAULT_API_URL}/api/schedule/patrol",
            json={"cron": schedule},
            timeout=5,
            verify=not _DEV_INSECURE,
            headers={"Authorization": f"Bearer {_get_token()}"},
        )
        data = resp.json()
        typer.echo(f"  *ruff* Status: {data.get('status', 'unknown')}")
        if data.get("scheduled"):
            typer.echo("  *WOOF!* Patrol is scheduled! REX will be on duty.")
    except Exception as e:
        typer.echo(f"  *whimper* Cannot reach REX: {e}")


@app.command()
def diag() -> None:
    """Full diagnostic dump for bug reports."""
    from rex.pal.detector import detect_hardware, detect_os, recommend_llm_model
    from rex.pal.docker_helper import get_docker_version, is_docker_installed, is_docker_running

    typer.echo(r"""
        ^
       / \__
      (    @\___   REX-BOT-AI v""" + VERSION + r"""
      /         O  *ruff ruff* Diagnostic sniff...
     /   (_____/   *sniff sniff*
    /_____/   U""")
    typer.echo("=" * 40)

    os_info = detect_os()
    typer.echo(f"OS:     {os_info.name} {os_info.version} ({os_info.architecture})")
    typer.echo(f"WSL:    {os_info.is_wsl}")
    typer.echo(f"Docker: {os_info.is_docker}")
    typer.echo(f"VM:     {os_info.is_vm}")
    typer.echo(f"Pi:     {os_info.is_raspberry_pi}")

    hw = detect_hardware()
    typer.echo(f"CPU:    {hw.cpu_model} ({hw.cpu_cores} cores, {hw.cpu_percent:.0f}%)")
    typer.echo(f"RAM:    {hw.ram_available_mb}/{hw.ram_total_mb} MB available")
    typer.echo(f"Disk:   {hw.disk_free_gb:.1f}/{hw.disk_total_gb:.1f} GB free")
    if hw.gpu_model:
        typer.echo(f"GPU:    {hw.gpu_model} ({hw.gpu_vram_mb} MB VRAM)")
    else:
        typer.echo("GPU:    None detected")

    typer.echo(f"LLM:    {recommend_llm_model(hw)}")
    typer.echo(f"Docker: {'installed' if is_docker_installed() else 'NOT installed'}, "
               f"{'running' if is_docker_running() else 'NOT running'}, "
               f"v{get_docker_version() or 'N/A'}")


@app.command()
def backup() -> None:
    """Create an immediate backup of REX data."""
    typer.echo(r"""
        ^
       / \__
      (    @\___   *ruff* Creating backup...
      /         O  *woof* Burying bones safely!
     /   (_____/
    /_____/   U
""")
    import shutil
    from datetime import datetime

    from rex.shared.config import get_config
    config = get_config()
    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    backup_dir = config.data_dir / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    archive = shutil.make_archive(
        str(backup_dir / f"rex-backup-{ts}"), "gztar",
        root_dir=str(config.data_dir),
        base_dir=".",
    )
    typer.echo(f"  *WOOF!* Backup created: {archive}")


@app.command()
def privacy(
    remote: bool = typer.Option(False, help="Query the API instead of running locally"),
) -> None:
    """Run a privacy audit and display results."""
    if remote:
        try:
            import httpx
            resp = httpx.get(
                f"{_DEFAULT_API_URL}/api/privacy/audit",
                timeout=10,
                headers={"Authorization": f"Bearer {_get_token()}"},
            )
            data = resp.json()
            import json
            typer.echo(json.dumps(data, indent=2))
        except Exception as e:
            typer.echo(f"  *whimper* Cannot reach REX API: {e}")
        return

    typer.echo(r"""
        ^
       / \__
      (    @\___   *ruff ruff* Running privacy audit...
      /         O  *sniff sniff* Checking for leaks!
     /   (_____/
    /_____/   U
""")
    from rex.core.privacy.audit import PrivacyAuditor
    from rex.pal import get_adapter
    from rex.shared.config import get_config
    config = get_config()
    pal = get_adapter()
    auditor = PrivacyAuditor(config=config, pal=pal)
    report = auditor.generate_privacy_report()
    typer.echo(report)


def _get_token() -> str:
    """Read cached auth token from ~/.rex-token.

    Validates file permissions: the token file must not be readable by
    group or others (mode must be 0o600 or stricter).  If permissions
    are too open the file is ignored and a warning is printed.
    """
    import os
    import stat
    from pathlib import Path

    token_file = Path(os.path.expanduser("~/.rex-token"))
    if not token_file.exists():
        return ""
    try:
        mode = token_file.stat().st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
            logging.getLogger(__name__).warning(
                "Ignoring %s: file permissions too open (mode %o). "
                "Run: chmod 600 %s",
                token_file, stat.S_IMODE(mode), token_file,
            )
            return ""
    except OSError:
        return ""
    return token_file.read_text().strip()


def main() -> None:
    """Entry point for ``python -m rex.core.cli`` and the ``rex`` console script."""
    app()


if __name__ == "__main__":
    main()
