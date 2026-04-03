"""REX CLI -- Typer-based command-line interface.

Provides all rex commands: start, stop, status, scan, sleep, wake, diag, version.
The ``start`` command initializes the full orchestrator and runs until SIGINT/SIGTERM.
"""

from __future__ import annotations

import asyncio
import contextlib
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

# Default API URL.  If TLS certs are present the dashboard serves HTTPS;
# otherwise it falls back to HTTP.  Auto-detect by checking the certs dir.
def _detect_api_url() -> str:
    """Return the dashboard URL, auto-detecting HTTP vs HTTPS."""
    explicit = _os.environ.get("REX_API_URL", "").strip()
    if explicit:
        return explicit
    # Check whether TLS certs exist
    from pathlib import Path
    data_dir = _os.environ.get("REX_DATA_DIR", "/etc/rex-bot-ai")
    port = _os.environ.get("REX_DASHBOARD_PORT", "8443")
    certs_dir = Path(data_dir) / "certs"
    if (certs_dir / "cert.pem").exists() and (certs_dir / "key.pem").exists():
        return f"https://localhost:{port}"
    return f"http://localhost:{port}"

_DEFAULT_API_URL = _detect_api_url()


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
        try:
            os.kill(pid, signal.SIGTERM)
        except PermissionError:
            typer.echo(
                f"  *whimper* Cannot stop REX (PID {pid}): permission denied.\n"
                "  REX was started with elevated privileges.\n"
                "  Rerun with: sudo rex stop"
            )
            return
        except ProcessLookupError:
            typer.echo("  *whimper* REX process not found (stale PID file).")
            with contextlib.suppress(OSError):
                os.unlink(pidfile)
            return
        typer.echo(f"  *ruff* Sent stop signal to REX (PID {pid})")
        typer.echo("  *woof* ... going down...")
    else:
        typer.echo("  *whimper* REX does not appear to be running (no PID file found).")


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
    username: str = typer.Option("REX-BOT", help="Username"),
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
        headers: dict[str, str] = {}
        token = _get_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = httpx.post(
            f"{_DEFAULT_API_URL}/api/devices/scan",
            json=body,
            timeout=10,
            verify=not _DEV_INSECURE,
            headers=headers,
        )
        if resp.status_code == 401:
            typer.echo("  Not logged in. Run 'rex login' first.")
            return
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
            headers=_auth_headers(),
        )
        if not _check_auth_response(resp):
            return
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
            headers=_auth_headers(),
        )
        if not _check_auth_response(resp):
            return
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
    typer.echo("  *GRRRRR* Requesting JUNKYARD DOG mode...")
    try:
        import httpx
        resp = httpx.post(
            f"{_DEFAULT_API_URL}/api/config/protection-mode",
            json={"mode": "junkyard_dog"},
            timeout=5,
            verify=not _DEV_INSECURE,
            headers=_auth_headers(),
        )
        if not _check_auth_response(resp):
            return
        data = resp.json()
        if data.get("mode") == "junkyard_dog" or data.get("status") == "updated":
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
        else:
            typer.echo(f"  Status: {data.get('status', 'unknown')}")
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
                headers=_auth_headers(),
            )
            if not _check_auth_response(resp):
                return
            data = resp.json()
            typer.echo(f"  *ruff* Scan: {data.get('status', 'unknown')}")

            # Run privacy audit
            resp2 = httpx.get(
                f"{_DEFAULT_API_URL}/api/privacy/audit",
                timeout=10,
                verify=not _DEV_INSECURE,
                headers=_auth_headers(),
            )
            if not _check_auth_response(resp2):
                return
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
            headers=_auth_headers(),
        )
        if not _check_auth_response(resp):
            return
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
    import tarfile
    from datetime import datetime

    from rex.shared.config import get_config
    config = get_config()

    typer.echo("  *ruff* Creating backup...")

    backup_dir = config.data_dir / "backups"
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        typer.echo(f"  *whimper* Cannot create backup directory: {backup_dir}")
        typer.echo("  Check permissions or run with sudo.")
        return

    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    archive_path = backup_dir / f"rex-backup-{ts}.tar.gz"

    # Exclude the backups directory itself to avoid recursion
    exclude_dirs = {"backups", ".git", "__pycache__"}

    try:
        with tarfile.open(str(archive_path), "w:gz") as tar:
            for item in sorted(config.data_dir.iterdir()):
                if item.name in exclude_dirs:
                    continue
                try:
                    tar.add(str(item), arcname=item.name)
                except PermissionError:
                    typer.echo(f"  (skipped unreadable: {item.name})")
                except OSError as exc:
                    typer.echo(f"  (skipped {item.name}: {exc})")
    except Exception as exc:
        typer.echo(f"  *whimper* Backup failed: {exc}")
        # Clean up partial archive
        with contextlib.suppress(OSError):
            archive_path.unlink()
        return

    size_kb = archive_path.stat().st_size // 1024
    typer.echo(f"  *WOOF!* Backup created: {archive_path} ({size_kb} KB)")
    # Prune old backups, keep last 5
    backups = sorted(backup_dir.glob("rex-backup-*.tar.gz"))
    for old in backups[:-5]:
        with contextlib.suppress(OSError):
            old.unlink()
            typer.echo(f"  (pruned old backup: {old.name})")


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
                headers=_auth_headers(),
            )
            if not _check_auth_response(resp):
                return
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


def _auth_headers() -> dict[str, str]:
    """Return Authorization header dict, or empty dict if no token."""
    token = _get_token()
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def _check_auth_response(resp: object) -> bool:
    """Check if response indicates auth failure. Returns True if OK."""
    status_code = getattr(resp, "status_code", 200)
    if status_code == 401:
        typer.echo("  Not logged in. Run 'rex login' first.")
        return False
    return True


def main() -> None:
    """Entry point for ``python -m rex.core.cli`` and the ``rex`` console script."""
    app()


if __name__ == "__main__":
    main()
