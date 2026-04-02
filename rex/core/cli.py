"""REX CLI -- Typer-based command-line interface.

Provides all rex commands: start, stop, status, scan, sleep, wake, diag, version.
The ``start`` command initializes the full orchestrator and runs until SIGINT/SIGTERM.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
import warnings
from datetime import UTC

import typer

# TLS verification is ENABLED by default.  For local development with
# self-signed certs, set REX_DEV_INSECURE=1 in the environment.
# This flag is intentionally narrow: it only disables TLS certificate
# verification for CLI -> local dashboard requests, NOT for any other
# HTTP client in the codebase.  MUST NOT be used in production or alpha deployments.
import os as _os
_DEV_INSECURE = _os.environ.get("REX_DEV_INSECURE", "").strip() in ("1", "true", "yes")
if _DEV_INSECURE:
    logging.getLogger(__name__).warning(
        "REX_DEV_INSECURE is set — TLS certificate verification DISABLED for CLI commands. "
        "Do NOT use this in production or alpha deployments."
    )
    # Suppress only the specific httpx/urllib3 warning for unverified HTTPS
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from rex.shared.constants import VERSION

app = typer.Typer(
    name="rex",
    help="REX-BOT-AI -- Open-source autonomous AI security agent.",
    no_args_is_help=True,
)

_DEFAULT_API_URL = "http://localhost:8443"


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
  /\_/\
 ( o.o )  REX-BOT-AI v""" + VERSION + r"""
  > ^ <   Starting up...
 /|   |\
(_|   |_)
""")

    from rex.shared.config import get_config
    config = get_config()
    typer.echo(f"  Mode:   {config.mode.value}")
    typer.echo(f"  Data:   {config.data_dir}")
    typer.echo(f"  Redis:  {config.redis_url}")
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
        typer.echo("\nREX is going to sleep. Goodbye.")


@app.command()
def stop() -> None:
    """Stop all REX services gracefully (sends SIGTERM to running instance)."""
    import os
    import signal
    pidfile = "/tmp/rex-bot-ai.pid"  # noqa: S108
    if os.path.exists(pidfile):
        with open(pidfile) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        typer.echo(f"Sent stop signal to REX (PID {pid})")
    else:
        typer.echo("REX does not appear to be running (no PID file found).")


@app.command()
def status() -> None:
    """Show health status of all REX services."""
    import httpx
    typer.echo(f"REX-BOT-AI v{VERSION}")
    typer.echo("")
    try:
        resp = httpx.get(f"{_DEFAULT_API_URL}/api/status", timeout=5, verify=not _DEV_INSECURE)
        data = resp.json()
        typer.echo(f"  Status:     {data.get('status', 'unknown')}")
        typer.echo(f"  Devices:    {data.get('device_count', 0)}")
        typer.echo(f"  Threats:    {data.get('active_threats', 0)}")
        typer.echo(f"  LLM:        {data.get('llm_status', 'unknown')}")
        typer.echo(f"  Power:      {data.get('power_state', 'unknown')}")
        typer.echo("")
        services = data.get("services", {})
        for name, info in services.items():
            healthy = info.get("healthy", False)
            mark = "OK" if healthy else "FAIL"
            degraded = " (degraded)" if info.get("degraded") else ""
            typer.echo(f"  rex-{name:12s} [{mark}]{degraded}")
    except Exception:
        typer.echo("  Cannot reach REX dashboard. Is REX running?")
        typer.echo("  Start with: rex start")


@app.command()
def version() -> None:
    """Print the REX-BOT-AI version string."""
    typer.echo(f"REX-BOT-AI v{VERSION}")


@app.command()
def login(
    username: str = typer.Option("admin", help="Username"),
    password: str = typer.Option(..., prompt=True, hide_input=True, help="Password"),
) -> None:
    """Authenticate with the REX API and save token for future CLI commands."""
    import httpx
    import os

    try:
        resp = httpx.post(
            f"{_DEFAULT_API_URL}/api/auth/login",
            json={"username": username, "password": password},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("token", "")
            if token:
                token_file = os.path.expanduser("~/.rex-token")
                with open(token_file, "w") as f:
                    f.write(token)
                os.chmod(token_file, 0o600)
                typer.echo("Login successful. Token saved to ~/.rex-token")
            else:
                typer.echo("Login response did not contain a token.")
        else:
            typer.echo(f"Login failed: {resp.status_code} {resp.text}")
    except Exception as e:
        typer.echo(f"Cannot reach REX API: {e}")


@app.command()
def scan(
    quick: bool = typer.Option(True, help="Quick scan (top 100 ports) vs deep (all ports)"),
    target: str = typer.Option("", help="Specific IP to scan (default: entire network)"),
) -> None:
    """Trigger an immediate network scan."""
    scan_type = "quick" if quick else "deep"
    msg = f"Triggering {scan_type} network scan"
    if target:
        msg += f" on {target}"
    typer.echo(msg + "...")
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
            typer.echo("  Scan command delivered to event bus.")
    except Exception as e:
        typer.echo(f"  Cannot reach REX: {e}")


@app.command()
def sleep() -> None:
    """Put REX into ALERT_SLEEP mode (lightweight watchdog only)."""
    typer.echo("Requesting ALERT_SLEEP mode...")
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
            typer.echo("  REX is sleeping with one ear open. Lightweight monitoring active.")
        else:
            typer.echo(f"  Detail: {data.get('detail', 'No response')}")
    except Exception as e:
        typer.echo(f"  Cannot reach REX: {e}")


@app.command()
def wake() -> None:
    """Wake REX to full AWAKE mode."""
    typer.echo("Requesting AWAKE mode...")
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
            typer.echo("  REX is awake. Full monitoring and protection active.")
        else:
            typer.echo(f"  Detail: {data.get('detail', 'No response')}")
    except Exception as e:
        typer.echo(f"  Cannot reach REX: {e}")


@app.command()
def diag() -> None:
    """Full diagnostic dump for bug reports."""
    from rex.pal.detector import detect_hardware, detect_os, recommend_llm_model
    from rex.pal.docker_helper import get_docker_version, is_docker_installed, is_docker_running

    typer.echo(f"REX-BOT-AI v{VERSION}")
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
    typer.echo("Creating backup...")
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
    typer.echo(f"Backup created: {archive}")


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
            typer.echo(f"Cannot reach REX API: {e}")
        return

    typer.echo("Running privacy audit...")
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

    Warns if the token file has insecure permissions (readable by others).
    """
    import os
    import stat
    from pathlib import Path
    token_file = Path(os.path.expanduser("~/.rex-token"))
    if token_file.exists():
        # Check file permissions -- warn if group/other-readable
        try:
            mode = token_file.stat().st_mode & 0o777
            if mode & 0o077:
                typer.echo(
                    f"  WARNING: {token_file} has insecure permissions ({oct(mode)}). "
                    f"Run: chmod 600 {token_file}",
                    err=True,
                )
        except OSError:
            pass
        return token_file.read_text().strip()
    return ""


def main() -> None:
    """Entry point for ``python -m rex.core.cli`` and the ``rex`` console script."""
    app()


if __name__ == "__main__":
    main()
