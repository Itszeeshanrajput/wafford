"""CLI entry point for the Wafford framework."""

from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path

import click

from wafford.config import ConfigManager, ProfileName
from wafford.constants import (
    BANNER,
    OPTIONAL_TOOLS,
    REQUIRED_TOOLS,
    TOOL_PATHS,
    WAFFORD_HOME,
    ExitCode,
)
from wafford.db import DatabaseManager
from wafford.version import VERSION

logger = logging.getLogger("wafford")


def _check_root() -> bool:
    return os.geteuid() == 0


def _setup_logging(level: str = "INFO", log_to_file: bool = True) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]

    if log_to_file:
        log_dir = WAFFORD_HOME / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "wafford.log"
        handlers.append(logging.FileHandler(str(log_file), encoding="utf-8"))

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )

def _verify_tool(name: str) -> tuple[str, bool, str]:
    path = TOOL_PATHS.get(name, f"/usr/bin/{name}")
    if shutil.which(name):
        return (name, True, shutil.which(name) or "")
    if Path(path).is_file() and os.access(path, os.X_OK):
        return (name, True, path)
    return (name, False, path)


@click.group(invoke_without_command=True)
@click.option(
    "--check-deps",
    "check_deps",
    is_flag=True,
    help="Verify all required system tools are installed.",
)
@click.option(
    "--update",
    "do_update",
    is_flag=True,
    help="Self-update Wafford to the latest version.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(),
    default=None,
    help="Path to a custom config file.",
)
@click.option(
    "--minconfig",
    "min_config",
    is_flag=True,
    help="Print minimal configuration template and exit.",
)
@click.option(
    "--headless",
    is_flag=True,
    default=False,
    help="Run with minimal zero-dependency config (plain theme, safe defaults).",
)
@click.option(
    "--profile",
    type=click.Choice(["default", "minimal", "full"], case_sensitive=False),
    default="default",
    show_default=True,
    help="Load a named configuration profile.",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    default=None,
)
@click.version_option(VERSION, "-V", "--version", prog_name="Wafford")
@click.pass_context
def cli(
    ctx: click.Context,
    check_deps: bool,
    do_update: bool,
    config_path: str | None,
    min_config: bool,
    headless: bool,
    profile: str,
    log_level: str | None,
) -> None:
    """Wafford — Professional WiFi Auditing Framework."""
    ctx.ensure_object(dict)

    if min_config:
        import yaml
        click.echo(yaml.dump(ConfigManager.minconfig(), default_flow_style=False, sort_keys=False))
        ctx.exit(0)
        return

    # Build effective profile name: headless forces 'minimal'
    effective_profile: ProfileName = "minimal" if headless else profile  # type: ignore[assignment]

    # Load config
    mgr = ConfigManager(config_path=config_path, profile=effective_profile, headless=headless)
    cfg = mgr.load()
    mgr.validate()

    ctx.obj["config"] = cfg
    ctx.obj["config_manager"] = mgr
    ctx.obj["headless"] = headless
    ctx.obj["profile"] = effective_profile

    effective_level = log_level or cfg.logging.log_level
    _setup_logging(level=effective_level, log_to_file=cfg.logging.log_to_file)

    # Handle sub-commands that exit early
    if check_deps:
        _run_check_deps()
        ctx.exit(0)
        return

    if do_update:
        _run_self_update()
        ctx.exit(0)
        return

    if ctx.invoked_subcommand is None:
        _launch_ui(ctx)


def _run_check_deps() -> None:
    """Verify required and optional system tools."""
    click.echo(f"\n{BANNER.format(version=VERSION)}")
    click.echo("Dependency Check\n" + "=" * 50)

    all_ok = True

    click.echo("\n  Required Tools:")
    for tool in REQUIRED_TOOLS:
        name, found, path = _verify_tool(tool)
        status = click.style("FOUND", fg="green") if found else click.style("MISSING", fg="red")
        path_display = path if found else "not found"
        click.echo(f"    {name:<20} [{status}]  {path_display}")
        if not found:
            all_ok = False

    click.echo("\n  Optional Tools:")
    for tool in OPTIONAL_TOOLS:
        name, found, path = _verify_tool(tool)
        status = (
            click.style("FOUND", fg="green")
            if found
            else click.style("NOT FOUND", fg="yellow")
        )
        path_display = path if found else "not installed"
        click.echo(f"    {name:<20} [{status}]  {path_display}")

    click.echo("\n" + "=" * 50)
    if all_ok:
        click.echo(click.style("  All required tools are installed.", fg="green"))
    else:
        click.echo(click.style("  Some required tools are missing.", fg="red"))
        click.echo("  Install them with: sudo apt install aircrack-ng mdk4 macchanger iw rfkill")

    click.echo(f"\n  Wafford home: {WAFFORD_HOME}")
    click.echo(f"  Version: {VERSION}\n")


def _run_self_update() -> None:
    """Self-update mechanism."""
    click.echo(f"\n{BANNER.format(version=VERSION)}")
    click.echo("Self-Update\n" + "=" * 50)

    try:
        import subprocess

        git = shutil.which("git")
        if not git:
            click.echo(click.style("  git is required for self-update.", fg="red"))
            return

        pip = shutil.which("pip3") or shutil.which("pip")
        if not pip:
            click.echo(click.style("  pip is required for self-update.", fg="red"))
            return

        click.echo("  Checking for updates...")
        result = subprocess.run(
            [pip, "install", "--upgrade", "wafford"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            click.echo(click.style("  Update complete!", fg="green"))
        else:
            click.echo(click.style(f"  Update failed: {result.stderr[:200]}", fg="red"))
    except Exception as exc:
        click.echo(click.style(f"  Update error: {exc}", fg="red"))


async def _init_database(db_path: Path | None = None) -> DatabaseManager:
    """Initialize and return the database manager."""
    db = DatabaseManager(db_path=db_path)
    await db.init_db()
    return db


def _launch_ui(ctx: click.Context) -> None:
    """Launch the Wafford TUI application."""
    headless: bool = ctx.obj.get("headless", False)

    click.echo(f"\n{BANNER.format(version=VERSION)}")

    if headless:
        click.echo("  Running in headless/minimal mode.\n")

    # Warn but don't block if not root
    if not _check_root():
        click.echo(click.style(
            "  WARNING: Not running as root. Some WiFi operations will be limited.\n"
            "  Run with: sudo wafford\n",
            fg="yellow",
        ))

    # Ensure directories exist
    WAFFORD_HOME.mkdir(parents=True, exist_ok=True)
    (WAFFORD_HOME / "data").mkdir(exist_ok=True)
    (WAFFORD_HOME / "logs").mkdir(exist_ok=True)
    (WAFFORD_HOME / "reports").mkdir(exist_ok=True)
    (WAFFORD_HOME / "plugins").mkdir(exist_ok=True)

    click.echo("  Starting Wafford TUI...\n")

    try:
        from wafford.ui.app import WaffordApp

        app = WaffordApp()
        app.run()
    except ImportError as exc:
        click.echo(click.style(
            f"  UI dependency missing: {exc}\n"
            "  Run: pip install textual rich\n",
            fg="red",
        ))
        sys.exit(ExitCode.GENERAL_ERROR)
    except KeyboardInterrupt:
        click.echo("\n  Interrupted.")
        sys.exit(ExitCode.INTERRUPTED)
    except Exception as exc:
        logger.exception("Fatal error during startup")
        click.echo(click.style(f"\n  Fatal error: {exc}", fg="red"))
        sys.exit(ExitCode.GENERAL_ERROR)


# ── Subcommands ───────────────────────────────────────────────────────────────


@cli.command("scan")
@click.option("-i", "--interface", required=True, help="Wireless interface to scan with.")
@click.option("-c", "--channels", default=None, help="Comma-separated channels to scan.")
@click.option("-d", "--duration", type=int, default=30, help="Scan duration in seconds.")
def cmd_scan(interface: str, channels: str | None, duration: int) -> None:
    """Perform a wireless network scan."""
    import asyncio

    if not _check_root():
        click.echo(click.style("  Root privileges required.", fg="red"))
        sys.exit(ExitCode.NO_ROOT)

    ch_list = [int(c.strip()) for c in channels.split(",")] if channels else None

    async def _run() -> None:
        from wafford.core.scanner import NetworkScanner

        scanner = NetworkScanner(interface)
        click.echo(f"  Scanning on {interface} for {duration}s...")

        async for result in scanner.scan(channels=ch_list, duration=duration):
            from wafford.core.interface import InterfaceManager

            bars = InterfaceManager.signal_to_bar(result.signal_dbm)
            click.echo(
                f"  {result.bssid}  {result.essid or '<hidden>':<32} "
                f"CH:{result.channel:<4}  {result.encryption:<12}  "
                f"{bars} {result.signal_dbm}dBm"
            )

        click.echo(f"\n  Scan complete. Found {len(scanner.results)} network(s).\n")

        # Save results
        output = WAFFORD_HOME / "data" / f"scan_{interface}_{duration}.json"
        scanner.save_results(output)
        click.echo(f"  Results saved to {output}")

    asyncio.run(_run())


@cli.command("interfaces")
def cmd_interfaces() -> None:
    """List detected wireless interfaces."""
    from wafford.core.interface import InterfaceManager

    mgr = InterfaceManager()
    interfaces = mgr.detect_interfaces()

    if not interfaces:
        click.echo(click.style("  No wireless interfaces detected.", fg="yellow"))
        return

    click.echo(f"\n  {'Name':<12} {'Mode':<10} {'MAC':<20} {'Chipset'}")
    click.echo("  " + "-" * 70)
    for iface in interfaces:
        mode_color = "green" if iface.mode == "managed" else "yellow"
        mode_str = click.style(f"{iface.mode:<10}", fg=mode_color)
        click.echo(
            f"  {iface.name:<12} "
            f"{mode_str} "
            f"{iface.mac:<20} "
            f"{iface.chipset or 'N/A'}"
        )
    click.echo()


@cli.command("monitor")
@click.option("-i", "--interface", required=True, help="Interface to put in monitor mode.")
@click.option("--stop", "stop_monitor", is_flag=True, help="Restore managed mode.")
def cmd_monitor(interface: str, stop_monitor: bool) -> None:
    """Enable or disable monitor mode on an interface."""
    if not _check_root():
        click.echo(click.style("  Root privileges required.", fg="red"))
        sys.exit(ExitCode.NO_ROOT)

    from wafford.core.interface import InterfaceManager

    mgr = InterfaceManager()

    if stop_monitor:
        info = mgr.set_managed_mode(interface)
        click.echo(f"  Managed mode restored on {info.name}")
    else:
        info = mgr.set_monitor_mode(interface)
        click.echo(f"  Monitor mode enabled on {info.name}")
        click.echo(f"  MAC: {info.mac}")


@cli.command("inject")
@click.option("-i", "--interface", required=True, help="Interface to test injection on.")
def cmd_inject(interface: str) -> None:
    """Test packet injection capability."""
    if not _check_root():
        click.echo(click.style("  Root privileges required.", fg="red"))
        sys.exit(ExitCode.NO_ROOT)

    from wafford.core.interface import InterfaceManager

    mgr = InterfaceManager()
    click.echo(f"  Testing injection on {interface}...")
    result = mgr.check_injection(interface)
    if result:
        click.echo(click.style("  Injection test PASSED", fg="green"))
    else:
        click.echo(click.style("  Injection test FAILED", fg="red"))


@cli.command("mac")
@click.option("-i", "--interface", required=True, help="Interface to randomise MAC for.")
@click.option("--restore", "restore_mac", is_flag=True, help="Restore original MAC address.")
def cmd_mac(interface: str, restore_mac: bool) -> None:
    """Randomise or restore the MAC address of an interface."""
    if not _check_root():
        click.echo(click.style("  Root privileges required.", fg="red"))
        sys.exit(ExitCode.NO_ROOT)

    from wafford.core.interface import InterfaceManager

    mgr = InterfaceManager()
    if restore_mac:
        mac = mgr.restore_mac(interface)
        click.echo(f"  MAC restored to {mac}")
    else:
        mac = mgr.randomize_mac(interface)
        click.echo(f"  MAC randomised to {mac}")


@cli.command("db")
@click.argument("action", type=click.Choice(["init", "status", "backup", "export", "vacuum"]))
@click.option("--output", type=click.Path(), default=None, help="Output path for export/backup.")
def cmd_db(action: str, output: str | None) -> None:
    """Database management commands."""
    import asyncio

    async def _run() -> None:
        db = DatabaseManager()
        await db.init_db()

        if action == "init":
            click.echo("  Database initialised successfully.")
        elif action == "status":
            status = db.migration_status()
            click.echo(f"  Current version: {status.get('current_version')}")
            click.echo(f"  Target version:  {status.get('target_version')}")
            click.echo(f"  Pending:         {status.get('pending_count')}")
            sessions = await db.get_sessions()
            click.echo(f"  Sessions:        {len(sessions)}")
        elif action == "backup":
            dest = await db.backup(output)
            click.echo(f"  Backup saved to {dest}")
        elif action == "export":
            dest = await db.export_json(output or str(WAFFORD_HOME / "data" / "export.json"))
            click.echo(f"  Exported to {dest}")
        elif action == "vacuum":
            await db.vacuum()
            click.echo("  Database vacuumed.")

        await db.close()

    asyncio.run(_run())


@cli.command("config")
@click.argument("action", type=click.Choice(["show", "reset", "set", "get", "min"]))
@click.option("--key", default=None, help="Config key (for get/set).")
@click.option("--value", default=None, help="Config value (for set).")
def cmd_config(action: str, key: str | None, value: str | None) -> None:
    """View or modify Wafford configuration."""
    mgr = ConfigManager()

    if action == "show":
        import yaml
        mgr.load()
        click.echo(yaml.dump(mgr.to_dict(), default_flow_style=False, sort_keys=False))
    elif action == "min":
        import yaml
        click.echo(yaml.dump(ConfigManager.minconfig(), default_flow_style=False, sort_keys=False))
    elif action == "reset":
        mgr.reset()
        click.echo("  Configuration reset to defaults.")
    elif action == "get":
        if not key:
            click.echo("  --key is required for get.")
            return
        mgr.load()
        val = mgr.get(key)
        click.echo(f"  {key} = {val}")
    elif action == "set":
        if not key or not value:
            click.echo("  --key and --value are required for set.")
            return
        mgr.load()
        mgr.set(key, value)
        mgr.save()
        click.echo(f"  {key} = {value} (saved)")


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    """Main entry point for the `wafford` CLI command."""
    try:
        cli(standalone_mode=True)
    except KeyboardInterrupt:
        click.echo("\n  Interrupted.")
        sys.exit(ExitCode.INTERRUPTED)
    except click.Abort:
        click.echo("\n  Aborted.")
        sys.exit(ExitCode.INTERRUPTED)
    except click.UsageError as exc:
        click.echo(click.style(f"  Usage error: {exc}", fg="red"))
        sys.exit(ExitCode.USAGE_ERROR)
    except Exception as exc:
        click.echo(click.style(f"  Fatal error: {exc}", fg="red"))
        sys.exit(ExitCode.GENERAL_ERROR)


if __name__ == "__main__":
    main()
