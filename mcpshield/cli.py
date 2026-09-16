import asyncio
import json
import re
import shlex
import sys
from pathlib import Path
from typing import List, Optional

import typer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client
from rich.console import Console
from rich.table import Table

from mcpshield import __version__
from mcpshield.config import discover_configs, load_servers
from mcpshield.detector import assess_tool
from mcpshield.snapshot import apply_diff, build_snapshot, diff_snapshot, fingerprint, load_snapshot, save_snapshot

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main():
    """MCPShield: scan MCP servers for tool poisoning."""


RISK_STYLE = {
    "SAFE": "[green]SAFE[/green]",
    "WARNING": "[yellow]WARNING[/yellow]",
    "DANGEROUS": "[bold red]DANGEROUS[/bold red]",
}

# Higher number = worse. Used for the --fail-on threshold and the summary.
RISK_ORDER = {"SAFE": 0, "WARNING": 1, "DANGEROUS": 2}

DEFAULT_TIMEOUT = 30.0

# Status messages go to stderr so --json output on stdout stays parseable.
err = Console(stderr=True)


# --- Collecting tools -------------------------------------------------------


def parse_command(server_command):
    """Split a quoted command line into (command, args)."""
    parts = shlex.split(server_command)
    if not parts:
        raise typer.BadParameter("server command is empty")
    return parts[0], parts[1:]


async def collect_tools(command, args=(), env=None, timeout=DEFAULT_TIMEOUT):
    """Launch a stdio server, list its tools, and assess each one."""
    full_env = get_default_environment()
    if env:
        full_env.update(env)
    server = StdioServerParameters(command=command, args=list(args), env=full_env)

    async def inner():
        async with stdio_client(server) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await session.list_tools()

    result = await asyncio.wait_for(inner(), timeout=timeout)

    report = []
    for tool in result.tools:
        risk, findings = assess_tool(tool.description, tool.input_schema)
        report.append({
            "name": tool.name,
            "risk": risk,
            "description": tool.description,
            "fingerprint": fingerprint(tool.description, tool.input_schema),
            "findings": findings,
            "inputs": list(tool.input_schema.get("properties", {}).keys()),
        })
    return report


def describe_error(exc):
    """One-line, human-readable reason a server could not be scanned."""
    if isinstance(exc, asyncio.TimeoutError):
        return "timed out waiting for the server to answer initialize/list_tools"
    # anyio wraps subprocess failures in an ExceptionGroup; surface the leaves.
    leaves = getattr(exc, "exceptions", None)
    if leaves:
        return "; ".join(describe_error(e) for e in leaves)
    msg = str(exc).strip() or exc.__class__.__name__
    return f"{exc.__class__.__name__}: {msg}"


# --- Snapshots --------------------------------------------------------------


def apply_snapshot(report, server_command, snapshot_path, update):
    """Diff the report against a baseline file, or create the baseline.

    Returns the diff dict, or None when a new baseline was just written.
    """
    current = build_snapshot(report, server=server_command)
    baseline = load_snapshot(snapshot_path)
    if baseline is None:
        save_snapshot(snapshot_path, current)
        err.print(f"[cyan]Baseline saved:[/cyan] {snapshot_path} ({len(report)} tools). Re-run to detect changes.")
        return None

    diff = diff_snapshot(baseline, current)
    apply_diff(report, baseline, diff)
    if update:
        save_snapshot(snapshot_path, current)
        err.print(f"[cyan]Baseline updated:[/cyan] {snapshot_path}")
    return diff


def snapshot_filename(server_name):
    return re.sub(r"[^\w.-]+", "_", server_name).strip("_") + ".json"


# --- Output -----------------------------------------------------------------


def format_findings(findings):
    if not findings:
        return "No problems found."
    lines = []
    for f in findings:
        where = "" if f["location"] == "description" else f" (in {f['location']})"
        lines.append(f"{f['rule']}: {f['evidence']}{where}")
    return "\n".join(lines)


def summary_line(tools):
    counts = {level: sum(1 for t in tools if t["risk"] == level) for level in RISK_ORDER}
    return (
        f"Summary: {RISK_STYLE['DANGEROUS']} {counts['DANGEROUS']}  "
        f"{RISK_STYLE['WARNING']} {counts['WARNING']}  "
        f"{RISK_STYLE['SAFE']} {counts['SAFE']}"
    )


def diff_line(diff, snapshot_path):
    return (
        f"Baseline {snapshot_path}: "
        f"[bold red]{len(diff['changed'])} changed[/bold red]  "
        f"[yellow]{len(diff['added'])} added[/yellow]  "
        f"[yellow]{len(diff['removed'])} removed[/yellow]  "
        f"{len(diff['unchanged'])} unchanged"
    )


def print_table(report, diff=None, snapshot_path=None):
    table = Table(title=f"MCP Scan — {len(report)} tools found")
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Risk")
    table.add_column("Why")
    for entry in report:
        table.add_row(entry["name"], RISK_STYLE[entry["risk"]], format_findings(entry["findings"]))

    console = Console()
    console.print(table)
    console.print(summary_line(report))
    if diff is not None:
        console.print(diff_line(diff, snapshot_path))


def print_audit_table(results):
    table = Table(title=f"MCP Audit — {len(results)} servers")
    table.add_column("Server", style="magenta", no_wrap=True)
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Risk")
    table.add_column("Why")
    for server in results:
        if server["status"] == "error":
            table.add_row(server["server"], "—", "[bold red]ERROR[/bold red]", server["error"])
        elif server["status"] == "skipped":
            table.add_row(server["server"], "—", "[dim]SKIPPED[/dim]", server["error"])
        elif not server["tools"]:
            table.add_row(server["server"], "—", "[dim]EMPTY[/dim]", "server exposes no tools")
        else:
            for i, entry in enumerate(server["tools"]):
                table.add_row(
                    server["server"] if i == 0 else "",
                    entry["name"],
                    RISK_STYLE[entry["risk"]],
                    format_findings(entry["findings"]),
                )
        table.add_section()

    console = Console()
    console.print(table)
    all_tools = [t for s in results for t in s["tools"]]
    errors = sum(1 for s in results if s["status"] == "error")
    skipped = sum(1 for s in results if s["status"] == "skipped")
    console.print(summary_line(all_tools) + f"  |  servers: {len(results)}, errors: {errors}, skipped: {skipped}")
    for server in results:
        if server.get("diff") is not None:
            console.print(f"[magenta]{server['server']}[/magenta] " + diff_line(server["diff"], server["snapshot"]))


def exit_code_for(tools, fail_on):
    worst = max((RISK_ORDER[t["risk"]] for t in tools), default=0)
    return 1 if worst >= RISK_ORDER[fail_on] and worst > 0 else 0


def validate_fail_on(fail_on):
    fail_on = fail_on.upper()
    if fail_on not in RISK_ORDER:
        raise typer.BadParameter(f"--fail-on must be one of {', '.join(RISK_ORDER)}")
    return fail_on


# --- Commands ---------------------------------------------------------------


@app.command()
def scan(
    server: str,
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON instead of a table."),
    fail_on: str = typer.Option(
        "DANGEROUS",
        "--fail-on",
        help="Exit non-zero if any tool is at or above this risk level (SAFE, WARNING, DANGEROUS).",
    ),
    snapshot: Optional[Path] = typer.Option(
        None,
        "--snapshot",
        help="Baseline file. Created on first run; later runs flag tools whose description or schema changed.",
    ),
    update_snapshot: bool = typer.Option(
        False,
        "--update-snapshot",
        help="After reporting, overwrite the baseline with what the server serves now.",
    ),
    timeout: float = typer.Option(DEFAULT_TIMEOUT, "--timeout", help="Seconds to wait for the server to list tools."),
):
    """Launch an MCP server over stdio and check every tool for poisoning.

    SERVER is the full command line that starts the server, quoted as one
    argument, e.g. "npx -y @modelcontextprotocol/server-filesystem /tmp".
    """
    fail_on = validate_fail_on(fail_on)
    if update_snapshot and snapshot is None:
        raise typer.BadParameter("--update-snapshot requires --snapshot")

    command, args = parse_command(server)
    try:
        report = asyncio.run(collect_tools(command, args, timeout=timeout))
    except Exception as exc:  # noqa: BLE001 - any launch failure is reported the same way
        err.print(f"[bold red]Could not scan server:[/bold red] {describe_error(exc)}")
        raise typer.Exit(code=2)

    diff = None
    if snapshot is not None:
        diff = apply_snapshot(report, server, snapshot, update_snapshot)

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print_table(report, diff, snapshot)

    sys.exit(exit_code_for(report, fail_on))


@app.command()
def audit(
    config: Optional[List[Path]] = typer.Argument(
        None,
        help="MCP config file(s). Omit to scan every known Claude Desktop / Claude Code / Cursor / VS Code config.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON instead of a table."),
    fail_on: str = typer.Option(
        "DANGEROUS",
        "--fail-on",
        help="Exit non-zero if any tool is at or above this risk level (SAFE, WARNING, DANGEROUS).",
    ),
    snapshot_dir: Optional[Path] = typer.Option(
        None,
        "--snapshot-dir",
        help="Directory of per-server baselines (<server>.json). Created on first run; later runs flag changes.",
    ),
    update_snapshot: bool = typer.Option(
        False,
        "--update-snapshot",
        help="After reporting, overwrite each baseline with what the server serves now.",
    ),
    timeout: float = typer.Option(DEFAULT_TIMEOUT, "--timeout", help="Seconds to wait for each server to list tools."),
):
    """Scan every server defined in one or more MCP client config files.

    Servers that fail to start or time out are reported as ERROR and do not
    stop the audit. Remote (http/sse) servers are reported as SKIPPED.
    """
    fail_on = validate_fail_on(fail_on)
    if update_snapshot and snapshot_dir is None:
        raise typer.BadParameter("--update-snapshot requires --snapshot-dir")

    paths = list(config) if config else discover_configs()
    if not paths:
        err.print("[bold red]No MCP config files found.[/bold red] Pass a path explicitly.")
        raise typer.Exit(code=2)
    if snapshot_dir is not None:
        snapshot_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for path in paths:
        try:
            specs = load_servers(path)
        except (OSError, ValueError) as exc:
            err.print(f"[bold red]Could not read {path}:[/bold red] {describe_error(exc)}")
            raise typer.Exit(code=2)
        err.print(f"[cyan]{path}[/cyan]: {len(specs)} server(s)")

        for spec in specs:
            entry = {
                "server": spec.name,
                "config": str(path),
                "transport": spec.transport,
                "status": "ok",
                "error": None,
                "tools": [],
            }
            results.append(entry)

            if spec.transport != "stdio":
                entry["status"] = "skipped"
                entry["error"] = f"{spec.transport} transport not supported yet"
                continue
            if not spec.command:
                entry["status"] = "error"
                entry["error"] = "no command in config"
                continue

            try:
                entry["tools"] = asyncio.run(collect_tools(spec.command, spec.args, spec.env, timeout=timeout))
            except Exception as exc:  # noqa: BLE001 - keep auditing the other servers
                entry["status"] = "error"
                entry["error"] = describe_error(exc)
                continue

            if snapshot_dir is not None:
                snap = snapshot_dir / snapshot_filename(spec.name)
                launch = " ".join(shlex.quote(p) for p in [spec.command, *spec.args])
                entry["snapshot"] = str(snap)
                entry["diff"] = apply_snapshot(entry["tools"], launch, snap, update_snapshot)

    if not results:
        err.print(f"[yellow]No MCP servers defined in {len(paths)} config file(s). Nothing to audit.[/yellow]")

    if json_output:
        print(json.dumps(results, indent=2))
    elif results:
        print_audit_table(results)

    all_tools = [t for s in results for t in s["tools"]]
    sys.exit(exit_code_for(all_tools, fail_on))


@app.command()
def version():
    """Print the installed version."""
    print(__version__)


if __name__ == "__main__":
    app()
