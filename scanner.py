import asyncio
import json
import shlex
import sys
from pathlib import Path
from typing import Optional

import typer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.table import Table

from detector import assess_tool
from snapshot import apply_diff, build_snapshot, diff_snapshot, fingerprint, load_snapshot, save_snapshot

app = typer.Typer()

RISK_STYLE = {
    "SAFE": "[green]SAFE[/green]",
    "WARNING": "[yellow]WARNING[/yellow]",
    "DANGEROUS": "[bold red]DANGEROUS[/bold red]",
}

# Higher number = worse. Used for the --fail-on threshold and the summary.
RISK_ORDER = {"SAFE": 0, "WARNING": 1, "DANGEROUS": 2}

# Status messages go to stderr so --json output on stdout stays parseable.
err = Console(stderr=True)


def format_findings(findings):
    if not findings:
        return "No problems found."
    lines = []
    for f in findings:
        where = "" if f["location"] == "description" else f" (in {f['location']})"
        lines.append(f"{f['rule']}: {f['evidence']}{where}")
    return "\n".join(lines)


async def collect_tools(server_command):
    parts = shlex.split(server_command)
    server = StdioServerParameters(command=parts[0], args=parts[1:])
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()

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


def print_table(report, diff=None, snapshot_path=None):
    table = Table(title=f"MCP Scan — {len(report)} tools found")
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Risk")
    table.add_column("Why")
    for entry in report:
        table.add_row(entry["name"], RISK_STYLE[entry["risk"]], format_findings(entry["findings"]))

    console = Console()
    console.print(table)

    counts = {level: sum(1 for e in report if e["risk"] == level) for level in RISK_ORDER}
    console.print(
        f"Summary: {RISK_STYLE['DANGEROUS']} {counts['DANGEROUS']}  "
        f"{RISK_STYLE['WARNING']} {counts['WARNING']}  "
        f"{RISK_STYLE['SAFE']} {counts['SAFE']}"
    )
    if diff is not None:
        console.print(
            f"Baseline {snapshot_path}: "
            f"[bold red]{len(diff['changed'])} changed[/bold red]  "
            f"[yellow]{len(diff['added'])} added[/yellow]  "
            f"[yellow]{len(diff['removed'])} removed[/yellow]  "
            f"{len(diff['unchanged'])} unchanged"
        )


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
):
    fail_on = fail_on.upper()
    if fail_on not in RISK_ORDER:
        raise typer.BadParameter(f"--fail-on must be one of {', '.join(RISK_ORDER)}")
    if update_snapshot and snapshot is None:
        raise typer.BadParameter("--update-snapshot requires --snapshot")

    report = asyncio.run(collect_tools(server))

    diff = None
    if snapshot is not None:
        diff = apply_snapshot(report, server, snapshot, update_snapshot)

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print_table(report, diff, snapshot)

    worst = max((RISK_ORDER[e["risk"]] for e in report), default=0)
    if worst >= RISK_ORDER[fail_on] and worst > 0:
        sys.exit(1)


if __name__ == "__main__":
    app()
