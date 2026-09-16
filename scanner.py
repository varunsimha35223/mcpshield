import asyncio
import json
import shlex
import sys
import typer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.table import Table

from detector import assess_tool

app = typer.Typer()

RISK_STYLE = {
    "SAFE": "[green]SAFE[/green]",
    "WARNING": "[yellow]WARNING[/yellow]",
    "DANGEROUS": "[bold red]DANGEROUS[/bold red]",
}

# Higher number = worse. Used for the --fail-on threshold and the summary.
RISK_ORDER = {"SAFE": 0, "WARNING": 1, "DANGEROUS": 2}


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
            "findings": findings,
            "inputs": list(tool.input_schema.get("properties", {}).keys()),
        })
    return report


def print_table(report):
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


@app.command()
def scan(
    server: str,
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON instead of a table."),
    fail_on: str = typer.Option(
        "DANGEROUS",
        "--fail-on",
        help="Exit non-zero if any tool is at or above this risk level (SAFE, WARNING, DANGEROUS).",
    ),
):
    fail_on = fail_on.upper()
    if fail_on not in RISK_ORDER:
        raise typer.BadParameter(f"--fail-on must be one of {', '.join(RISK_ORDER)}")

    report = asyncio.run(collect_tools(server))

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print_table(report)

    worst = max((RISK_ORDER[e["risk"]] for e in report), default=0)
    if worst >= RISK_ORDER[fail_on] and worst > 0:
        sys.exit(1)


if __name__ == "__main__":
    app()
