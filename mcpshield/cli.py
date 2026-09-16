import asyncio
import json
import re
import shlex
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

import typer
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import get_default_environment, stdio_client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
from rich.console import Console
from rich.table import Table

from mcpshield import __version__
from mcpshield.config import REMOTE_TRANSPORTS, ServerSpec, discover_configs, load_servers
from mcpshield.detector import assess_prompt, assess_resource, assess_tool
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


SUPPORTED_TRANSPORTS = {"stdio", *REMOTE_TRANSPORTS}


def parse_header(text):
    """'Name: value' -> ('Name', 'value')."""
    name, sep, value = text.partition(":")
    if not sep or not name.strip():
        raise typer.BadParameter(f"header must look like 'Name: value', got {text!r}")
    return name.strip(), value.strip()


def spec_from_target(target, transport=None, headers=None):
    """Build a ServerSpec from a scan target: a URL or a quoted command line."""
    headers = dict(headers or {})
    if re.match(r"^https?://", target, re.IGNORECASE):
        transport = transport or "http"
        if transport not in REMOTE_TRANSPORTS:
            raise typer.BadParameter(f"a URL target needs --transport http or sse, not {transport}")
        return ServerSpec(name=target, transport=transport, url=target, headers=headers)

    if transport not in (None, "stdio"):
        raise typer.BadParameter(f"--transport {transport} needs a URL target")
    parts = shlex.split(target)
    if not parts:
        raise typer.BadParameter("server command is empty")
    return ServerSpec(name=target, transport="stdio", command=parts[0], args=parts[1:])


def parse_command(server_command):
    """Split a quoted command line into (command, args). Kept for callers that only need that."""
    spec = spec_from_target(server_command)
    return spec.command, spec.args


def launch_string(spec):
    """Human-readable 'how this server was reached', stored in snapshots."""
    if spec.transport == "stdio":
        return " ".join(shlex.quote(p) for p in [spec.command, *spec.args])
    return f"{spec.transport} {spec.url}"


@asynccontextmanager
async def open_transport(spec):
    """Yield (read, write) streams for a ServerSpec over whichever transport it uses."""
    if spec.transport == "stdio":
        env = get_default_environment()
        env.update(spec.env)
        params = StdioServerParameters(command=spec.command, args=list(spec.args), env=env)
        async with stdio_client(params) as (read, write):
            yield read, write
    elif spec.transport == "http":
        client = create_mcp_http_client(headers=spec.headers or None)
        async with client:
            async with streamable_http_client(spec.url, http_client=client) as streams:
                yield streams[0], streams[1]
    elif spec.transport == "sse":
        async with sse_client(spec.url, headers=spec.headers or None) as (read, write):
            yield read, write
    else:
        raise ValueError(f"unsupported transport {spec.transport!r}")


async def collect_tools(spec, timeout=DEFAULT_TIMEOUT):
    """Connect to a server, list its tools, and assess each one."""
    if spec.transport not in SUPPORTED_TRANSPORTS:
        raise ValueError(f"unsupported transport {spec.transport!r}")
    if spec.transport == "stdio" and not spec.command:
        raise ValueError("no command in config")
    if spec.transport in REMOTE_TRANSPORTS and not spec.url:
        raise ValueError("no url in config")

    async def optional(coro):
        # Resources and prompts are optional server features. A server that
        # advertises one but fails the list call should not sink the scan.
        try:
            return await coro
        except Exception:  # noqa: BLE001
            return None

    async def inner():
        async with open_transport(spec) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                caps = init.capabilities
                tools = (await session.list_tools()).tools
                resources, templates, prompts = [], [], []
                if caps.resources:
                    r = await optional(session.list_resources())
                    resources = r.resources if r else []
                    t = await optional(session.list_resource_templates())
                    templates = (getattr(t, "resource_templates", None) or getattr(t, "resourceTemplates", [])) if t else []
                if caps.prompts:
                    p = await optional(session.list_prompts())
                    prompts = p.prompts if p else []
                return tools, resources, templates, prompts

    tools, resources, templates, prompts = await asyncio.wait_for(inner(), timeout=timeout)

    report = []
    for tool in tools:
        risk, findings = assess_tool(tool.description, tool.input_schema, name=tool.name)
        report.append({
            "kind": "tool",
            "name": tool.name,
            "risk": risk,
            "description": tool.description,
            "fingerprint": fingerprint(tool.description, tool.input_schema),
            "findings": findings,
            "inputs": list(tool.input_schema.get("properties", {}).keys()),
        })
    for kind, items in (("resource", resources), ("resource_template", templates)):
        for res in items:
            uri = str(getattr(res, "uri", None) or getattr(res, "uri_template", None) or getattr(res, "uriTemplate", ""))
            mime = getattr(res, "mime_type", None) or getattr(res, "mimeType", None)
            risk, findings = assess_resource(res.description, uri=uri, name=res.name)
            report.append({
                "kind": kind,
                "name": res.name,
                "risk": risk,
                "description": res.description,
                "uri": uri,
                "fingerprint": fingerprint(res.description, {"uri": uri, "mime_type": mime}),
                "findings": findings,
                "inputs": [],
            })
    for prompt in prompts:
        arguments = [
            {"name": a.name, "description": a.description, "required": bool(a.required)}
            for a in (prompt.arguments or [])
        ]
        risk, findings = assess_prompt(prompt.description, arguments, name=prompt.name)
        report.append({
            "kind": "prompt",
            "name": prompt.name,
            "risk": risk,
            "description": prompt.description,
            "fingerprint": fingerprint(prompt.description, arguments),
            "findings": findings,
            "inputs": [a["name"] for a in arguments],
        })
    return report


def describe_error(exc):
    """One-line, human-readable reason a server could not be scanned."""
    if isinstance(exc, asyncio.TimeoutError):
        return "timed out waiting for the server to answer initialize/list_tools"
    if isinstance(exc, ValueError):  # our own config-validation messages are already readable
        return str(exc)
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


KIND_LABEL = {"tool": "tool", "resource": "resource", "resource_template": "template", "prompt": "prompt"}


def scan_title(report, prefix="MCP Scan"):
    counts = {}
    for entry in report:
        counts[entry.get("kind", "tool")] = counts.get(entry.get("kind", "tool"), 0) + 1
    parts = [f"{counts.get('tool', 0)} tools"]
    if counts.get("resource") or counts.get("resource_template"):
        parts.append(f"{counts.get('resource', 0) + counts.get('resource_template', 0)} resources")
    if counts.get("prompt"):
        parts.append(f"{counts['prompt']} prompts")
    return f"{prefix} — {', '.join(parts)}"


def print_table(report, diff=None, snapshot_path=None):
    table = Table(title=scan_title(report))
    table.add_column("Kind", style="dim", no_wrap=True)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Risk")
    table.add_column("Why")
    for entry in report:
        table.add_row(
            KIND_LABEL.get(entry.get("kind", "tool"), entry.get("kind")),
            entry["name"],
            RISK_STYLE[entry["risk"]],
            format_findings(entry["findings"]),
        )

    console = Console()
    console.print(table)
    console.print(summary_line(report))
    if diff is not None:
        console.print(diff_line(diff, snapshot_path))


def print_audit_table(results):
    table = Table(title=f"MCP Audit — {len(results)} servers")
    table.add_column("Server", style="magenta", no_wrap=True)
    table.add_column("Kind", style="dim", no_wrap=True)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Risk")
    table.add_column("Why")
    for server in results:
        if server["status"] == "error":
            table.add_row(server["server"], "", "—", "[bold red]ERROR[/bold red]", server["error"])
        elif server["status"] == "skipped":
            table.add_row(server["server"], "", "—", "[dim]SKIPPED[/dim]", server["error"])
        elif not server["tools"]:
            table.add_row(server["server"], "", "—", "[dim]EMPTY[/dim]", "server exposes no tools, resources or prompts")
        else:
            for i, entry in enumerate(server["tools"]):
                table.add_row(
                    server["server"] if i == 0 else "",
                    KIND_LABEL.get(entry.get("kind", "tool"), entry.get("kind")),
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
    transport: Optional[str] = typer.Option(
        None,
        "--transport",
        help="Force a transport for a URL target: http (streamable HTTP, the default) or sse.",
    ),
    header: List[str] = typer.Option(
        [],
        "--header",
        "-H",
        help="Extra HTTP header for URL targets, as 'Name: value'. Repeatable.",
    ),
):
    """Connect to an MCP server and check every tool for poisoning.

    SERVER is either a URL (http:// or https://, streamable HTTP by default,
    --transport sse for legacy SSE) or the full command line that starts a
    stdio server, quoted as one argument, e.g.
    "npx -y @modelcontextprotocol/server-filesystem /tmp".
    """
    fail_on = validate_fail_on(fail_on)
    if update_snapshot and snapshot is None:
        raise typer.BadParameter("--update-snapshot requires --snapshot")

    spec = spec_from_target(server, transport.lower() if transport else None, dict(parse_header(h) for h in header))
    try:
        report = asyncio.run(collect_tools(spec, timeout=timeout))
    except Exception as exc:  # noqa: BLE001 - any launch failure is reported the same way
        err.print(f"[bold red]Could not scan server:[/bold red] {describe_error(exc)}")
        raise typer.Exit(code=2)

    diff = None
    if snapshot is not None:
        diff = apply_snapshot(report, launch_string(spec), snapshot, update_snapshot)

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

    stdio, http and sse servers are all scanned. Servers that fail to start,
    refuse the connection, or time out are reported as ERROR and do not stop
    the audit. Servers with an unknown transport type are reported as SKIPPED.
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

            if spec.transport not in SUPPORTED_TRANSPORTS:
                entry["status"] = "skipped"
                entry["error"] = f"{spec.transport} transport not supported"
                continue

            try:
                entry["tools"] = asyncio.run(collect_tools(spec, timeout=timeout))
            except Exception as exc:  # noqa: BLE001 - keep auditing the other servers
                entry["status"] = "error"
                entry["error"] = describe_error(exc)
                continue

            if snapshot_dir is not None:
                snap = snapshot_dir / snapshot_filename(spec.name)
                entry["snapshot"] = str(snap)
                entry["diff"] = apply_snapshot(entry["tools"], launch_string(spec), snap, update_snapshot)

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
