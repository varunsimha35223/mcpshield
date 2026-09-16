"""Read MCP server definitions out of client config files.

Supported shapes:

    Claude Desktop, Claude Code (.mcp.json / ~/.claude.json), Cursor:
        {"mcpServers": {"<name>": {"command": "...", "args": [...], "env": {...}}}}
    Claude Code user config also nests per-project servers:
        {"projects": {"<path>": {"mcpServers": {...}}}}
    VS Code (.vscode/mcp.json):
        {"servers": {"<name>": {"command": "...", "args": [...], "type": "stdio"}}}

Remote servers carry "url" and/or "type": "http" | "sse". They are returned
with that transport so the caller can report them as skipped.
"""

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

REMOTE_TRANSPORTS = {"http", "sse", "streamable-http", "streamable_http"}


@dataclass
class ServerSpec:
    name: str
    transport: str  # "stdio", "http", "sse", ...
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    source: str = ""  # config file this came from


def _spec_from_entry(name, entry, source):
    if not isinstance(entry, dict):
        return None
    transport = (entry.get("type") or "").lower()
    if not transport:
        transport = "http" if entry.get("url") else "stdio"
    return ServerSpec(
        name=name,
        transport=transport,
        command=entry.get("command"),
        args=[str(a) for a in entry.get("args", []) or []],
        env={str(k): str(v) for k, v in (entry.get("env") or {}).items()},
        url=entry.get("url"),
        source=source,
    )


def load_servers(path):
    """Return the ServerSpecs defined in one config file, in file order."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object at the top level")

    found: dict[str, ServerSpec] = {}

    def add(name, entry, scope=None):
        spec = _spec_from_entry(name, entry, str(path))
        if spec is None:
            return
        key = name
        if key in found and found[key] != spec:
            # Same name, different definition (e.g. two Claude Code projects).
            key = f"{name} [{scope or 'dup'}]"
        found[key] = spec
        spec.name = key

    for top_key in ("mcpServers", "servers"):
        for name, entry in (data.get(top_key) or {}).items():
            add(name, entry)

    for project, pdata in (data.get("projects") or {}).items():
        if isinstance(pdata, dict):
            for name, entry in (pdata.get("mcpServers") or {}).items():
                add(name, entry, scope=Path(project).name or project)

    return list(found.values())


def candidate_config_paths(home=None, cwd=None):
    """Every well-known MCP config location on this platform, existing or not."""
    home = Path(home or Path.home())
    cwd = Path(cwd or Path.cwd())

    if sys.platform == "darwin":
        desktop = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif sys.platform.startswith("win"):
        desktop = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming")) / "Claude" / "claude_desktop_config.json"
    else:
        desktop = home / ".config" / "Claude" / "claude_desktop_config.json"

    return [
        desktop,
        home / ".claude.json",  # Claude Code, user scope
        cwd / ".mcp.json",  # Claude Code, project scope
        home / ".cursor" / "mcp.json",
        cwd / ".cursor" / "mcp.json",
        cwd / ".vscode" / "mcp.json",
    ]


def discover_configs(home=None, cwd=None):
    """The subset of candidate_config_paths() that exist on disk."""
    return [p for p in candidate_config_paths(home, cwd) if p.is_file()]
