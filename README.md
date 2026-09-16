# MCPShield

Static scanner for [Model Context Protocol](https://modelcontextprotocol.io) servers.
It connects to a server over stdio, streamable HTTP, or SSE, lists its tools, and checks every tool and
parameter description for signs of **tool poisoning**: hidden instructions,
exfiltration prompts, cross-tool hijacking, credential references, and invisible
Unicode. A baseline snapshot catches **rug pulls**, where descriptions change
after install.

## Install

```bash
uv tool install git+https://github.com/<you>/mcpshield   # or: pipx install ...
mcpshield --help
```

From a checkout, `uv run mcpshield ...` works without installing.

## Usage

```bash
mcpshield scan "npx -y @modelcontextprotocol/server-filesystem /tmp"     # stdio
mcpshield scan https://mcp.example.com/mcp -H "Authorization: Bearer $TOKEN"  # streamable HTTP
mcpshield scan https://mcp.example.com/sse --transport sse                  # legacy SSE
mcpshield scan "uv run python tests/fixtures/evil_server.py" --json
mcpshield scan "..." --fail-on warning   # stricter CI gate
```

The exit code is `1` when any tool reaches the `--fail-on` level
(default `DANGEROUS`), so the scan can block a pipeline. Exit code `2` means
the server could not be scanned at all (bad command, crash, or `--timeout`).

### Audit every server you have configured

```bash
mcpshield audit                          # finds Claude Desktop, Claude Code, Cursor, VS Code configs
mcpshield audit ~/.claude.json .mcp.json # or name the files
mcpshield audit --json --snapshot-dir .mcpshield/   # per-server baselines for CI
```

`audit` reads `mcpServers` / `servers` blocks (and Claude Code's per-project
servers). stdio servers are launched with the `env` from the config; `http`
and `sse` servers are connected to with their `headers`. Everything lands in
one table. A server that fails to start, refuses the connection, or times out
shows as `ERROR` and does not stop the audit or change the exit code. Any
other transport type shows as `SKIPPED`.

### Rug-pull detection

A server can serve clean descriptions at install time and swap them later.
Static rules cannot see that, so record a baseline and diff against it:

```bash
mcpshield scan "..." --snapshot baseline.json                     # first run writes the file
mcpshield scan "..." --snapshot baseline.json                     # later runs diff against it
mcpshield scan "..." --snapshot baseline.json --update-snapshot   # accept changes
```

A changed description or input schema is a `DANGEROUS` `rug_pull` finding.
Tools added since the baseline are `WARNING` `new_tool`; tools that vanished
appear as `WARNING` `removed_tool` rows. Commit the baseline next to your MCP
config so CI catches a swap.

## Risk levels

| Level | Meaning |
|---|---|
| `DANGEROUS` | Hidden instructions, exfiltration, tool shadowing, invisible Unicode, or a description that changed since the baseline. Do not install. |
| `WARNING` | Credential references, URLs, base64-like blobs, dotfile paths, a missing description, or a tool added/removed since the baseline. Review by hand. |
| `SAFE` | No rule fired. Static checks only; this is not proof of safety. |

## Development

```bash
uv sync
uv run pytest
```

Layout:

- `mcpshield/detector.py`: phrase, regex, and Unicode rules
- `mcpshield/snapshot.py`: baseline file format and diffing
- `mcpshield/cli.py`: the `mcpshield` command
- `tests/fixtures/evil_server.py`: deliberately poisoned server used as a test fixture. Never connect a real agent to it.
