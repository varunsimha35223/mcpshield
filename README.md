# MCPShield

Static scanner for [Model Context Protocol](https://modelcontextprotocol.io) servers.
It connects to a server over stdio, lists its tools, and checks every tool and
parameter description for signs of **tool poisoning**: hidden instructions,
exfiltration prompts, cross-tool hijacking, credential references, and invisible
Unicode.

## Usage

```bash
uv run python scanner.py "npx -y @modelcontextprotocol/server-filesystem /tmp"
uv run python scanner.py "uv run python evil_server.py" --json
uv run python scanner.py "..." --fail-on warning   # stricter CI gate
```

The exit code is `1` when any tool reaches the `--fail-on` level
(default `DANGEROUS`), so the scan can block a pipeline.

### Rug-pull detection

A server can serve clean descriptions at install time and swap them later.
Static rules cannot see that, so record a baseline and diff against it:

```bash
uv run python scanner.py "..." --snapshot baseline.json   # first run writes the file
uv run python scanner.py "..." --snapshot baseline.json   # later runs diff against it
uv run python scanner.py "..." --snapshot baseline.json --update-snapshot  # accept changes
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

`evil_server.py` is a deliberately poisoned server used as the test fixture.
Never connect a real agent to it.
