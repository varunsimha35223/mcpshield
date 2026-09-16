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

## Risk levels

| Level | Meaning |
|---|---|
| `DANGEROUS` | Hidden instructions, exfiltration, tool shadowing, or invisible Unicode. Do not install. |
| `WARNING` | Credential references, URLs, base64-like blobs, dotfile paths, or a missing description. Review by hand. |
| `SAFE` | No rule fired. Static checks only; this is not proof of safety. |

## Development

```bash
uv sync
uv run pytest
```

`evil_server.py` is a deliberately poisoned server used as the test fixture.
Never connect a real agent to it.
