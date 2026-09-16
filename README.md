# MCPShield

Static scanner for [Model Context Protocol](https://modelcontextprotocol.io) servers.
It connects to a server over stdio, streamable HTTP, or SSE, lists its tools,
resources, and prompts, and checks every description (tool, parameter, resource,
resource URI, prompt, prompt argument) for signs of **tool poisoning**: hidden instructions,
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

A changed description or definition is a `DANGEROUS` `rug_pull` finding.
Items added since the baseline are `WARNING` `new_item`; items that vanished
appear as `WARNING` `removed_item` rows. Tools, resources, and prompts are
tracked separately, so a prompt and a tool with the same name never collide.
Commit the baseline next to your MCP config so CI catches a swap. Baselines
written by older versions (tools only) are read and upgraded automatically.

### Policy file

Silence a false positive, raise a severity, or add your own rules without
touching the scanner. Put a `.mcpshield.toml` in the working directory (or
your home directory), or pass `--policy PATH`:

```toml
[severity]
credential_reference = "DANGEROUS"   # raise
embedded_url = "IGNORE"              # drop a rule entirely
new_item = "IGNORE"                  # snapshot rules can be tuned too

[phrases]
hidden_instruction = ["you are now"] # extend a built-in rule
company_policy = ["contact hr"]      # or add one (WARNING unless [severity] says otherwise)

[patterns]
internal_host = ['(?i)\binternal\.corp\b']

[allow]
phrases = ["api key"]                # never flag these built-in phrases
items = ["tool:get_secret", "prompt:*"]   # kind:name globs; findings stay in the report, marked allowed
servers = ["trusted-*"]              # server-name globs (audit) or scan targets
```

`mcpshield policy --init` writes a commented template; `mcpshield policy`
shows what is in effect. Allowed findings stay visible in the output and in
JSON (`"allowed": true`) but no longer count toward the risk level or exit
code.

## Risk levels

| Level | Meaning |
|---|---|
| `DANGEROUS` | Hidden instructions, exfiltration, tool shadowing, invisible Unicode, or a description that changed since the baseline. Do not install. |
| `WARNING` | Credential references, URLs, base64-like blobs, dotfile paths, a missing description, or a tool added/removed since the baseline. Review by hand. |
| `SAFE` | No rule fired. Static checks only; this is not proof of safety. |

Resource *contents* are not fetched. The scanner looks at what a client shows
the model before anything is called: names, descriptions, URIs, and argument
descriptions. A resource that serves poisoned text when read is out of scope.

## Use in CI

Commit a baseline next to your MCP config and let the scan gate the pipeline:

```yaml
# .github/workflows/mcp-audit.yml
name: MCP audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv tool install git+https://github.com/<you>/mcpshield
      - run: mcpshield audit .mcp.json --snapshot-dir .mcpshield --fail-on warning
```

Exit code `1` means a finding crossed `--fail-on`; `2` means a config or
policy file could not be read. Unreachable servers are reported but do not
fail the job on their own.

## Development

```bash
uv sync
uv run pytest
```

The repository's own workflow in `.github/workflows/ci.yml` runs the suite on
Python 3.10 to 3.13, then audits a clean and a poisoned fixture config and
checks the exit codes, and finally proves a policy can silence the poisoned one.

Layout:

- `mcpshield/detector.py`: phrase, regex, and Unicode rules
- `mcpshield/snapshot.py`: baseline file format and diffing
- `mcpshield/cli.py`: the `mcpshield` command
- `tests/fixtures/evil_server.py`: deliberately poisoned server used as a test fixture. Never connect a real agent to it.
