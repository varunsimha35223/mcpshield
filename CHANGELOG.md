# Changelog

All notable changes to MCPShield. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.2.0 - 2026-09-16

First tagged release. Everything below was built in numbered phases on a
single branch; 0.1.0 was the unreleased scaffold.

### Scanning

- Connects to MCP servers over stdio, streamable HTTP, and SSE. URL targets
  take `--transport sse` and repeatable `-H "Name: value"` headers.
- Lists tools, resources, resource templates, and prompts, and checks every
  description the model sees: tool and parameter descriptions, resource
  descriptions and URIs, prompt and argument descriptions, and item names.
- Rules: hidden instructions, exfiltration phrases, tool shadowing,
  credential references, embedded URLs, base64-like payloads, dotfile paths,
  missing descriptions, and invisible Unicode (zero-width, bidi controls,
  invisible operators, and U+E0000 tag characters used for ASCII smuggling).
- Three risk levels: `DANGEROUS`, `WARNING`, `SAFE`. `--fail-on` picks the
  level that makes the exit code 1; exit code 2 means the server or a file
  could not be read.
- `--read-resources` fetches concrete resources and scans their text
  (first 64 KB; binary parts skipped; unreadable resources noted, not
  flagged). Off by default.
- `--timeout` bounds the handshake; unreachable servers are reported with a
  one-line reason.

### Rug-pull detection

- `--snapshot FILE` records a fingerprint of every item and diffs later
  runs: changed items are `DANGEROUS` `rug_pull`, added are `WARNING`
  `new_item`, removed appear as `WARNING` `removed_item` rows.
  `--update-snapshot` accepts the current state.
- Snapshot format version 2 keys items by kind and name; version 1 files
  upgrade in memory.

### Auditing configs

- `mcpshield audit [CONFIG...]` reads Claude Desktop, Claude Code (user and
  project scope, including per-project servers), Cursor, and VS Code config
  files, and scans every server they define in one table. With no argument
  it discovers the well-known config locations for the platform.
- stdio servers launch with the config's `env`; remote servers connect with
  its `headers`. Unknown transport types are `SKIPPED`; failures are
  per-server `ERROR` rows that do not stop the audit.
- `--snapshot-dir` keeps one baseline per server.

### Policy

- `.mcpshield.toml` (working directory, home directory, or `--policy`)
  overrides severities (including `IGNORE`), adds phrases and regexes, and
  allow-lists built-in phrases, items by `kind:name` glob, or whole servers.
  Allowed findings stay in the output but do not affect risk or exit code.
- `mcpshield policy` shows the effective policy; `--init` writes a template.

### Output

- Rich tables by default; `--json` for machine use; `--sarif` for GitHub
  code scanning, with physical locations on the config file for audits and
  suppressions for policy-allowed findings. `--output` writes either to a
  file.

### Authentication

- `--oauth` runs the MCP authorization flow for remote servers (dynamic
  registration, PKCE, browser redirect to a local listener). Tokens are
  cached per server under `~/.config/mcpshield/tokens/`. `mcpshield tokens`
  lists and clears them. Config entries can opt in with `"oauth": true`.

### Project

- Installable package with a `mcpshield` console script (`uv tool install`).
- GitHub Actions workflow: pytest on Python 3.10 to 3.13 plus macOS, then a
  dogfood job that audits clean and poisoned fixture configs and checks the
  exit codes.
- MIT license.

## 0.1.0 - 2026-09-09

Unreleased scaffold: a stdio-only scanner with a flat list of suspicious
phrases and a zero-width character check.
