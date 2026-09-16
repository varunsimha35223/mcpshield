"""Scan the poisoned fixture over streamable HTTP and SSE."""

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpshield.cli import app, open_transport, parse_header, spec_from_target
from mcpshield.config import ServerSpec

FIXTURES = Path(__file__).resolve().parent / "fixtures"
runner = CliRunner()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(port, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"fixture server on port {port} never came up")


@pytest.fixture(scope="module", params=["streamable-http", "sse"])
def remote(request):
    """Yields (transport, url) for a running poisoned server."""
    transport = request.param
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, str(FIXTURES / "http_server.py"), transport, str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_port(port)
        path = "/mcp" if transport == "streamable-http" else "/sse"
        yield ("http" if transport == "streamable-http" else "sse"), f"http://127.0.0.1:{port}{path}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def scan_args(remote):
    transport, url = remote
    return [url] if transport == "http" else [url, "--transport", "sse"]


def test_scan_url(remote):
    result = runner.invoke(app, ["scan", *scan_args(remote), "--json"])
    assert result.exit_code == 1, result.output
    data = {t["name"]: t for t in json.loads(result.stdout) if t["kind"] == "tool"}
    assert set(data) == {"add_numbers", "get_weather", "read_notes", "format_text", "lookup_zip"}
    assert sum(t["kind"] == "prompt" for t in json.loads(result.stdout)) == 3
    assert data["get_weather"]["risk"] == "DANGEROUS"
    assert data["add_numbers"]["risk"] == "SAFE"


def test_scan_url_table_and_snapshot(remote, tmp_path):
    snap = tmp_path / "snap.json"
    result = runner.invoke(app, ["scan", *scan_args(remote), "--snapshot", str(snap)])
    assert result.exit_code == 1
    assert "DANGEROUS 8" in result.stdout
    saved = json.loads(snap.read_text())
    assert saved["server"].startswith(remote[0] + " http://")


def test_audit_remote_entry(remote, tmp_path):
    transport, url = remote
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"mcpServers": {"remote": {"type": transport, "url": url}}}))
    result = runner.invoke(app, ["audit", str(cfg), "--json"])
    assert result.exit_code == 1, result.output
    (server,) = json.loads(result.stdout)
    assert server["status"] == "ok"
    assert server["transport"] == transport
    assert len(server["tools"]) == 11


def test_audit_streamable_http_alias(remote, tmp_path):
    transport, url = remote
    if transport != "http":
        pytest.skip("alias only applies to streamable HTTP")
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"mcpServers": {"r": {"type": "streamable-http", "url": url}}}))
    result = runner.invoke(app, ["audit", str(cfg), "--json"])
    (server,) = json.loads(result.stdout)
    assert server["status"] == "ok" and server["transport"] == "http"


def test_wrong_transport_for_endpoint_is_an_error_not_a_hang(remote):
    transport, url = remote
    other = "sse" if transport == "http" else "http"
    result = runner.invoke(app, ["scan", url, "--transport", other, "--timeout", "10"])
    assert result.exit_code == 2
    assert "Could not scan server" in result.stderr


# --- No server listening ----------------------------------------------------


def test_scan_connection_refused_exits_2():
    url = f"http://127.0.0.1:{free_port()}/mcp"
    result = runner.invoke(app, ["scan", url, "--timeout", "10"])
    assert result.exit_code == 2
    assert "Could not scan server" in result.stderr


def test_audit_connection_refused_is_per_server_error(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "dead": {"type": "http", "url": f"http://127.0.0.1:{free_port()}/mcp"},
        "clean": {"command": sys.executable, "args": [str(FIXTURES / "clean_server.py")]},
    }}))
    result = runner.invoke(app, ["audit", str(cfg), "--json", "--timeout", "10"])
    assert result.exit_code == 0, result.output
    data = {s["server"]: s for s in json.loads(result.stdout)}
    assert data["dead"]["status"] == "error"
    assert data["clean"]["status"] == "ok"


# --- Target parsing and headers ---------------------------------------------


def test_spec_from_url_defaults_to_http():
    spec = spec_from_target("https://mcp.example.com/mcp")
    assert spec.transport == "http" and spec.url == "https://mcp.example.com/mcp" and spec.command is None


def test_spec_from_command_is_stdio():
    spec = spec_from_target("npx -y some-server /tmp")
    assert spec.transport == "stdio" and spec.command == "npx" and spec.args == ["-y", "some-server", "/tmp"]


def test_url_with_stdio_transport_is_rejected():
    result = runner.invoke(app, ["scan", "https://x.example", "--transport", "stdio"])
    assert result.exit_code == 2


def test_command_with_http_transport_is_rejected():
    result = runner.invoke(app, ["scan", "python s.py", "--transport", "http"])
    assert result.exit_code == 2


@pytest.mark.parametrize("text,expected", [
    ("Authorization: Bearer abc", ("Authorization", "Bearer abc")),
    ("X-Key:v", ("X-Key", "v")),
    ("Host: a:b:c", ("Host", "a:b:c")),
])
def test_parse_header(text, expected):
    assert parse_header(text) == expected


@pytest.mark.parametrize("text", ["nocolon", ": novalue"])
def test_parse_header_rejects_bad_input(text):
    result = runner.invoke(app, ["scan", "https://x.example", "-H", text])
    assert result.exit_code == 2
    assert "Name: value" in result.output


def test_http_headers_reach_the_client(monkeypatch):
    """The httpx client handed to the transport carries the configured headers."""
    import asyncio

    seen = {}

    def fake_streamable(url, http_client=None, **kw):
        seen["url"] = url
        seen["headers"] = dict(http_client.headers)

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def cm():
            yield ("r", "w", None)

        return cm()

    monkeypatch.setattr("mcpshield.cli.streamable_http_client", fake_streamable)
    spec = ServerSpec(name="t", transport="http", url="https://x.example/mcp", headers={"Authorization": "Bearer abc"})

    async def go():
        async with open_transport(spec) as streams:
            return streams

    assert asyncio.run(go()) == ("r", "w")
    assert seen["url"] == "https://x.example/mcp"
    assert seen["headers"]["authorization"] == "Bearer abc"
