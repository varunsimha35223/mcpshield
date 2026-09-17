import asyncio
import json
import stat
import sys
import threading
import urllib.request
from pathlib import Path

import pytest
from mcp.client.auth import OAuthClientProvider
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from typer.testing import CliRunner

from mcpshield.cli import app, effective_timeout, open_transport, spec_from_target
from mcpshield.config import ServerSpec, load_servers
from mcpshield.oauth import (
    FLOW_TIMEOUT,
    CallbackFlow,
    FileTokenStorage,
    OAuthCallbackError,
    build_provider,
    list_stored,
    server_key,
)
from conftest import plain

FIXTURES = Path(__file__).resolve().parent / "fixtures"
runner = CliRunner()


def free_port():
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- storage ----------------------------------------------------------------


def test_storage_round_trip(tmp_path):
    st = FileTokenStorage("https://mcp.example.com/mcp", tmp_path)
    assert asyncio.run(st.get_tokens()) is None
    assert asyncio.run(st.get_client_info()) is None

    asyncio.run(st.set_tokens(OAuthToken(access_token="abc", token_type="Bearer", refresh_token="r")))
    asyncio.run(st.set_client_info(OAuthClientInformationFull(client_id="cid", redirect_uris=["http://127.0.0.1:7867/callback"])))

    tokens = asyncio.run(st.get_tokens())
    assert tokens.access_token == "abc" and tokens.refresh_token == "r"
    assert asyncio.run(st.get_client_info()).client_id == "cid"
    data = json.loads(st.path.read_text())
    assert data["server_url"] == "https://mcp.example.com/mcp"


def test_storage_file_is_private(tmp_path):
    st = FileTokenStorage("https://a.example/mcp", tmp_path / "tokens")
    asyncio.run(st.set_tokens(OAuthToken(access_token="x", token_type="Bearer")))
    assert stat.S_IMODE(st.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(st.path.parent.stat().st_mode) == 0o700


def test_storage_is_per_server(tmp_path):
    a = FileTokenStorage("https://a.example/mcp", tmp_path)
    b = FileTokenStorage("https://b.example/mcp", tmp_path)
    assert a.path != b.path
    asyncio.run(a.set_tokens(OAuthToken(access_token="a", token_type="Bearer")))
    assert asyncio.run(b.get_tokens()) is None
    assert server_key("https://a.example/mcp") == server_key("  https://a.example/mcp \n")


def test_storage_clear_and_list(tmp_path):
    a = FileTokenStorage("https://a.example/mcp", tmp_path)
    b = FileTokenStorage("https://b.example/mcp", tmp_path)
    asyncio.run(a.set_tokens(OAuthToken(access_token="a", token_type="Bearer")))
    asyncio.run(b.set_client_info(OAuthClientInformationFull(client_id="c", redirect_uris=["http://127.0.0.1:1/callback"])))
    listed = {url: has for url, _p, has in list_stored(tmp_path)}
    assert listed == {"https://a.example/mcp": True, "https://b.example/mcp": False}
    assert a.clear() is True and a.clear() is False
    assert [u for u, _p, _h in list_stored(tmp_path)] == ["https://b.example/mcp"]
    assert list_stored(tmp_path / "missing") == []


# --- callback flow ----------------------------------------------------------


def hit(url):
    """GET a URL from a thread so the asyncio listener can serve it."""
    out = {}

    def go():
        with urllib.request.urlopen(url, timeout=5) as r:
            out["body"] = r.read().decode()

    t = threading.Thread(target=go)
    t.start()
    return t, out


def test_callback_flow_receives_code():
    port = free_port()
    seen = []
    flow = CallbackFlow(port=port, timeout=5, open_browser=False, notify=seen.append)

    async def run():
        await flow.redirect("https://auth.example/authorize?x=1")
        t, out = hit(f"http://127.0.0.1:{port}/callback?code=CODE123&state=st&iss=https%3A%2F%2Fauth.example")
        result = await flow.callback()
        t.join(5)
        return result, out

    result, out = asyncio.run(run())
    assert result.code == "CODE123" and result.state == "st" and result.iss == "https://auth.example"
    assert "close this window" in out["body"]
    assert seen and "https://auth.example/authorize?x=1" in seen[0]
    assert flow.redirect_uri == f"http://127.0.0.1:{port}/callback"


def test_callback_flow_reports_authorization_error():
    port = free_port()
    flow = CallbackFlow(port=port, timeout=5, open_browser=False, notify=lambda _m: None)

    async def run():
        await flow.redirect("https://auth.example/authorize")
        t, _ = hit(f"http://127.0.0.1:{port}/callback?error=access_denied&error_description=nope")
        try:
            await flow.callback()
        finally:
            t.join(5)

    with pytest.raises(OAuthCallbackError) as exc:
        asyncio.run(run())
    assert "access_denied" in str(exc.value) and "nope" in str(exc.value)


def test_callback_flow_times_out():
    flow = CallbackFlow(port=free_port(), timeout=0.3, open_browser=False, notify=lambda _m: None)

    async def run():
        await flow.redirect("https://auth.example/authorize")
        await flow.callback()

    with pytest.raises(OAuthCallbackError) as exc:
        asyncio.run(run())
    assert "within 0s" in str(exc.value) or "within" in str(exc.value)


def test_callback_flow_opens_browser(monkeypatch):
    opened = []
    monkeypatch.setattr("mcpshield.oauth.webbrowser.open", lambda url: opened.append(url) or True)
    flow = CallbackFlow(port=free_port(), timeout=1, open_browser=True, notify=lambda _m: None)

    async def run():
        await flow.redirect("https://auth.example/authorize")
        await flow.stop()

    asyncio.run(run())
    assert opened == ["https://auth.example/authorize"]


# --- provider wiring --------------------------------------------------------


def test_build_provider(tmp_path):
    provider = build_provider("https://mcp.example.com/mcp", port=7001, storage=FileTokenStorage("https://mcp.example.com/mcp", tmp_path), open_browser=False)
    assert isinstance(provider, OAuthClientProvider)
    meta = provider.context.client_metadata
    assert [str(u) for u in meta.redirect_uris] == ["http://127.0.0.1:7001/callback"]
    assert meta.client_name.startswith("mcpshield")
    assert meta.token_endpoint_auth_method == "none"


def test_open_transport_passes_provider_for_http(monkeypatch):
    seen = {}

    def fake_create(headers=None, timeout=None, auth=None):
        seen["auth"] = auth
        seen["headers"] = headers

        class C:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        return C()

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def fake_streamable(url, http_client=None, **kw):
        yield ("r", "w", None)

    monkeypatch.setattr("mcpshield.cli.create_mcp_http_client", fake_create)
    monkeypatch.setattr("mcpshield.cli.streamable_http_client", fake_streamable)

    async def go(spec):
        async with open_transport(spec) as streams:
            return streams

    no_oauth = ServerSpec(name="t", transport="http", url="https://x.example/mcp")
    asyncio.run(go(no_oauth))
    assert seen["auth"] is None

    with_oauth = ServerSpec(name="t", transport="http", url="https://x.example/mcp", oauth=True, oauth_port=7002)
    asyncio.run(go(with_oauth))
    assert isinstance(seen["auth"], OAuthClientProvider)
    assert [str(u) for u in seen["auth"].context.client_metadata.redirect_uris] == ["http://127.0.0.1:7002/callback"]


def test_open_transport_passes_provider_for_sse(monkeypatch):
    seen = {}
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def fake_sse(url, headers=None, auth=None, **kw):
        seen["auth"] = auth
        yield ("r", "w")

    monkeypatch.setattr("mcpshield.cli.sse_client", fake_sse)

    async def go(spec):
        async with open_transport(spec) as streams:
            return streams

    asyncio.run(go(ServerSpec(name="t", transport="sse", url="https://x.example/sse", oauth=True)))
    assert isinstance(seen["auth"], OAuthClientProvider)


def test_effective_timeout_is_raised_for_oauth():
    spec = ServerSpec(name="t", transport="http", url="https://x.example/mcp", oauth=True)
    assert effective_timeout(spec, 30) >= FLOW_TIMEOUT
    assert effective_timeout(spec, 10_000) == 10_000
    spec.oauth = False
    assert effective_timeout(spec, 30) == 30


# --- config -----------------------------------------------------------------


def test_config_oauth_flag(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "a": {"type": "http", "url": "https://a.example/mcp", "oauth": True},
        "b": {"type": "http", "url": "https://b.example/mcp"},
    }}))
    specs = {s.name: s for s in load_servers(cfg)}
    assert specs["a"].oauth is True and specs["b"].oauth is False


# --- CLI --------------------------------------------------------------------


def test_scan_oauth_rejects_stdio_target():
    result = runner.invoke(app, ["scan", "python s.py", "--oauth"])
    assert result.exit_code == 2
    assert "URL targets" in plain(result.output)


def test_scan_oauth_marks_spec_and_extends_timeout(monkeypatch):
    seen = {}

    async def fake_collect(spec, timeout=None, policy=None, read_resources=False):
        seen["spec"] = spec
        seen["timeout"] = timeout
        return []

    monkeypatch.setattr("mcpshield.cli.collect_tools", fake_collect)
    result = runner.invoke(app, ["scan", "https://x.example/mcp", "--oauth", "--oauth-port", "7010", "--json"])
    assert result.exit_code == 0, result.output
    assert seen["spec"].oauth is True and seen["spec"].oauth_port == 7010
    assert seen["timeout"] >= FLOW_TIMEOUT


def test_audit_oauth_applies_to_remote_only(monkeypatch, tmp_path):
    seen = []

    async def fake_collect(spec, timeout=None, policy=None, read_resources=False):
        seen.append((spec.name, spec.oauth, timeout))
        return []

    monkeypatch.setattr("mcpshield.cli.collect_tools", fake_collect)
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "local": {"command": sys.executable, "args": ["x"]},
        "remote": {"type": "http", "url": "https://r.example/mcp"},
        "flagged": {"type": "http", "url": "https://f.example/mcp", "oauth": True},
    }}))
    runner.invoke(app, ["audit", str(cfg), "--json"])
    assert seen == [("local", False, 30.0), ("remote", False, 30.0), ("flagged", True, max(30.0, FLOW_TIMEOUT + 30))]
    seen.clear()
    runner.invoke(app, ["audit", str(cfg), "--json", "--oauth"])
    assert [(n, o) for n, o, _t in seen] == [("local", False), ("remote", True), ("flagged", True)]


def test_tokens_command(tmp_path, monkeypatch):
    monkeypatch.setattr("mcpshield.oauth.DEFAULT_TOKEN_DIR", tmp_path)
    result = runner.invoke(app, ["tokens"])
    assert result.exit_code == 0 and "No stored OAuth tokens" in plain(result.stdout)

    asyncio.run(FileTokenStorage("https://a.example/mcp").set_tokens(OAuthToken(access_token="x", token_type="Bearer")))
    asyncio.run(FileTokenStorage("https://b.example/mcp").set_client_info(
        OAuthClientInformationFull(client_id="c", redirect_uris=["http://127.0.0.1:1/callback"])))
    result = runner.invoke(app, ["tokens"])
    assert "token " in plain(result.stdout) and "https://a.example/mcp" in plain(result.stdout)
    assert "registration only" in plain(result.stdout) and "https://b.example/mcp" in plain(result.stdout)

    result = runner.invoke(app, ["tokens", "--clear", "https://a.example/mcp"])
    assert result.exit_code == 0 and "Cleared tokens" in plain(result.stderr)
    result = runner.invoke(app, ["tokens", "--clear", "https://a.example/mcp"])
    assert result.exit_code == 1 and "No stored tokens" in plain(result.stderr)

    result = runner.invoke(app, ["tokens", "--clear-all"])
    assert result.exit_code == 0 and "Cleared 1 server" in plain(result.stderr)
    assert list_stored(tmp_path) == []
