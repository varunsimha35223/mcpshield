"""OAuth 2.1 for remote MCP servers.

Hosted servers often refuse a plain bearer header and require the MCP
authorization flow: dynamic client registration, PKCE, a browser round trip,
then a token. The SDK's OAuthClientProvider drives the protocol; this module
supplies the three pieces it leaves to the application:

- FileTokenStorage: tokens and client registration on disk, one file per
  server URL, mode 0600, under ~/.config/mcpshield/tokens/.
- CallbackFlow: opens the browser on the authorization URL and runs a
  one-shot HTTP listener on 127.0.0.1 to receive the authorization code.
- build_provider(): wires the above into an httpx2 Auth object.

The callback port is fixed by default because the redirect URI is part of the
client registration a server remembers; a new port would mean re-registering.
"""

import asyncio
import hashlib
import json
import os
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from mcp.client.auth import AuthorizationCodeResult, OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

from mcpshield import __version__

DEFAULT_TOKEN_DIR = Path.home() / ".config" / "mcpshield" / "tokens"
CALLBACK_HOST = "127.0.0.1"
DEFAULT_CALLBACK_PORT = 7867
CALLBACK_PATH = "/callback"
FLOW_TIMEOUT = 180.0  # seconds to wait for the user to finish in the browser


class OAuthCallbackError(RuntimeError):
    """The authorization server sent an error, or no callback arrived in time."""


def server_key(server_url):
    return hashlib.sha256(server_url.strip().encode("utf-8")).hexdigest()[:16]


class FileTokenStorage(TokenStorage):
    """JSON file per server: {"server_url", "tokens", "client_info"}."""

    def __init__(self, server_url, directory=None):
        self.server_url = server_url
        self.directory = Path(directory or DEFAULT_TOKEN_DIR)
        self.path = self.directory / f"{server_key(server_url)}.json"

    def _read(self):
        if not self.path.exists():
            return {"server_url": self.server_url}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data):
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        data["server_url"] = self.server_url
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    async def get_tokens(self):
        raw = self._read().get("tokens")
        return OAuthToken.model_validate(raw) if raw else None

    async def set_tokens(self, tokens):
        data = self._read()
        data["tokens"] = tokens.model_dump(mode="json", exclude_none=True)
        self._write(data)

    async def get_client_info(self):
        raw = self._read().get("client_info")
        return OAuthClientInformationFull.model_validate(raw) if raw else None

    async def set_client_info(self, client_info):
        data = self._read()
        data["client_info"] = client_info.model_dump(mode="json", exclude_none=True)
        self._write(data)

    def clear(self):
        if self.path.exists():
            self.path.unlink()
            return True
        return False


def list_stored(directory=None):
    """[(server_url, path, has_tokens)] for every stored server."""
    directory = Path(directory or DEFAULT_TOKEN_DIR)
    out = []
    if not directory.is_dir():
        return out
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.append((data.get("server_url", "?"), path, bool(data.get("tokens"))))
    return out


class CallbackFlow:
    """Browser redirect plus a one-shot local HTTP listener for the code."""

    def __init__(self, port=DEFAULT_CALLBACK_PORT, host=CALLBACK_HOST, timeout=FLOW_TIMEOUT, open_browser=True, notify=print):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.open_browser = open_browser
        self.notify = notify
        self._server = None
        self._result = None

    @property
    def redirect_uri(self):
        return f"http://{self.host}:{self.port}{CALLBACK_PATH}"

    async def _handle(self, reader, writer):
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=10)
            parts = request_line.decode("latin-1").split()
            target = parts[1] if len(parts) >= 2 else "/"
            # Drain headers so the browser gets a clean response.
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if line in (b"\r\n", b"\n", b""):
                    break
            query = parse_qs(urlsplit(target).query)
            if "error" in query:
                desc = query.get("error_description", [""])[0]
                body = f"Authorization failed: {query['error'][0]} {desc}".strip()
                self._result.set_exception(OAuthCallbackError(body))
            elif "code" in query:
                body = "Authorization complete. You can close this window and return to mcpshield."
                self._result.set_result(AuthorizationCodeResult(
                    code=query["code"][0],
                    state=query.get("state", [None])[0],
                    iss=query.get("iss", [None])[0],
                ))
            else:
                body = "Waiting for the authorization code..."
            payload = body.encode("utf-8")
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                + f"Content-Length: {len(payload)}\r\n".encode() + b"Connection: close\r\n\r\n" + payload
            )
            await writer.drain()
        finally:
            writer.close()

    async def start(self):
        if self._server is None:
            self._result = asyncio.get_running_loop().create_future()
            self._server = await asyncio.start_server(self._handle, self.host, self.port)

    async def stop(self):
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def redirect(self, authorization_url):
        """redirect_handler: listen first, then send the user to the browser."""
        await self.start()
        self.notify(f"Open this URL to authorize mcpshield:\n  {authorization_url}")
        if self.open_browser:
            try:
                webbrowser.open(authorization_url)
            except Exception:  # noqa: BLE001 - headless is fine; the URL was printed
                pass

    async def callback(self):
        """callback_handler: wait for the browser to hit the listener."""
        await self.start()
        try:
            return await asyncio.wait_for(asyncio.shield(self._result), timeout=self.timeout)
        except asyncio.TimeoutError as exc:
            raise OAuthCallbackError(f"no OAuth callback on {self.redirect_uri} within {int(self.timeout)}s") from exc
        finally:
            await self.stop()


def client_metadata(redirect_uri):
    return OAuthClientMetadata(
        client_name=f"mcpshield {__version__}",
        redirect_uris=[redirect_uri],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="none",
    )


def build_provider(server_url, port=DEFAULT_CALLBACK_PORT, storage=None, timeout=FLOW_TIMEOUT, open_browser=True, notify=print):
    """An httpx2 Auth that performs the MCP OAuth flow on demand."""
    flow = CallbackFlow(port=port, timeout=timeout, open_browser=open_browser, notify=notify)
    return OAuthClientProvider(
        server_url=server_url,
        client_metadata=client_metadata(flow.redirect_uri),
        storage=storage or FileTokenStorage(server_url),
        redirect_handler=flow.redirect,
        callback_handler=flow.callback,
    )
