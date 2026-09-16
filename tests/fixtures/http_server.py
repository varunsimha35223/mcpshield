"""Serve the poisoned fixture tools over HTTP.

Usage: python http_server.py (streamable-http|sse) PORT

streamable-http listens at http://127.0.0.1:PORT/mcp, sse at /sse.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evil_server import mcp  # noqa: E402

if __name__ == "__main__":
    transport, port = sys.argv[1], int(sys.argv[2])
    mcp.run(transport, host="127.0.0.1", port=port)
