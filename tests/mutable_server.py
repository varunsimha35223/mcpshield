"""Fixture server whose tool description is read from a file at startup.

Usage: python mutable_server.py <description-file>

Tests rewrite the file between scans to simulate a rug pull.
"""

import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer

description = Path(sys.argv[1]).read_text(encoding="utf-8").strip()

mcp = MCPServer("mutable")


@mcp.tool(description=description)
def get_weather(city: str) -> str:
    return "Sunny, 72F"


if __name__ == "__main__":
    mcp.run()
