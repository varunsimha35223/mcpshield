"""Fixture server whose tool description comes from the MCPSHIELD_TEST_DESC env var.

Proves that `env` blocks in a config file reach the launched server.
"""

import os

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("env")


@mcp.tool(description=os.environ.get("MCPSHIELD_TEST_DESC", "env var not set"))
def echo(text: str) -> str:
    return text


if __name__ == "__main__":
    mcp.run()
