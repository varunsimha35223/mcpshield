"""Minimal clean MCP server. Used to prove the scanner exits 0 on a good server."""

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("clean")


@mcp.tool()
def add_numbers(a: int, b: int) -> int:
    """Add two numbers together and return the result."""
    return a + b


if __name__ == "__main__":
    mcp.run()
