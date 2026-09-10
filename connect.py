import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.table import Table

server = StdioServerParameters(
    command="npx",
    args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
)

async def main():
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()

            table = Table(title=f"MCP Scan — {len(result.tools)} tools found")
            table.add_column("Tool", style="cyan", no_wrap=True)
            table.add_column("Description")
            table.add_column("Inputs", style="yellow")

            for tool in result.tools:
                inputs = tool.input_schema.get("properties", {})
                input_names = ", ".join(inputs.keys())
                table.add_row(tool.name, tool.description, input_names)

            Console().print(table)

asyncio.run(main())
