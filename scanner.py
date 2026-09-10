import asyncio
import json
import shlex
import typer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.table import Table

from detector import assess_description

app = typer.Typer()

async def run_scan(server_command, json_output):
    parts = shlex.split(server_command)
    server = StdioServerParameters(command=parts[0], args=parts[1:])
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()

            if json_output:
                data = []
                for tool in result.tools:
                    risk, reason = assess_description(tool.description)
                    data.append({
                        "name": tool.name,
                        "risk": risk,
                        "reason": reason,
                        "inputs": list(tool.input_schema.get("properties", {}).keys()),
                    })
                print(json.dumps(data, indent=2))
            else:
                table = Table(title=f"MCP Scan — {len(result.tools)} tools found")
                table.add_column("Tool", style="cyan", no_wrap=True)
                table.add_column("Risk")
                table.add_column("Why")
                for tool in result.tools:
                    risk, reason = assess_description(tool.description)
                    if risk == "SAFE":
                        risk_text = "[green]SAFE[/green]"
                    else:
                        risk_text = "[red]DANGEROUS[/red]"
                    table.add_row(tool.name, risk_text, reason)
                Console().print(table)

@app.command()
def scan(server: str, json_output: bool = typer.Option(False, "--json")):
    asyncio.run(run_scan(server, json_output))

if __name__ == "__main__":
    app()
