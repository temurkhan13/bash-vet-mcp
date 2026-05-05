"""Entry point: `python -m bash_vet_mcp` runs a stdio MCP server."""
from __future__ import annotations

import asyncio

from mcp.server.stdio import stdio_server

from bash_vet_mcp.server import build_server


def main() -> None:
    asyncio.run(_run())


async def _run() -> None:
    server = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    main()
