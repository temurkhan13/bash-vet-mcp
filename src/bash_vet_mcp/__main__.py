"""Entry point: `python -m bash_vet_mcp` runs a stdio MCP server."""
from __future__ import annotations

import asyncio
import os
import sys

from mcp.server.stdio import stdio_server

from bash_vet_mcp import __version__
from bash_vet_mcp.server import build_server


def _emit_startup_banner() -> None:
    """Print a one-line value-prove banner to stderr at startup.

    Goes to stderr (stdout is reserved for MCP JSON-RPC protocol traffic).
    Suppressible via `BASH_VET_QUIET=1` env var for users who pipe stderr to
    a log file and want it terse.
    """
    if os.environ.get("BASH_VET_QUIET", "").strip() in {"1", "true", "yes"}:
        return
    banner = (
        f"bash-vet-mcp v{__version__} ready · "
        f"vets LLM-emitted shell commands BEFORE execution · "
        f"26 rules across 8 families · sub-second, local, free"
    )
    print(banner, file=sys.stderr, flush=True)


def main() -> None:
    _emit_startup_banner()
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
