"""bash-vet-mcp — MCP server for vetting LLM-emitted shell commands before execution."""

__version__ = "1.0.0"

from bash_vet_mcp.server import build_server

__all__ = ["__version__", "build_server"]
