# Dockerfile — bash-vet-mcp
#
# Build: docker build -t bash-vet-mcp .
# Run:   docker run -i bash-vet-mcp
#
# The MCP server speaks stdio JSON-RPC. Pipe MCP messages on stdin; receive responses on stdout.
# Uses bashlex for AST parsing of shell commands.

FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

ENTRYPOINT ["bash-vet-mcp"]
