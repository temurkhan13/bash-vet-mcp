"""`bash-vet-mcp-report` console script — vet commands and print markdown.

Reads commands from stdin (one per line) when stdin is piped. Falls back to
the bundled demo command set when run interactively (no stdin redirection).
Output is GitHub-flavored markdown on stdout, suitable for piping into a doc,
posting to Slack, opening a GitHub issue, etc.
"""
from __future__ import annotations

import sys

from bash_vet_mcp import __version__
from bash_vet_mcp.demo import DEMO_COMMANDS
from bash_vet_mcp.render import render_vet_results
from bash_vet_mcp.scanner import vet_command


def _read_commands() -> list[str]:
    """Return commands from stdin if piped, else the demo set."""
    # If stdin is a TTY, no input is coming → use the demo set
    if sys.stdin.isatty():
        return [cmd for (_label, cmd, _why) in DEMO_COMMANDS]

    # Stdin is piped — read one command per non-empty line
    commands: list[str] = []
    for line in sys.stdin:
        line = line.strip()
        if line and not line.startswith("#"):
            commands.append(line)
    if not commands:
        return [cmd for (_label, cmd, _why) in DEMO_COMMANDS]
    return commands


def main() -> None:
    # Force UTF-8 stdout (Windows cp1252 chokes on emoji + non-ASCII separators)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

    commands = _read_commands()
    results = [(cmd, vet_command(cmd)) for cmd in commands]
    md = render_vet_results(results=results, version=__version__)
    print(md, file=sys.stdout)


if __name__ == "__main__":
    main()
