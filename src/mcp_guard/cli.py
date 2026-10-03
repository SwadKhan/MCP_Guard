"""Typer command-line entry point."""

import typer

from mcp_guard import __version__

app = typer.Typer(
    help="Static security scanner for MCP server source and tool manifests.",
    invoke_without_command=True,
)


@app.callback()
def main(version: bool = typer.Option(False, "--version", help="Show the installed version.")) -> None:
    """Inspect Python/TypeScript MCP servers and tools/list JSON manifests."""
    if version:
        typer.echo(f"mcp-guard {__version__}")
        raise typer.Exit()
