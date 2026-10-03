"""Compact colored terminal summary."""

import typer


def print_summary(report: dict[str, object]) -> None:
    """Write a colored summary to stderr so stdout can remain machine-readable JSON."""
    summary = report["summary"]
    assert isinstance(summary, dict)
    total = summary["findings"]
    counts = summary["by_severity"]
    assert isinstance(counts, dict)
    if total:
        typer.secho(f"MCP-Guard: {total} finding(s)", fg=typer.colors.YELLOW, bold=True, err=True)
        if counts:
            rendered = ", ".join(f"{level}: {count}" for level, count in sorted(counts.items()))
            typer.secho(f"  {rendered}", fg=typer.colors.YELLOW, err=True)
    else:
        typer.secho("MCP-Guard: no findings", fg=typer.colors.GREEN, bold=True, err=True)
