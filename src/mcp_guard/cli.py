"""Typer command-line entry point."""

import json
from enum import Enum
from pathlib import Path

import typer

from mcp_guard import __version__
from mcp_guard.manifest import ManifestError, load_manifest
from mcp_guard.models import Severity
from mcp_guard.rules.rug_pull import create_baseline, validate_baseline
from mcp_guard.scanner import ScanInputError, scan

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


class FailOn(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@app.command("scan")
def scan_command(
    target: Path = typer.Argument(..., help="Python/TypeScript source file, directory, or tools/list JSON manifest."),
    manifest: Path | None = typer.Option(None, "--manifest", help="Additional tools/list JSON manifest to scan."),
    lockfile: Path | None = typer.Option(None, "--lockfile", help="Approved tool-definition baseline to compare."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON report to this path instead of stdout."),
    fail_on: FailOn = typer.Option(FailOn.NONE, "--fail-on", help="Exit 1 if any finding has this severity or higher."),
) -> None:
    """Scan local MCP source or a saved tools/list JSON result."""
    try:
        report = scan(target, manifest, lockfile)
    except (ScanInputError, ManifestError, OSError) as exc:
        raise typer.BadParameter(str(exc), param_hint="TARGET/--manifest") from exc

    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if output:
        try:
            output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            raise typer.BadParameter(f"cannot write report {output}: {exc}", param_hint="--output") from exc
    else:
        typer.echo(rendered, nl=False)

    if fail_on is not FailOn.NONE:
        threshold = Severity.parse(fail_on.value)
        if any(Severity.parse(item["severity"]) >= threshold for item in report["findings"]):
            raise typer.Exit(code=1)


@app.command("baseline")
def baseline_command(
    manifest: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True, help="tools/list JSON manifest."),
    output: Path = typer.Option(Path(".mcp-guard.lock.json"), "--output", "-o", help="Lockfile path to create."),
) -> None:
    """Create a tool-definition baseline lockfile from a saved manifest."""
    try:
        payload = create_baseline(load_manifest(manifest))
        validate_baseline(payload)
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except (ManifestError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc), param_hint="MANIFEST/--output") from exc
