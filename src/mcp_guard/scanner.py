"""Coordinate source and manifest scans across registered rules."""

import json
from pathlib import Path
from typing import Any

from mcp_guard.manifest import load_manifest
from mcp_guard.models import Finding
from mcp_guard.rules.base import Rule
from mcp_guard.rules.excessive_permissions import ExcessivePermissionsRule
from mcp_guard.rules.prompt_injection import PromptInjectionPathRule
from mcp_guard.rules.rug_pull import RugPullRule, validate_baseline
from mcp_guard.rules.secrets import SecretsRule
from mcp_guard.rules.tool_poisoning import ToolPoisoningRule

SOURCE_SUFFIXES = {".py", ".ts", ".tsx"}
DEFAULT_RULES: tuple[Rule, ...] = (
    ToolPoisoningRule(), ExcessivePermissionsRule(), SecretsRule(), PromptInjectionPathRule(), RugPullRule()
)


class ScanInputError(ValueError):
    """Raised for a target that cannot be statically scanned."""


def collect_source_files(target: Path) -> list[Path]:
    """Return supported source files from a file or recursively from a directory."""
    if not target.exists():
        raise ScanInputError(f"input path does not exist: {target}")
    if target.is_file():
        if target.suffix.lower() not in SOURCE_SUFFIXES:
            raise ScanInputError(f"unsupported source type: {target.suffix or '(no extension)'}; use .py, .ts, or .tsx")
        return [target]
    if not target.is_dir():
        raise ScanInputError(f"input is not a regular file or directory: {target}")
    return sorted(path for path in target.rglob("*") if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES)


def scan(
    target: Path,
    manifest_path: Path | None = None,
    lockfile_path: Path | None = None,
    rules: tuple[Rule, ...] = DEFAULT_RULES,
) -> dict[str, Any]:
    """Scan source files and/or one tools/list manifest and return a JSON-ready report."""
    if target.suffix.lower() == ".json":
        if manifest_path is not None:
            raise ScanInputError("provide a JSON manifest as the input path or with --manifest, not both")
        manifest_path = target
        source_files: list[Path] = []
    else:
        source_files = collect_source_files(target)

    findings: list[Finding] = []
    scanned_sources: list[str] = []
    for path in source_files:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ScanInputError(f"cannot read source file {path}: {exc}") from exc
        scanned_sources.append(str(path))
        for rule in rules:
            findings.extend(rule.scan_source(path, source))

    scanned_manifests: list[str] = []
    if manifest_path is not None:
        tools = load_manifest(manifest_path)
        scanned_manifests.append(str(manifest_path))
        active_rules = rules
        if lockfile_path is not None:
            try:
                lock_data = json.loads(lockfile_path.read_text(encoding="utf-8"))
                baseline = validate_baseline(lock_data)
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise ScanInputError(f"invalid lockfile {lockfile_path}: {exc}") from exc
            active_rules = tuple(rule for rule in rules if not isinstance(rule, RugPullRule)) + (RugPullRule(baseline),)
        for rule in active_rules:
            findings.extend(rule.scan_tools(tools))
    elif lockfile_path is not None:
        raise ScanInputError("--lockfile requires a JSON tools/list manifest")

    counts: dict[str, int] = {}
    for finding in findings:
        key = finding.severity.name.lower()
        counts[key] = counts.get(key, 0) + 1

    return {
        "tool": "mcp-guard",
        "version": "0.1.0",
        "scanned": {"source_files": scanned_sources, "manifests": scanned_manifests},
        "summary": {"findings": len(findings), "by_severity": counts},
        "findings": [finding_to_dict(item) for item in findings],
    }


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Convert a finding into a stable JSON-compatible representation."""
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.name.lower(),
        "description": finding.description,
        "remediation": finding.remediation,
        "path": str(finding.path) if finding.path else None,
        "line": finding.line,
        "evidence": finding.evidence,
        "owasp_llm": list(finding.owasp_llm),
        "metadata": finding.metadata,
    }
