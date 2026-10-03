"""Small stateless web API shared by the Vercel handler and tests."""

from pathlib import Path
from typing import Any

from mcp_guard.llm_judge import borderline_findings, judge_findings
from mcp_guard.manifest import ManifestError, parse_manifest_data
from mcp_guard.models import Finding
from mcp_guard.scanner import DEFAULT_RULES, finding_to_dict

MAX_SOURCE_CHARS = 1_000_000
MAX_TOOLS = 500
ALLOWED_SOURCE_SUFFIXES = {".py", ".ts", ".tsx"}


class RequestError(ValueError):
    """An invalid or oversized scan request."""


class JudgeError(RuntimeError):
    """The optional AI judge failed after the scan completed."""


def scan_payload(payload: Any) -> dict[str, Any]:
    """Scan JSON fields named source, tools/manifest, and optional llm_judge."""
    if not isinstance(payload, dict):
        raise RequestError("request body must be a JSON object")
    findings: list[Finding] = []
    scanned: dict[str, Any] = {"source_files": [], "manifests": []}

    source = payload.get("source")
    if source is not None:
        if not isinstance(source, str):
            raise RequestError("'source' must be a string")
        if len(source) > MAX_SOURCE_CHARS:
            raise RequestError(f"'source' exceeds the {MAX_SOURCE_CHARS}-character limit")
        filename = payload.get("filename", "server.py")
        if not isinstance(filename, str) or Path(filename).suffix.lower() not in ALLOWED_SOURCE_SUFFIXES:
            raise RequestError("'filename' must end in .py, .ts, or .tsx")
        safe_name = Path(filename).name
        path = Path(safe_name)
        scanned["source_files"].append(safe_name)
        for rule in DEFAULT_RULES:
            findings.extend(rule.scan_source(path, source))

    raw_manifest = payload.get("manifest")
    raw_tools = payload.get("tools")
    if raw_manifest is not None and raw_tools is not None:
        raise RequestError("provide 'tools' or 'manifest', not both")
    if raw_manifest is not None:
        manifest_data = raw_manifest
    elif raw_tools is not None:
        manifest_data = {"tools": raw_tools}
    else:
        manifest_data = None

    if manifest_data is not None:
        try:
            tools = parse_manifest_data(manifest_data)
        except ManifestError as exc:
            raise RequestError(str(exc)) from exc
        if len(tools) > MAX_TOOLS:
            raise RequestError(f"manifest exceeds the {MAX_TOOLS}-tool limit")
        scanned["manifests"].append("request")
        for rule in DEFAULT_RULES:
            findings.extend(rule.scan_tools(tools))

    if not scanned["source_files"] and not scanned["manifests"]:
        raise RequestError("include source code, tools, or a manifest to scan")

    by_severity: dict[str, int] = {}
    for finding in findings:
        level = finding.severity.name.lower()
        by_severity[level] = by_severity.get(level, 0) + 1
    report: dict[str, Any] = {
        "tool": "mcp-guard",
        "version": "0.1.0",
        "scanned": scanned,
        "summary": {"findings": len(findings), "by_severity": by_severity},
        "findings": [finding_to_dict(item) for item in findings],
    }

    if payload.get("llm_judge") is True:
        try:
            report["llm_judgments"] = judge_findings(borderline_findings(report))
        except RuntimeError:
            raise
        except Exception as exc:
            # Do not return provider exception details that could disclose request data.
            raise JudgeError(f"OpenAI judge request failed ({type(exc).__name__})") from exc
    elif payload.get("llm_judge") not in (None, False):
        raise RequestError("'llm_judge' must be a boolean")
    return report
