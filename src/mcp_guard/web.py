"""Small stateless web API shared by the Vercel handler and tests."""

from pathlib import Path
from typing import Any

import os

from mcp_guard import ai_guard
from mcp_guard.llm_judge import MAX_EXPLAINED_FINDINGS, configured_model, explain_findings
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


def scan_payload(payload: Any, client_id: str = "local") -> dict[str, Any]:
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

    llm_judge = payload.get("llm_judge")
    if llm_judge not in (None, False, True):
        raise RequestError("'llm_judge' must be a boolean")
    if llm_judge is True and report["findings"]:
        _add_ai_explanations(report, client_id)
    return report


def _add_ai_explanations(report: dict[str, Any], client_id: str) -> None:
    """Attach AI explanations, preferring cached results and enforcing demo rate limits."""
    findings = report["findings"]
    if len(findings) > MAX_EXPLAINED_FINDINGS:
        report["ai_note"] = f"AI explanations cover the first {MAX_EXPLAINED_FINDINGS} findings."
    key = ai_guard.cache_key(findings[:MAX_EXPLAINED_FINDINGS])
    cached = ai_guard.get_cached(key)
    if cached is not None:
        report["ai_explanations"] = cached["explanations"]
        report["ai_model"] = cached.get("model", configured_model())
        report["ai_cached"] = True
        return
    if not os.getenv("OPENAI_API_KEY", "").strip():
        report["ai_error"] = "AI explanations unavailable: OPENAI_API_KEY is not configured on the server."
        return
    blocked = ai_guard.allow_ai_call(client_id)
    if blocked:
        report["ai_error"] = blocked
        return
    try:
        explanations = explain_findings(findings)
    except Exception as exc:
        # Rule-based results are still returned; only exception class names are echoed back.
        cause = exc.__cause__ or exc.__context__
        detail = type(exc).__name__ + (f" <- {type(cause).__name__}" if cause else "")
        status = getattr(exc, "status_code", None)
        if status:
            detail += f", HTTP {status}"
        report["ai_error"] = f"AI explanations unavailable: OpenAI request failed ({detail})."
        return
    report["ai_explanations"] = explanations
    report["ai_model"] = configured_model()
    report["ai_cached"] = False
    if explanations:
        ai_guard.put_cached(key, explanations, report["ai_model"])


def health() -> dict[str, Any]:
    """Health information for GET /api; never includes secret values."""
    return {
        "service": "MCP-Guard",
        "status": "ok",
        "ai_configured": bool(os.getenv("OPENAI_API_KEY", "").strip()),
        "ai_limit_per_ip_per_hour": ai_guard.per_client_limit(),
        "ai_model": configured_model(),
        "max_source_characters": MAX_SOURCE_CHARS,
        "usage": "POST JSON with source (+filename) and/or tools/manifest; set llm_judge=true for AI explanations.",
    }
