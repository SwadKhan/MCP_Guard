"""Detect high-impact shell, filesystem, and network capabilities."""

import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from mcp_guard.models import Finding, RuleMetadata, Severity
from mcp_guard.rules.base import Rule

OWASP = ("LLM06:2025 Excessive Agency",)
_SOURCE_PATTERNS = (
    ("shell execution", re.compile(r"\b(?:subprocess\.(?:run|Popen|call|check_output)|os\.system|child_process\.exec(?:Sync)?|execSync)\s*\(")),
    ("broad filesystem access", re.compile(r"\b(?:open|read_text|write_text|readFileSync|writeFileSync)\s*\([^\n]*(?:/|\*\*|\.ssh|\.env)")),
    ("broad filesystem access", re.compile(r"\bopen\s*\(\s*(?:path|file_path|filename|user_path)\b", re.I)),
    ("network request", re.compile(r"\b(?:requests\.(?:get|post|put|delete)|fetch|axios\.(?:get|post)|httpx\.(?:get|post))\s*\(")),
)
_TOOL_PATTERNS = (
    ("shell execution", re.compile(r"\b(?:shell|terminal|command|exec|run_command)\b", re.I)),
    ("broad filesystem access", re.compile(r"\b(?:arbitrary|any|entire|unrestricted|all)\b.{0,50}\b(?:file|filesystem|directory|path)|\b(?:read|write|delete)\s+(?:any|arbitrary|all)\s+files?", re.I)),
    ("arbitrary network access", re.compile(r"\b(?:arbitrary|any|unrestricted)\b.{0,50}\b(?:url|host|network|http|internet)|\b(?:fetch|request)\s+(?:any|arbitrary)\s+(?:url|host)", re.I)),
)


class ExcessivePermissionsRule(Rule):
    metadata = RuleMetadata(
        "MCPG-002", "Excessive permissions", Severity.HIGH,
        "The server exposes shell execution, broad filesystem access, or arbitrary network requests.",
        "Constrain capabilities to the task, validate paths and destinations, and require approval for high-impact actions.",
        OWASP,
    )

    def scan_source(self, path: Path, source: str) -> Iterable[Finding]:
        for line_number, line in enumerate(source.splitlines(), 1):
            for capability, pattern in _SOURCE_PATTERNS:
                match = pattern.search(line)
                if match:
                    yield self._finding(path, line_number, capability, line.strip())

    def scan_tools(self, tools: list[dict[str, Any]]) -> Iterable[Finding]:
        for tool in tools:
            text = f"{tool.get('name', '')} {tool.get('description', '')} {tool.get('inputSchema', '')}"
            for capability, pattern in _TOOL_PATTERNS:
                match = pattern.search(text)
                if match:
                    yield self._finding(None, None, capability, f"{tool.get('name', '')}: {match.group(0)}")

    def _finding(self, path: Path | None, line: int | None, capability: str, evidence: str) -> Finding:
        return Finding(self.metadata.rule_id, f"Potential {capability}", self.metadata.severity,
                       f"{self.metadata.description} Detected: {capability}.", self.metadata.remediation,
                       path=path, line=line, evidence=evidence[:240], owasp_llm=self.metadata.owasp_llm)
