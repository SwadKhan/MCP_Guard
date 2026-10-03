"""Heuristically detect tool output passed to an LLM without sanitization."""

import re
from collections.abc import Iterable
from pathlib import Path

from mcp_guard.models import Finding, RuleMetadata, Severity
from mcp_guard.rules.base import Rule

OWASP = ("LLM01:2025 Prompt Injection",)
_OUTPUT_ASSIGNMENT = re.compile(
    r"(?:\b(?:const|let|var)\s+)?(?P<name>[A-Za-z_]\w*)\s*=\s*(?:await\s+)?[^\n]*(?:call_tool|callTool|invoke_tool|invokeTool|tools?\.call)\s*\(", re.I
)
_MODEL_SINK = re.compile(
    r"(?:chat\.completions\.create|responses\.create|generate_content|generateContent|\.invoke|\.complete)\s*\(", re.I
)
_SANITIZER = re.compile(r"\b(?:sanitize|sanitise|escape|validate|strip_control_chars|sanitize_tool_output)\s*\(", re.I)


class PromptInjectionPathRule(Rule):
    metadata = RuleMetadata(
        "MCPG-004", "Unsanitised tool output path", Severity.MEDIUM,
        "Tool output appears to flow directly into a model request without a recognized sanitization step.",
        "Treat tool output as untrusted data, apply context-appropriate sanitization, and keep it separate from instructions.",
        OWASP,
    )

    def scan_source(self, path: Path, source: str) -> Iterable[Finding]:
        assignments = {match.group("name"): match.start() for match in _OUTPUT_ASSIGNMENT.finditer(source)}
        if not assignments:
            return ()
        findings: list[Finding] = []
        for sink in _MODEL_SINK.finditer(source):
            call_end = source.find(")", sink.end())
            if call_end < 0:
                call_end = min(len(source), sink.end() + 1200)
            else:
                call_end = min(call_end, sink.end() + 3000)
            call = source[sink.start():call_end]
            for name, assigned_at in assignments.items():
                if not re.search(rf"\b{re.escape(name)}\b", call):
                    continue
                sanitizer_call = rf"{_SANITIZER.pattern}\s*{re.escape(name)}\b"
                sanitized_aliases = set(re.findall(
                    rf"(?:const\s+|let\s+|var\s+)?([A-Za-z_]\w*)\s*=\s*{sanitizer_call}",
                    source[assigned_at:sink.start()], re.I,
                ))
                # Direct sanitizer calls at the sink and sanitized aliases are accepted.
                safe_direct = re.search(sanitizer_call, call, re.I)
                if safe_direct or any(re.search(rf"\b{re.escape(alias)}\b", call) for alias in sanitized_aliases):
                    continue
                line = source.count("\n", 0, sink.start()) + 1
                findings.append(Finding(
                    self.metadata.rule_id, "Tool output reaches model unsanitized", self.metadata.severity,
                    self.metadata.description, self.metadata.remediation, path=path, line=line,
                    evidence=f"tool result variable {name!r} is referenced in an LLM call",
                    owasp_llm=self.metadata.owasp_llm,
                ))
        return findings

    def scan_tools(self, tools: list[dict[str, object]]) -> Iterable[Finding]:
        return ()
