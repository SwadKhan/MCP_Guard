"""Detect manipulative tool names/descriptions and invisible Unicode."""

import re
import unicodedata
from collections.abc import Iterable
from pathlib import Path

from mcp_guard.models import Finding, RuleMetadata, Severity
from mcp_guard.rules.base import Rule

OWASP = ("LLM01:2025 Prompt Injection",)
_PATTERNS = (
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.I),
    re.compile(r"(?:read|access|exfiltrat\w*|send|upload)\b.{0,100}(?:~[/\\]\.ssh|\.ssh|credentials?|secrets?|private\s+keys?)", re.I | re.S),
    re.compile(r"(?:send|exfiltrat\w*|upload)\b.{0,100}(?:data|files?|contents?)\b.{0,60}(?:https?://|attacker|external)", re.I | re.S),
    re.compile(r"(?:do\s+not|don't)\s+(?:tell|inform|show)\s+(?:the\s+)?user", re.I),
)


def _signals(text: str) -> list[str]:
    signals = [f"suspicious instruction: {match.group(0)}" for pattern in _PATTERNS if (match := pattern.search(text))]
    invisible = [char for char in text if unicodedata.category(char) in {"Cf", "Cc"} and char not in "\n\r\t"]
    if invisible:
        names = ", ".join(sorted({f"U+{ord(char):04X}" for char in invisible}))
        signals.append(f"contains invisible/control Unicode characters ({names})")
    return signals


class ToolPoisoningRule(Rule):
    metadata = RuleMetadata(
        "MCPG-001", "Tool poisoning", Severity.HIGH,
        "Tool names or descriptions contain hidden or manipulative instructions.",
        "Remove instructions aimed at overriding the model or accessing/exfiltrating unrelated data; remove invisible Unicode.",
        OWASP,
    )

    def scan_source(self, path: Path, source: str) -> Iterable[Finding]:
        for line_number, line in enumerate(source.splitlines(), 1):
            for signal in _signals(line):
                yield self._finding(path, line_number, signal, line.strip())

    def scan_tools(self, tools: list[dict[str, object]]) -> Iterable[Finding]:
        for tool in tools:
            name = str(tool.get("name", ""))
            description = str(tool.get("description", ""))
            text = f"{name}\n{description}"
            for signal in _signals(text):
                yield self._finding(None, None, signal, f"{name}: {signal}")

    def _finding(self, path: Path | None, line: int | None, signal: str, evidence: str) -> Finding:
        return Finding(self.metadata.rule_id, "Suspicious tool instruction", self.metadata.severity,
                       f"{self.metadata.description} Signal: {signal}", self.metadata.remediation,
                       path=path, line=line, evidence=evidence[:240], owasp_llm=self.metadata.owasp_llm)
