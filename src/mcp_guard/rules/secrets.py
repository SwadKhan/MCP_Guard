"""Detect common hard-coded credentials in source code."""

import re
from collections.abc import Iterable
from pathlib import Path

from mcp_guard.models import Finding, RuleMetadata, Severity
from mcp_guard.rules.base import Rule

OWASP = ("LLM02:2025 Sensitive Information Disclosure",)
_SECRET_PATTERNS = (
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("generic credential assignment", re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
)


class SecretsRule(Rule):
    metadata = RuleMetadata(
        "MCPG-005", "Hard-coded secrets", Severity.CRITICAL,
        "Source code appears to contain a hard-coded API key, token, or password.",
        "Revoke exposed credentials, remove them from source history, and load replacements from environment-backed secret storage.",
        OWASP,
    )

    def scan_source(self, path: Path, source: str) -> Iterable[Finding]:
        for line_number, line in enumerate(source.splitlines(), 1):
            for kind, pattern in _SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Evidence deliberately omits the credential value.
                    yield Finding(self.metadata.rule_id, f"Possible hard-coded {kind}", self.metadata.severity,
                                  self.metadata.description, self.metadata.remediation,
                                  path=path, line=line_number, evidence=f"{kind} detected (value redacted)",
                                  owasp_llm=self.metadata.owasp_llm)
