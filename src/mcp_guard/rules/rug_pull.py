"""Hash tool definitions and report additions, removals, or modifications."""

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from mcp_guard.models import Finding, RuleMetadata, Severity
from mcp_guard.rules.base import Rule

OWASP = ("LLM03:2025 Supply Chain Vulnerabilities",)


def definition_hash(tool: dict[str, Any]) -> str:
    """Hash a complete tool definition using stable canonical JSON."""
    canonical = json.dumps(tool, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def create_baseline(tools: list[dict[str, Any]]) -> dict[str, Any]:
    """Create a JSON-serializable lockfile payload for a manifest."""
    return {"format_version": 1, "tools": {tool["name"]: definition_hash(tool) for tool in tools}}


def validate_baseline(data: Any) -> dict[str, str]:
    """Validate and return the tool hash mapping from a baseline payload."""
    if not isinstance(data, dict) or data.get("format_version") != 1 or not isinstance(data.get("tools"), dict):
        raise ValueError("lockfile must have format_version 1 and a tools object")
    if not all(isinstance(name, str) and isinstance(value, str) and len(value) == 64 for name, value in data["tools"].items()):
        raise ValueError("lockfile tools must map names to SHA-256 hashes")
    return data["tools"]


class RugPullRule(Rule):
    metadata = RuleMetadata(
        "MCPG-003", "Tool definition changed", Severity.HIGH,
        "A tool definition differs from its approved baseline, or was added or removed.",
        "Review the tool change and update the lockfile only after verifying the new definition.",
        OWASP,
    )

    def __init__(self, baseline: dict[str, str] | None = None) -> None:
        self.baseline = baseline

    def scan_source(self, path: Path, source: str) -> Iterable[Finding]:
        return ()

    def scan_tools(self, tools: list[dict[str, Any]]) -> Iterable[Finding]:
        if self.baseline is None:
            return ()
        current = {tool["name"]: tool for tool in tools}
        findings: list[Finding] = []
        for name, tool in current.items():
            digest = definition_hash(tool)
            if name not in self.baseline:
                detail = "new tool was added"
            elif digest != self.baseline[name]:
                detail = f"definition hash changed ({self.baseline[name][:12]} → {digest[:12]})"
            else:
                continue
            findings.append(Finding(self.metadata.rule_id, self.metadata.name, self.metadata.severity,
                                    f"Tool {name!r}: {detail}.", self.metadata.remediation,
                                    evidence=f"tool={name}; {detail}", owasp_llm=self.metadata.owasp_llm))
        for name in self.baseline.keys() - current.keys():
            findings.append(Finding(self.metadata.rule_id, self.metadata.name, self.metadata.severity,
                                    f"Tool {name!r} was removed from the manifest.", self.metadata.remediation,
                                    evidence=f"tool={name}; tool removed", owasp_llm=self.metadata.owasp_llm))
        return findings
