"""Base interface for independently implemented scanner rules."""

from abc import ABC, abstractmethod
from collections.abc import Iterable
from pathlib import Path

from mcp_guard.models import Finding, RuleMetadata


class Rule(ABC):
    """A rule that inspects source files or normalized tool definitions."""

    metadata: RuleMetadata

    @abstractmethod
    def scan_source(self, path: Path, source: str) -> Iterable[Finding]:
        """Inspect one Python or TypeScript source file."""

    def scan_tools(self, tools: list[dict[str, object]]) -> Iterable[Finding]:
        """Inspect tools/list definitions; source-only rules may keep this empty."""
        return ()
