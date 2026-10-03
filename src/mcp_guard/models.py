"""Shared data models used by scanner rules and report formats."""

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    """Ordered finding severities, suitable for CI thresholds."""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @classmethod
    def parse(cls, value: str) -> "Severity":
        """Parse a case-insensitive severity name."""
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(item.name.lower() for item in cls)
            raise ValueError(f"unknown severity {value!r}; choose from {choices}") from exc


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    """Stable identity and explanation attached to one scanner rule."""

    rule_id: str
    name: str
    severity: Severity
    description: str
    remediation: str
    owasp_llm: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Finding:
    """One detected security issue."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    path: Path | None = None
    line: int | None = None
    evidence: str | None = None
    owasp_llm: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)
