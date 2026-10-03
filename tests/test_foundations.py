from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_guard import __version__
from mcp_guard.cli import app
from mcp_guard.models import Finding, RuleMetadata, Severity
from mcp_guard.rules.base import Rule


def test_severity_order_supports_thresholds() -> None:
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


@pytest.mark.parametrize(("value", "expected"), [("high", Severity.HIGH), ("CRITICAL", Severity.CRITICAL)])
def test_severity_parse(value: str, expected: Severity) -> None:
    assert Severity.parse(value) is expected


def test_invalid_severity_has_choices() -> None:
    with pytest.raises(ValueError, match="choose from"):
        Severity.parse("urgent")


def test_finding_carries_rule_and_owasp_mapping() -> None:
    finding = Finding("MCPG-001", "Suspicious instruction", Severity.HIGH, "desc", "fix", owasp_llm=("LLM01:2025",))
    assert finding.rule_id == "MCPG-001"
    assert finding.owasp_llm == ("LLM01:2025",)


def test_rule_interface_is_abstract() -> None:
    with pytest.raises(TypeError):
        Rule()  # type: ignore[abstract]


def test_cli_version() -> None:
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout

