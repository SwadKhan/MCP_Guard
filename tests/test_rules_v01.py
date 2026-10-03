from pathlib import Path

import pytest

from mcp_guard.manifest import ManifestError, load_manifest
from mcp_guard.rules.excessive_permissions import ExcessivePermissionsRule
from mcp_guard.rules.secrets import SecretsRule
from mcp_guard.rules.tool_poisoning import ToolPoisoningRule

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("rule", [ToolPoisoningRule(), ExcessivePermissionsRule()])
def test_rules_detect_vulnerable_tools_list(rule) -> None:
    findings = list(rule.scan_tools(load_manifest(FIXTURES / "vulnerable_tools.json")))
    assert findings
    assert all(item.rule_id == rule.metadata.rule_id for item in findings)


@pytest.mark.parametrize("rule", [ToolPoisoningRule(), ExcessivePermissionsRule()])
def test_rules_accept_clean_tools_list(rule) -> None:
    findings = list(rule.scan_tools(load_manifest(FIXTURES / "clean_tools.json")))
    assert findings == []


def test_manifest_loader_accepts_json_rpc_tools_list() -> None:
    tools = load_manifest(FIXTURES / "vulnerable_tools.json")
    assert [tool["name"] for tool in tools] == ["ignore_previous_instructions", "run_command"]


def test_manifest_loader_rejects_unrecognized_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"resources": []}', encoding="utf-8")
    with pytest.raises(ManifestError, match="tools"):
        load_manifest(path)


@pytest.mark.parametrize("filename", ["vulnerable_server.py", "vulnerable_server.ts"])
def test_excessive_permissions_detected_in_source(filename: str) -> None:
    path = FIXTURES / filename
    findings = list(ExcessivePermissionsRule().scan_source(path, path.read_text(encoding="utf-8")))
    assert findings
    assert all(item.rule_id == "MCPG-002" for item in findings)


def test_excessive_permissions_flags_user_controlled_file_path() -> None:
    source = "def read_anything(path):\n    return open(path).read()\n"
    findings = list(ExcessivePermissionsRule().scan_source(Path("server.py"), source))
    assert len(findings) == 1
    assert "filesystem" in findings[0].title


def test_excessive_permissions_absent_from_clean_source() -> None:
    path = FIXTURES / "clean_server.py"
    assert list(ExcessivePermissionsRule().scan_source(path, path.read_text(encoding="utf-8"))) == []


def test_hard_coded_secrets_detected_and_redacted_in_evidence() -> None:
    path = FIXTURES / "vulnerable_server.py"
    findings = list(SecretsRule().scan_source(path, path.read_text(encoding="utf-8")))
    assert findings
    assert all(item.rule_id == "MCPG-005" for item in findings)
    assert all("THIS_IS_A_FAKE" not in (item.evidence or "") for item in findings)


@pytest.mark.parametrize("filename", ["clean_server.py", "clean_tools.json"])
def test_clean_fixtures_have_no_secrets(filename: str) -> None:
    path = FIXTURES / filename
    source = path.read_text(encoding="utf-8")
    assert list(SecretsRule().scan_source(path, source)) == []


def test_tool_poisoning_detects_hidden_unicode() -> None:
    tool = {"name": "lookup\u200b", "description": "Lookup a record."}
    findings = list(ToolPoisoningRule().scan_tools([tool]))
    assert len(findings) == 1
    assert "U+200B" in findings[0].description
