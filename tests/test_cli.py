import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_guard.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_emits_json_for_manifest() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "clean_tools.json")])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["findings"] == 0
    assert report["scanned"]["manifests"] == [str(FIXTURES / "clean_tools.json")]


def test_fail_on_high_exits_nonzero_for_vulnerable_manifest() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "vulnerable_tools.json"), "--fail-on", "high"])
    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["summary"]["findings"] > 0


def test_fail_on_high_allows_clean_source() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "clean_server.py"), "--fail-on", "high"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["summary"]["findings"] == 0


def test_scan_writes_json_to_output_file(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    result = runner.invoke(app, ["scan", str(FIXTURES / "vulnerable_server.py"), "--output", str(output)])
    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["findings"] > 0
    assert {finding["rule_id"] for finding in report["findings"]} >= {"MCPG-002", "MCPG-005"}


def test_scan_rejects_invalid_fail_on_value() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "clean_server.py"), "--fail-on", "urgent"])
    assert result.exit_code != 0
