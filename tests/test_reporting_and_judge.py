import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_guard.cli import app
from mcp_guard.llm_judge import borderline_findings, judge_findings, redact_text
from mcp_guard.reporters.html_report import render_html

FIXTURES = Path(__file__).parent / "fixtures"


def test_html_report_escapes_untrusted_finding_content() -> None:
    html = render_html({
        "summary": {"findings": 1},
        "findings": [{
            "rule_id": "MCPG-001", "severity": "high", "title": "<script>alert(1)</script>",
            "description": "desc", "remediation": "fix", "evidence": "<img src=x onerror=alert(1)>",
            "owasp_llm": ["LLM01:2025 Prompt Injection"],
        }],
    })
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html


def test_secret_redaction_covers_provider_keys_and_assignments() -> None:
    raw = "api_key='sk-proj-THIS_IS_A_FAKE_TEST_KEY_1234567890' Bearer ghp_12345678901234567890"
    safe = redact_text(raw)
    assert "THIS_IS_A_FAKE" not in safe
    assert "ghp_12345678901234567890" not in safe
    assert safe.count("[REDACTED]") >= 2


def test_borderline_selection_only_includes_low_and_medium() -> None:
    report = {"findings": [
        {"rule_id": "MCPG-1", "severity": "low", "title": "low"},
        {"rule_id": "MCPG-2", "severity": "medium", "title": "medium"},
        {"rule_id": "MCPG-3", "severity": "high", "title": "high"},
    ]}
    assert [item["rule_id"] for item in borderline_findings(report)] == ["MCPG-1", "MCPG-2"]


def test_judge_redacts_request_payload_before_sending(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-is-not-used-as-finding-data")

    class Responses:
        def __init__(self):
            self.payload = None

        def create(self, **kwargs):
            self.payload = kwargs
            class Response:
                output_text = '[{"rule_id":"MCPG-004","likely_valid":true,"justification":"Possible unsafe data flow."}]'
            return Response()

    class Client:
        def __init__(self):
            self.responses = Responses()

    client = Client()
    result = judge_findings([{"rule_id": "MCPG-004", "evidence": "token='ghp_12345678901234567890'"}], client=client)
    assert "ghp_12345678901234567890" not in client.responses.payload["input"]
    assert result[0]["likely_valid"] is True


def test_judge_skips_request_when_there_are_no_borderline_findings() -> None:
    assert judge_findings([]) == []


def test_scan_writes_html_and_keeps_json_stdout_separate(tmp_path: Path) -> None:
    html_path = tmp_path / "report.html"
    result = CliRunner().invoke(app, ["scan", str(FIXTURES / "vulnerable_tools.json"), "--html", str(html_path)])
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["summary"]["findings"] > 0
    assert "MCP-Guard:" in result.stderr
    assert "MCPG-001" in html_path.read_text(encoding="utf-8")
