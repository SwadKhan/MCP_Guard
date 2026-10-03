"""Small self-contained HTML report renderer."""

import html
import json
from typing import Any


def render_html(report: dict[str, Any]) -> str:
    """Render an escaped, standalone HTML report from the JSON report model."""
    findings = report.get("findings", [])
    sections: list[str] = []
    for finding in findings:
        fields = (
            ("Rule", finding.get("rule_id")),
            ("Severity", finding.get("severity")),
            ("Title", finding.get("title")),
            ("Location", f"{finding.get('path') or 'manifest'}:{finding.get('line') or ''}"),
            ("Description", finding.get("description")),
            ("Remediation", finding.get("remediation")),
            ("Evidence", finding.get("evidence")),
            ("OWASP LLM Top 10", ", ".join(finding.get("owasp_llm", []))),
        )
        rows = "".join(
            f"<dt>{html.escape(str(label))}</dt><dd>{html.escape(str(value or ''))}</dd>" for label, value in fields
        )
        sections.append(f'<article class="finding"><dl>{rows}</dl></article>')
    if not sections:
        sections.append("<p>No findings.</p>")
    total = report.get("summary", {}).get("findings", len(findings))
    body = "\n".join(sections)
    report_json = html.escape(json.dumps(report, ensure_ascii=False, indent=2))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MCP-Guard security report</title>
  <style>
    :root {{ color-scheme: light dark; font: 16px/1.5 system-ui, sans-serif; }}
    body {{ max-width: 920px; margin: 2rem auto; padding: 0 1rem; }}
    .finding {{ border: 1px solid #8886; border-left: 5px solid #c87900; border-radius: .4rem; padding: 1rem; margin: 1rem 0; }}
    dl {{ display: grid; grid-template-columns: 10rem 1fr; gap: .45rem 1rem; margin: 0; }}
    dt {{ font-weight: 700; }} dd {{ margin: 0; overflow-wrap: anywhere; }}
    pre {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
  </style>
</head>
<body>
  <h1>MCP-Guard security report</h1>
  <p>{html.escape(str(total))} finding(s)</p>
  {body}
  <details><summary>JSON report</summary><pre>{report_json}</pre></details>
</body>
</html>
"""
