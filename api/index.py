"""Vercel serverless endpoint for scanning submitted MCP source and manifests."""

import json
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from mcp_guard.web import JudgeError, RequestError, health, scan_payload

MAX_BODY_BYTES = 1_500_000


class handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        self._send_json(200, health())

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"error": "invalid Content-Length"})
            return
        if length < 1:
            self._send_json(400, {"error": "request body is required"})
            return
        if length > MAX_BODY_BYTES:
            self._send_json(413, {"error": f"request body exceeds {MAX_BODY_BYTES} bytes"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            result = scan_payload(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "request body must contain valid UTF-8 JSON"})
            return
        except RequestError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except JudgeError as exc:
            self._send_json(502, {"error": str(exc)})
            return
        except RuntimeError as exc:
            self._send_json(503, {"error": str(exc)})
            return
        self._send_json(200, result)

    def do_PUT(self) -> None:
        self._send_json(405, {"error": "method not allowed; use POST"})

    def log_message(self, format: str, *args: object) -> None:
        # Avoid placing submitted source or tool text in deployment logs.
        return
