"""Load JSON representations of MCP tools/list results."""

import json
from pathlib import Path
from typing import Any


class ManifestError(ValueError):
    """Raised when a JSON file is not a recognizable tools/list manifest."""


def load_manifest(path: Path) -> list[dict[str, Any]]:
    """Read tool definitions from a tools/list response or a bare ``tools`` object."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read JSON manifest {path}: {exc}") from exc

    return parse_manifest_data(data)


def parse_manifest_data(data: Any) -> list[dict[str, Any]]:
    """Validate a decoded tools/list response and return normalized tool objects."""
    # MCP may be captured as a direct result or wrapped in a JSON-RPC response.
    if isinstance(data, dict) and isinstance(data.get("result"), dict):
        data = data["result"]
    if not isinstance(data, dict) or not isinstance(data.get("tools"), list):
        raise ManifestError("manifest must be an object containing a 'tools' array")

    tools: list[dict[str, Any]] = []
    for index, tool in enumerate(data["tools"]):
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            raise ManifestError(f"tool at index {index} must be an object with a string 'name'")
        tools.append(tool)
    return tools
