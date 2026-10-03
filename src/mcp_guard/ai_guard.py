"""Cost protection for the public web demo: response caching and AI rate limits.

The cache key is a hash of the findings that would be sent to the model, so the
same input (for example the demo samples) never triggers a second paid API call.
Explanations saved in sample_ai_cache.json are served with no API call at all.
Rate limits are kept in memory per serverless instance, so they are best-effort:
the OpenAI organisation spend limit remains the hard cap.
"""

import hashlib
import json
import os
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any

_CACHE_FILE = Path(__file__).with_name("sample_ai_cache.json")
_CACHE_FIELDS = ("rule_id", "title", "severity", "description", "evidence")
_MAX_MEMORY_ENTRIES = 256
_lock = threading.Lock()
_memory_cache: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
_client_hits: dict[str, deque] = {}
_global_hits: deque = deque()


def _int_env(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def per_client_limit() -> int:
    return _int_env("MCP_GUARD_AI_PER_IP_PER_HOUR", 5)


def global_limit() -> int:
    return _int_env("MCP_GUARD_AI_GLOBAL_PER_HOUR", 100)


def cache_key(findings: list[dict[str, Any]]) -> str:
    """Stable hash of the finding fields that determine the AI explanation."""
    reduced = [{key: item.get(key) for key in _CACHE_FIELDS} for item in findings]
    blob = json.dumps(reduced, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _load_saved() -> dict[str, Any]:
    try:
        data = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


_saved_cache = _load_saved()


def get_cached(key: str) -> dict[str, Any] | None:
    """Return {"explanations": [...], "model": str} from the saved or in-memory cache."""
    if key in _saved_cache:
        return _saved_cache[key]
    with _lock:
        entry = _memory_cache.get(key)
        if entry is not None:
            _memory_cache.move_to_end(key)
        return entry


def put_cached(key: str, explanations: list[dict[str, Any]], model: str) -> None:
    with _lock:
        _memory_cache[key] = {"explanations": explanations, "model": model}
        _memory_cache.move_to_end(key)
        while len(_memory_cache) > _MAX_MEMORY_ENTRIES:
            _memory_cache.popitem(last=False)


def allow_ai_call(client_id: str, now: float | None = None) -> str | None:
    """Record an AI call; return None if allowed, otherwise a user-facing reason."""
    now = time.time() if now is None else now
    window_start = now - 3600
    with _lock:
        while _global_hits and _global_hits[0] < window_start:
            _global_hits.popleft()
        hits = _client_hits.setdefault(client_id or "unknown", deque())
        while hits and hits[0] < window_start:
            hits.popleft()
        if len(_global_hits) >= global_limit():
            return "The demo's hourly AI budget is used up. Rule-based results are still shown; try AI again later."
        if len(hits) >= per_client_limit():
            return f"AI limit reached ({per_client_limit()} AI scans per hour per visitor). Rule-based results are still shown."
        hits.append(now)
        _global_hits.append(now)
        if len(_client_hits) > 10_000:
            _client_hits.clear()
        return None


def reset_for_tests() -> None:
    with _lock:
        _memory_cache.clear()
        _client_hits.clear()
        _global_hits.clear()
