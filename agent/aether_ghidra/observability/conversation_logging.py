from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config.settings import load_config


_WRITE_LOCK = threading.Lock()


def _json_safe(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        try:
            return _json_safe(value.model_dump(exclude_none=True))
        except Exception:
            pass
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "__dict__"):
        return _json_safe(vars(value))
    return str(value)


class ConversationLogger:
    """Writes outbound model conversations to a separate JSONL transcript."""

    def __init__(self, config: dict[str, Any] | None = None, path: str | Path | None = None) -> None:
        config = load_config() if config is None else config
        configured = os.getenv("AETHER_GHIDRA_CONVERSATION_LOG_FILE") or config.get("CONVERSATION_LOG_FILE")
        self.path = Path(path or configured).expanduser() if (path or configured) else None

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def record_completion(
        self,
        source: str,
        request: dict[str, Any],
        response: Any = None,
        error: Exception | None = None,
    ) -> None:
        if self.path is None:
            return
        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "model": request.get("model"),
            "messages": _json_safe(request.get("messages", [])),
        }
        for key in ("tools", "tool_choice"):
            if key in request:
                record[key] = _json_safe(request[key])
        if response is not None:
            choices = getattr(response, "choices", None) or []
            message = getattr(choices[0], "message", None) if choices else None
            record["response"] = _json_safe(message if message is not None else response)
        if error is not None:
            record["error"] = {"type": type(error).__name__, "message": str(error)}
        try:
            with _WRITE_LOCK:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record, ensure_ascii=True, default=str) + "\n")
                try:
                    self.path.chmod(0o600)
                except OSError:
                    pass
        except OSError:
            # Transcript logging must never make an LLM request fail.
            return
