from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any


HISTORY_ROOT = Path.home() / ".config" / "aether-ghidra" / "annotation-history"


class AnnotationHistory:
    def __init__(self, program_key: str) -> None:
        safe_key = re.sub(r"[^A-Za-z0-9_.-]", "_", program_key or "unknown")
        self.path = HISTORY_ROOT / f"{safe_key}.json"

    def entries(self) -> list[dict[str, Any]]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            return value if isinstance(value, list) else []
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return []

    def append(self, entry: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        values = self.entries()
        values.append({"timestamp": time.time(), **entry})
        self.path.write_text(json.dumps(values, indent=2) + "\n", encoding="utf-8")

    def latest_active(self) -> dict[str, Any] | None:
        for entry in reversed(self.entries()):
            if not entry.get("undone"):
                return entry
        return None

    def mark_undone(self, batch_id: str) -> None:
        values = self.entries()
        for entry in values:
            if entry.get("batch_id") == batch_id:
                entry["undone"] = True
                entry["undone_timestamp"] = time.time()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(values, indent=2) + "\n", encoding="utf-8")
