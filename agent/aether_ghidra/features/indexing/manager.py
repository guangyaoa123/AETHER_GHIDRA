from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Any

from .model import FunctionIndex


class FunctionIndexManager:
    """Stable per-binary index persistence and cache."""

    _lock = threading.RLock()
    _cache: dict[str, FunctionIndex] = {}

    @classmethod
    def stable_id(cls, metadata: dict[str, Any]) -> str:
        for key in ("sha256", "md5"):
            value = str(metadata.get(key, "")).strip().lower()
            if value and set(value) != {"0"}:
                return value
        seed = "|".join(str(metadata.get(key, "")) for key in ("executable_path", "name", "language", "compiler"))
        return "program-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()

    @classmethod
    def path(cls, stable_id: str) -> Path:
        return Path.home() / ".config" / "aether-ghidra" / "indexes" / stable_id / "index.json"

    @classmethod
    def get(cls, metadata: dict[str, Any]) -> FunctionIndex:
        stable_id = cls.stable_id(metadata)
        with cls._lock:
            if stable_id not in cls._cache:
                cls._cache[stable_id] = FunctionIndex.load(cls.path(stable_id)) or FunctionIndex(
                    stable_id=stable_id,
                    program_name=str(metadata.get("name", "")),
                    total_function_count=int(metadata.get("function_count", 0)),
                )
            return cls._cache[stable_id]

    @classmethod
    def save(cls, index: FunctionIndex) -> None:
        with cls._lock:
            cls._cache[index.stable_id] = index
            index.save(cls.path(index.stable_id))

    @classmethod
    def clear(cls, metadata: dict[str, Any]) -> None:
        stable_id = cls.stable_id(metadata)
        with cls._lock:
            cls._cache.pop(stable_id, None)
            path = cls.path(stable_id)
            try:
                path.unlink()
            except FileNotFoundError:
                pass
