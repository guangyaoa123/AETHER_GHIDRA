from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
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
    def job_path(cls, stable_id: str) -> Path:
        return cls.path(stable_id).with_name("job.json")

    @classmethod
    def save_job(cls, stable_id: str, payload: dict[str, object]) -> None:
        path = cls.job_path(stable_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps({**payload, "updated_at": int(time.time() * 1000)}, indent=2)
        fd, temporary = tempfile.mkstemp(prefix="job-", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(data)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @classmethod
    def load_job(cls, job_id: str) -> dict[str, object] | None:
        root = Path.home() / ".config" / "aether-ghidra" / "indexes"
        try:
            paths = root.glob("*/job.json")
        except OSError:
            return None
        for path in paths:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict) and str(payload.get("job_id", "")) == job_id:
                return payload
        return None

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
