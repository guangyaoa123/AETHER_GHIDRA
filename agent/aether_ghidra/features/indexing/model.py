from __future__ import annotations

import base64
import json
import os
import tempfile
import time
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .taxonomy import DynamicTagManager, importance_at_or_above


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class BatchMetadata:
    indexed_functions: int = 0
    total_batches: int = 0
    completed_batches: int = 0
    current_batch: int = 0
    phase: str = "PENDING"
    decompiled_count: int = 0
    decompile_skip_count: int = 0
    decompile_fail_count: int = 0
    current_function_address: str | None = None
    current_function_name: str | None = None
    start_time: int = 0
    last_update_time: int = 0
    last_error: str | None = None
    batch_token_counts: list[int] = field(default_factory=list)

    @property
    def total_tokens(self) -> int:
        return sum(self.batch_token_counts)


@dataclass
class FunctionEntry:
    name: str
    address: str
    tags: set[str] = field(default_factory=set)
    summary: str = ""
    called_functions: list[Any] = field(default_factory=list)
    caller_functions: list[Any] = field(default_factory=list)
    key_operations: list[str] = field(default_factory=list)
    key_constants: list[str] = field(default_factory=list)

    def importance(self) -> str | None:
        return next((tag for tag in self.tags if tag in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"}), None)

    def searchable(self) -> str:
        return " ".join([
            self.name, self.summary, *self.tags,
            *(json.dumps(value, sort_keys=True, default=str) if isinstance(value, dict) else str(value)
              for value in [*self.called_functions, *self.caller_functions]),
            *self.key_operations, *self.key_constants,
        ])

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "address": self.address,
            "tags": sorted(self.tags),
            "summary": self.summary,
            "called_functions": list(self.called_functions),
            "caller_functions": list(self.caller_functions),
            "key_operations": list(self.key_operations),
            "key_constants": list(self.key_constants),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "FunctionEntry":
        return cls(
            name=str(value.get("name", "")),
            address=str(value.get("address", "")),
            tags=set(value.get("tags", [])),
            summary=str(value.get("summary", "")),
            # Version-one indexes called this deterministic outgoing edge list
            # "callee_functions" and stored model-supplied API names separately.
            called_functions=list(value.get("called_functions") or value.get("callee_functions", [])),
            caller_functions=list(value.get("caller_functions", [])),
            key_operations=list(value.get("key_operations", [])),
            key_constants=list(value.get("key_constants", [])),
        )


@dataclass
class FunctionIndex:
    index_version: int = 2
    stable_id: str = ""
    program_name: str = ""
    timestamp: int = field(default_factory=now_ms)
    indexed: bool = False
    indexing_state: str = "PENDING"
    total_function_count: int = 0
    indexing_progress: int = 0
    total_tokens_used: int = 0
    last_indexed_address: str | None = None
    entries_by_address: dict[str, FunctionEntry] = field(default_factory=dict)
    batch_metadata: BatchMetadata = field(default_factory=BatchMetadata)
    dynamic_tags: dict[str, dict[str, Any]] = field(default_factory=dict)
    pseudocode_cache: dict[str, str] = field(default_factory=dict)
    decompile_blacklist: dict[str, dict[str, str]] = field(default_factory=dict)
    llm_failed_entries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def size(self) -> int:
        return len(self.entries_by_address)

    def is_usable(self) -> bool:
        return bool(self.entries_by_address) and self.indexing_state in {"COMPLETED", "IN_PROGRESS", "PARTIAL", "PAUSED"}

    def is_resumable(self) -> bool:
        return self.indexing_state in {"IN_PROGRESS", "PARTIAL", "FAILED", "PAUSED"}

    def add_entry(self, entry: FunctionEntry) -> None:
        self.entries_by_address[entry.address] = entry
        self.llm_failed_entries.pop(entry.address, None)

    def cache_pseudocode(self, address: str, code: str) -> None:
        self.pseudocode_cache[address] = base64.b64encode(zlib.compress(code.encode("utf-8"), 6)).decode("ascii")

    def cached_pseudocode(self, address: str) -> str | None:
        encoded = self.pseudocode_cache.get(address)
        if not encoded:
            return None
        try:
            return zlib.decompress(base64.b64decode(encoded)).decode("utf-8")
        except (ValueError, zlib.error, UnicodeDecodeError):
            return None

    def entries_by_importance(self, minimum: str) -> list[FunctionEntry]:
        return [entry for entry in self.entries_by_address.values() if entry.importance() and importance_at_or_above(entry.importance() or "", minimum)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "index_version": self.index_version,
            "stable_id": self.stable_id,
            "program_name": self.program_name,
            "timestamp": self.timestamp,
            "indexed": self.indexed,
            "indexing_state": self.indexing_state,
            "total_function_count": self.total_function_count,
            "indexed_function_count": self.size(),
            "indexing_progress": self.indexing_progress,
            "total_tokens_used": self.total_tokens_used,
            "last_indexed_address": self.last_indexed_address,
            "batch_metadata": asdict(self.batch_metadata),
            "dynamic_tags": self.dynamic_tags,
            "pseudocode_cache": self.pseudocode_cache,
            "decompile_blacklist": self.decompile_blacklist,
            "llm_failed_entries": self.llm_failed_entries,
            "functions": [entry.to_dict() for entry in self.entries_by_address.values()],
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        fd, temporary = tempfile.mkstemp(prefix="index-", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @classmethod
    def load(cls, path: Path) -> "FunctionIndex | None":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return None
        index = cls(
            index_version=max(2, int(data.get("index_version", 1))),
            stable_id=str(data.get("stable_id", data.get("sha256", ""))),
            program_name=str(data.get("program_name", "")),
            timestamp=int(data.get("timestamp", now_ms())),
            indexed=bool(data.get("indexed", False)),
            indexing_state=str(data.get("indexing_state", "PENDING")),
            total_function_count=int(data.get("total_function_count", 0)),
            indexing_progress=int(data.get("indexing_progress", 0)),
            total_tokens_used=int(data.get("total_tokens_used", 0)),
            last_indexed_address=data.get("last_indexed_address"),
            dynamic_tags=dict(data.get("dynamic_tags", {})),
            pseudocode_cache=dict(data.get("pseudocode_cache", {})),
            decompile_blacklist=dict(data.get("decompile_blacklist", {})),
            llm_failed_entries=dict(data.get("llm_failed_entries", {})),
        )
        index.entries_by_address = {
            entry.address: entry for entry in (FunctionEntry.from_dict(item) for item in data.get("functions", []))
        }
        index.batch_metadata = BatchMetadata(**{
            key: value for key, value in dict(data.get("batch_metadata", {})).items()
            if key in BatchMetadata.__dataclass_fields__
        })
        return index
