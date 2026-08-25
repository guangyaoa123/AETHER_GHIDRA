from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .config import get_context_setting


class TruncationStrategy(Enum):
    FULL = "full"
    METADATA_ONLY = "metadata"
    STATUS_ONLY = "status"
    SUMMARIZED = "summarized"
    DROPPED = "dropped"


TOOL_PRIORITY = {
    "add_memory": "HIGH", "search_memory": "HIGH", "get_function_pseudocode": "MEDIUM",
    "get_data_at_address": "MEDIUM", "list_functions": "LOW",
}


@dataclass
class ToolCallRecord:
    name: str
    arguments: dict[str, Any]
    result: str
    tool_call_id: str = ""
    priority: str = "MEDIUM"
    tokens: int = 0
    strategy: TruncationStrategy = TruncationStrategy.FULL

    def __post_init__(self) -> None:
        if self.priority == "MEDIUM":
            self.priority = TOOL_PRIORITY.get(self.name, "MEDIUM")
        self.tokens = len(str({"name": self.name, "arguments": self.arguments, "result": self.result, "id": self.tool_call_id})) // 4

    def _metadata_summary(self) -> str:
        result = self.result.lower()
        if "function" in result or "class" in result:
            return f"{self.name}: structure examined"
        if "memory" in result and ("stored" in result or "added" in result):
            return f"{self.name}: memory stored"
        if "error" in result or "not found" in result:
            return f"{self.name}: {self.result[:50]}..."
        args = ", ".join(f"{key}={value}" for key, value in list(self.arguments.items())[:3])
        return f"{self.name}({args}) -> {len(self.result)} chars"

    def _status_summary(self) -> str:
        lowered = self.result.lower()
        return f"{self.name}: {'FAILED' if 'error' in lowered or 'not found' in lowered else 'OK'}"

    def get_truncated_content(self) -> str:
        if self.strategy == TruncationStrategy.FULL:
            return self.result
        if self.strategy == TruncationStrategy.METADATA_ONLY:
            return self._metadata_summary()
        if self.strategy == TruncationStrategy.STATUS_ONLY:
            return self._status_summary()
        if self.strategy == TruncationStrategy.SUMMARIZED:
            return f"[{self.name} call]"
        return ""

    def to_message(self) -> dict[str, Any]:
        if self.strategy == TruncationStrategy.DROPPED:
            return {}
        message = {"role": "tool", "content": self.get_truncated_content()}
        if self.tool_call_id:
            message["tool_call_id"] = self.tool_call_id
        return message


@dataclass
class ToolCallGroup:
    tool_name: str
    calls: list[ToolCallRecord] = field(default_factory=list)
    summary: str = ""

    def add(self, record: ToolCallRecord) -> None:
        self.calls.append(record)

    def generate_summary(self) -> str:
        success = sum("error" not in call.result.lower() and "not found" not in call.result.lower() for call in self.calls)
        failed = len(self.calls) - success
        self.summary = f"Previous {len(self.calls)} {self.tool_name} calls: {success} successful" + (f", {failed} failed" if failed else "")
        return self.summary

    def to_message(self) -> dict[str, Any]:
        return {"role": "tool", "content": self.summary or self.generate_summary()}


class ToolOutputBuffer:
    def __init__(self, max_records: int = 100, max_tokens: int = 10_000) -> None:
        self.max_records = get_context_setting("tool_buffer", "max_records", default=max_records)
        self.max_tokens = get_context_setting("tool_buffer", "max_tokens", default=max_tokens)
        self.records: deque[ToolCallRecord] = deque(maxlen=self.max_records)
        self._current_tokens = 0

    @property
    def current_tokens(self) -> int:
        return self._current_tokens

    def add(self, name: str, arguments: dict[str, Any], result: str, tool_call_id: str = "") -> ToolCallRecord:
        if tool_call_id:
            for record in self.records:
                if record.tool_call_id == tool_call_id:
                    self._current_tokens -= record.tokens
                    record.result = str(result)
                    record.__post_init__()
                    self._current_tokens += record.tokens
                    return record
        if len(self.records) >= self.max_records:
            self._current_tokens -= self.records[0].tokens
        record = ToolCallRecord(name, arguments, str(result), tool_call_id)
        self.records.append(record)
        self._current_tokens += record.tokens
        return record

    def get_record_by_id(self, tool_call_id: str) -> ToolCallRecord | None:
        return next((record for record in self.records if record.tool_call_id == tool_call_id), None)

    def get_messages(self) -> list[dict[str, Any]]:
        return [message for record in self.records if (message := record.to_message())]

    def truncate(self, target_tokens: int) -> int:
        initial = self._current_tokens
        self._drop_by_priority("LOW", target_tokens)
        self._drop_by_priority("MEDIUM", target_tokens)
        if self._current_tokens > target_tokens:
            self._summarize_groups(target_tokens)
        if self._current_tokens > target_tokens:
            self._reduce_to_metadata(target_tokens)
        if self._current_tokens > target_tokens:
            self._reduce_to_status(target_tokens)
        if self._current_tokens > target_tokens:
            self._drop_oldest(target_tokens)
        return initial - self._current_tokens

    def _drop_by_priority(self, priority: str, target_tokens: int) -> None:
        for record in list(self.records):
            if self._current_tokens <= target_tokens:
                return
            if record.priority == priority and record.strategy != TruncationStrategy.DROPPED:
                self.records.remove(record)
                self._current_tokens -= record.tokens

    def _summarize_groups(self, target_tokens: int) -> None:
        groups: dict[str, ToolCallGroup] = {}
        for record in self.records:
            if record.strategy == TruncationStrategy.FULL:
                groups.setdefault(record.name, ToolCallGroup(record.name)).add(record)
        for group in sorted(groups.values(), key=lambda item: -len(item.calls)):
            if len(group.calls) < 3:
                continue
            for record in group.calls[:-2]:
                old_tokens = record.tokens
                record.strategy = TruncationStrategy.SUMMARIZED
                record.tokens = 50
                self._current_tokens -= max(0, old_tokens - record.tokens)
            if self._current_tokens <= target_tokens:
                return

    def _reduce_to_metadata(self, target_tokens: int) -> None:
        for record in self.records:
            if self._current_tokens <= target_tokens:
                return
            if record.strategy == TruncationStrategy.FULL:
                old_tokens = record.tokens
                record.strategy = TruncationStrategy.METADATA_ONLY
                record.tokens = len(record._metadata_summary()) // 4
                self._current_tokens -= max(0, old_tokens - record.tokens)

    def _reduce_to_status(self, target_tokens: int) -> None:
        for record in self.records:
            if self._current_tokens <= target_tokens:
                return
            if record.strategy in (TruncationStrategy.FULL, TruncationStrategy.METADATA_ONLY):
                old_tokens = record.tokens
                record.strategy = TruncationStrategy.STATUS_ONLY
                record.tokens = len(record._status_summary()) // 4
                self._current_tokens -= max(0, old_tokens - record.tokens)

    def _drop_oldest(self, target_tokens: int) -> None:
        while self.records and self._current_tokens > target_tokens:
            self._current_tokens -= self.records.popleft().tokens

    def get_statistics(self) -> dict[str, Any]:
        by_priority = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_strategy: dict[str, int] = {}
        for record in self.records:
            by_priority[record.priority] = by_priority.get(record.priority, 0) + 1
            by_strategy[record.strategy.value] = by_strategy.get(record.strategy.value, 0) + 1
        return {"total_records": len(self.records), "total_tokens": self._current_tokens, "by_priority": by_priority, "by_strategy": by_strategy}

    def clear(self) -> None:
        self.records.clear()
        self._current_tokens = 0

    def summary(self) -> str:
        return f"Tool Output Buffer: {len(self.records)} records, {self._current_tokens:,} tokens"
