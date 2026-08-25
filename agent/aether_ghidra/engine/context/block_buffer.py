from __future__ import annotations

import re
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .config import get_context_setting


logger = logging.getLogger(__name__)


@dataclass
class ConversationBlock:
    messages: list[dict[str, Any]] = field(default_factory=list)
    tokens: int = 0
    is_summarized: bool = False
    summary: str | None = None
    has_tool_calls: bool = False
    has_tool_response: bool = False

    def add_message(self, message: dict[str, Any]) -> None:
        self.messages.append(message)
        self.tokens = sum(len(str(item.get("content") or "")) // 4 for item in self.messages)
        self.has_tool_calls |= message.get("role") == "assistant" and bool(message.get("tool_calls"))
        self.has_tool_response |= message.get("role") == "tool"

    def to_message_dicts(self) -> list[dict[str, Any]]:
        if self.is_summarized and self.summary:
            return [{"role": "system", "content": f"[CONVERSATION SUMMARY]\n{self.summary}"}]
        return self.messages

    def get_tool_call_ids(self) -> list[str]:
        return [call.get("id", "") for message in self.messages for call in message.get("tool_calls", []) if isinstance(call, dict)]

    def get_tool_response_ids(self) -> list[str]:
        return [message["tool_call_id"] for message in self.messages if message.get("role") == "tool" and "tool_call_id" in message]

    def summarize(self, summary_text: str) -> None:
        self.summary = summary_text
        self.is_summarized = True
        self.tokens = len(summary_text) // 4 + 20


class BlockBuffer:
    VARIABLE_SUMMARY_THRESHOLD = get_context_setting("block_buffer", "variable_summary_threshold", default=3000)
    SESSION_SUMMARY_TARGET = get_context_setting("block_buffer", "session_summary_target", default=2000)
    SUMMARY_NOTE_TARGET = get_context_setting("block_buffer", "summary_note_target", default=600)

    def __init__(self, max_raw_blocks: int = 10, max_tokens: int = 50_000) -> None:
        self.blocks: deque[ConversationBlock] = deque()
        self.max_raw_blocks = get_context_setting("block_buffer", "max_raw_blocks", default=max_raw_blocks)
        self.max_tokens = get_context_setting("block_buffer", "max_tokens", default=max_tokens)
        self._current_tokens = 0
        self.session_summary = ""
        self.variable_summary = ""
        self.variable_summary_threshold = self.VARIABLE_SUMMARY_THRESHOLD

    @property
    def current_tokens(self) -> int:
        return self._current_tokens

    @property
    def raw_block_count(self) -> int:
        return sum(not block.is_summarized for block in self.blocks)

    @property
    def summarized_block_count(self) -> int:
        return sum(block.is_summarized for block in self.blocks)

    def add_message(self, message: dict[str, Any]) -> None:
        role = message.get("role", "unknown")
        block: ConversationBlock | None = None
        if role in ("assistant", "user") or not self.blocks:
            block = ConversationBlock()
            self.blocks.append(block)
        elif role == "tool":
            block = next((item for item in reversed(self.blocks) if item.has_tool_calls), None)
            if block is None:
                block = ConversationBlock()
                self.blocks.append(block)
        else:
            block = self.blocks[-1]
        before = block.tokens
        block.add_message(message)
        self._current_tokens += block.tokens - before

    def needs_summarization(self) -> bool:
        return self.raw_block_count > self.max_raw_blocks or self._current_tokens > self.max_tokens

    def needs_aggressive_truncation(self) -> bool:
        return self._current_tokens > self.max_tokens * 1.5

    def summarize_oldest_blocks(self, num_blocks: int | None = None, summarizer_agent: Any = None, plan: Any = None) -> int:
        raw_without_tools = [block for block in self.blocks if not block.is_summarized and not block.has_tool_calls and not block.has_tool_response]
        raw_complete = [block for block in self.blocks if not block.is_summarized and block.has_tool_calls and block.has_tool_response]
        raw_blocks = raw_without_tools or raw_complete
        if not raw_blocks:
            return 0
        requested = min(5, len(raw_blocks)) if num_blocks is None else num_blocks
        count = min(requested, max(0, len(raw_blocks) - min(3, len(raw_blocks))))
        if count <= 0:
            return 0
        selected = raw_blocks[:count]
        if summarizer_agent and count >= 3:
            summary_text = summarizer_agent.summarize_blocks(selected, plan=plan).chronological_summary
        else:
            summary_text = "\n".join(self._generate_summary(block) for block in selected)
        for block in selected:
            self.blocks.remove(block)
        self._current_tokens = sum(block.tokens for block in self.blocks)
        self.add_to_variable_summary(summary_text, summarizer_agent=summarizer_agent)
        logger.debug("summarized blocks=%s summary_chars=%s remaining_blocks=%s", count, len(summary_text), len(self.blocks))
        return count

    def add_to_variable_summary(self, summary_text: str, summarizer_agent: Any = None) -> bool:
        self.variable_summary = f"{self.variable_summary}\n\n{summary_text}".strip() if self.variable_summary else summary_text
        if len(self.variable_summary) >= self.variable_summary_threshold and summarizer_agent:
            logger.debug("merging variable summary chars=%s into session summary", len(self.variable_summary))
            self.merge_variable_into_session(summarizer_agent)
            return True
        return False

    def merge_variable_into_session(self, summarizer_agent: Any) -> None:
        if not self.variable_summary:
            return
        consolidated = summarizer_agent.meta_summarize(
            self.session_summary,
            self.variable_summary,
            target_length=self.SESSION_SUMMARY_TARGET,
        )
        self.session_summary = consolidated
        self.variable_summary = ""

    def get_session_summary(self) -> str:
        return self.session_summary

    def get_variable_summary(self) -> str:
        return self.variable_summary

    def get_combined_summary(self) -> str:
        return "\n\n".join(
            part for part in (
                f"Session Summary:\n{self.session_summary}" if self.session_summary else "",
                f"Variable Summary:\n{self.variable_summary}" if self.variable_summary else "",
            ) if part
        )

    def clear_summaries(self) -> None:
        self.session_summary = ""
        self.variable_summary = ""

    def drop_oldest_blocks(self, num_blocks: int = 1) -> int:
        freed = 0
        for _ in range(min(num_blocks, len(self.blocks))):
            block = self.blocks.popleft()
            freed += block.tokens
        self._current_tokens -= freed
        return freed

    def truncate_to_budget(self, target_tokens: int | None = None) -> int:
        limit = self.max_tokens if target_tokens is None else target_tokens
        freed = 0
        for block in list(self.blocks):
            if block.is_summarized:
                continue
            old_tokens = block.tokens
            block.summarize(self._generate_summary(block))
            freed += old_tokens - block.tokens
        self._current_tokens = sum(block.tokens for block in self.blocks)
        while self._current_tokens > limit and len(self.blocks) > 3:
            freed += self.drop_oldest_blocks(1)
        return freed

    def _generate_summary(self, block: ConversationBlock) -> str:
        tools: list[str] = []
        user_notes: list[str] = []
        assistant_notes: list[str] = []
        evidence: list[str] = []
        for message in block.messages:
            role = message.get("role")
            calls = message.get("tool_calls") or []
            if role == "assistant" and calls:
                for call in calls:
                    function = call.get("function", {}) if isinstance(call, dict) else getattr(call, "function", None)
                    tools.append(function.get("name", "unknown") if isinstance(function, dict) else getattr(function, "name", "unknown"))
            content = str(message.get("content") or "")
            if not content or len(content) <= 20:
                continue
            if role == "user":
                user_notes.append(self._summarize_text_for_cap(content, "user message"))
            elif role == "assistant" and not calls:
                assistant_notes.append(self._summarize_text_for_cap(content, "assistant response"))
            elif role == "tool":
                note = self._summarize_tool_content(content)
                if note:
                    evidence.append(note)
        sentences = []
        if user_notes:
            sentences.append(f"The discussion focused on {self._join_notes(user_notes)}.")
        if tools:
            sentences.append(f"Evidence was gathered with {', '.join(dict.fromkeys(tools))}.")
        if evidence:
            sentences.append(f"The retrieved evidence showed {self._join_notes(evidence)}.")
        if assistant_notes:
            sentences.append(f"The analysis concluded that {self._join_notes(assistant_notes)}.")
        return " ".join(sentences) or f"[{len(block.messages)} messages in block]"

    def _summarize_tool_content(self, content: str) -> str:
        if "Found" in content:
            match = re.search(r"Found (\d+) file", content)
            return f"{match.group(1)} file(s) matched the query" if match else self._summarize_text_for_cap(content, "tool result")
        if "stored" in content.lower() or "Memory stored" in content:
            match = re.search(r"ID: ([a-f0-9-]+)", content)
            return f"a memory item was stored ({match.group(1)[:8]}...)" if match else self._summarize_text_for_cap(content, "tool result")
        return self._summarize_text_for_cap(content, "tool result")

    @staticmethod
    def _normalize_text(text: str) -> str:
        return re.sub(r"\s+", " ", text).strip()

    def _summarize_text_for_cap(self, text: str, label: str) -> str:
        normalized = self._normalize_text(text)
        if len(normalized) <= self.SUMMARY_NOTE_TARGET:
            return normalized
        identifiers = self._extract_summary_identifiers(normalized)
        return f"a long {label} ({len(normalized)} chars)" + (f" mentioning {', '.join(identifiers)}" if identifiers else "")

    @staticmethod
    def _extract_summary_identifiers(text: str, limit: int = 12) -> list[str]:
        candidates = [value for groups in re.findall(r"`([^`]{1,80})`|'([^']{1,80})'|\"([^\"]{1,80})\"", text) for value in groups if value]
        candidates += re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b", text)
        stopwords = {"this", "that", "with", "from", "have", "function", "analysis", "message", "assistant", "response", "content", "summary"}
        result: list[str] = []
        for candidate in candidates:
            if candidate and candidate.lower() not in stopwords and candidate not in result:
                result.append(candidate)
            if len(result) >= limit:
                break
        return result

    @staticmethod
    def _join_notes(notes: list[str]) -> str:
        unique = list(dict.fromkeys(note for note in notes if note))
        return unique[0] if len(unique) == 1 else "; ".join(unique)

    def get_messages(self) -> list[dict[str, Any]]:
        return [message for block in self.blocks for message in block.to_message_dicts()]

    def get_consolidated_summary(self) -> str:
        return self.get_combined_summary()

    def get_summarized_conversation_history(self) -> list[dict[str, Any]]:
        result = []
        if self.get_combined_summary():
            result.append({"role": "system", "content": f"[CONVERSATION SUMMARY]\n{self.get_combined_summary()}"})
        for block in self.blocks:
            result.extend(block.to_message_dicts())
        return result

    def get_statistics(self) -> dict[str, Any]:
        return {
            "total_blocks": len(self.blocks), "raw_blocks": self.raw_block_count,
            "summarized_blocks": self.summarized_block_count, "total_tokens": self._current_tokens,
            "avg_tokens_per_block": self._current_tokens / len(self.blocks) if self.blocks else 0,
        }

    def clear(self) -> None:
        self.blocks.clear()
        self._current_tokens = 0
