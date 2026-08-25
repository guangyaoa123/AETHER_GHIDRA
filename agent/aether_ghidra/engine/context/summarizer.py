from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .config import get_context_setting


@dataclass
class ConversationTurn:
    role: str
    content: str
    tokens: int = 0
    summary: str | None = None
    is_summary: bool = False
    tool_call_id: str | None = None

    def __post_init__(self) -> None:
        if self.tokens == 0:
            self.tokens = len(self.content) // 4

    def to_message(self) -> dict[str, Any]:
        message = {"role": self.role, "content": self.summary if self.is_summary and self.summary else self.content}
        if self.role == "tool" and self.tool_call_id:
            message["tool_call_id"] = self.tool_call_id
        return message

    def summarize(self, summary_text: str) -> None:
        self.summary = summary_text
        self.is_summary = True
        self.tokens = len(summary_text) // 4


@dataclass
class ConversationSummary:
    turn_range: tuple[int, int]
    summary: str
    tokens: int = 0
    key_findings: list[str] = field(default_factory=list)
    tool_calls_made: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.tokens = len(self.summary) // 4

    def to_message(self) -> dict[str, Any]:
        return {"role": "system", "content": self.summary}


class ConversationSummarizer:
    SUMMARY_PREFIX = """[CONVERSATION SUMMARY]
This summarizes previous conversation turns to save space.
Key findings and decisions are preserved below.

"""

    def __init__(self, keep_raw_turns: int = 10, max_summary_tokens: int = 500) -> None:
        self.keep_raw_turns = get_context_setting("summarizer", "keep_raw_turns", default=keep_raw_turns)
        self.max_summary_tokens = get_context_setting("summarizer", "max_summary_tokens", default=max_summary_tokens)
        self._summaries: deque[ConversationSummary] = deque(maxlen=5)

    def summarize_turns(self, turns: list[ConversationTurn], llm_client: Any = None) -> ConversationSummary:
        if not turns:
            return ConversationSummary((0, 0), "[No conversation to summarize]")
        tool_calls: list[str] = []
        key_findings: list[str] = []
        for turn in turns:
            if turn.role == "tool":
                tool_name = self._extract_tool_name(turn.content)
                if tool_name:
                    tool_calls.append(tool_name)
                if self._is_finding(turn.content):
                    key_findings.append(turn.content)
        summary = self._llm_summarize(turns, llm_client) if llm_client else self._keyword_summarize(turns, tool_calls, key_findings)
        return ConversationSummary((0, len(turns)), self.SUMMARY_PREFIX + summary, key_findings=key_findings, tool_calls_made=tool_calls)

    @staticmethod
    def _extract_tool_name(content: str) -> str | None:
        if "Found" in content and "file" in content.lower():
            return "list_files"
        if "Function" in content or "function" in content.lower():
            return "get_function_content"
        if "Memory stored" in content:
            return "add_memory"
        if "Found" in content and "relevant" in content.lower():
            return "search_memories"
        if "File:" in content:
            return "get_file_summary"
        return None

    @staticmethod
    def _is_finding(content: str) -> bool:
        return any(keyword in content.lower() for keyword in (
            "stored", "identified", "found", "detected", "suspicious", "malicious",
            "credential", "persistence", "exfil", "injection",
        ))

    def _llm_summarize(self, turns: list[ConversationTurn], llm_client: Any) -> str:
        prompt = f"""Summarize the following conversation turns, focusing on:
1. What analysis was performed
2. Key findings discovered
3. Tools used and their results
4. Any decisions or conclusions reached

Aim to keep the summary under {self.max_summary_tokens} tokens. Do not cut off
text mid-sentence; rewrite/compress naturally instead.

Conversation:
{' '.join(f'{turn.role}: {turn.content}' for turn in turns)}

Summary:"""
        try:
            return llm_client.complete(prompt)
        except Exception:
            return self._keyword_summarize(turns, [], [])

    @staticmethod
    def _keyword_summarize(turns: list[ConversationTurn], tool_calls: list[str], key_findings: list[str]) -> str:
        lines = [f"Analyzed {len(turns)} conversation turns."]
        counts: dict[str, int] = {}
        for tool in tool_calls:
            counts[tool] = counts.get(tool, 0) + 1
        if counts:
            lines.append("Tools used: " + ", ".join(f"{count}x {name}" for name, count in counts.items()) + ".")
        if key_findings:
            lines.append("Key findings:")
            lines.extend(f"  - {finding}" for finding in key_findings)
        if not counts and not key_findings:
            lines.append("No significant findings in this section.")
        return "\n".join(lines)

    def apply_sliding_window(self, turns: list[ConversationTurn], target_tokens: int | None = None) -> list[ConversationTurn]:
        if len(turns) <= self.keep_raw_turns:
            return turns
        summary = self.summarize_turns(turns[:-self.keep_raw_turns])
        return [ConversationTurn("system", summary.summary, is_summary=True), *turns[-self.keep_raw_turns:]]

    def compress_to_budget(self, turns: list[ConversationTurn], budget_tokens: int) -> list[ConversationTurn]:
        if sum(turn.tokens for turn in turns) <= budget_tokens:
            return turns
        result = self.apply_sliding_window(turns)
        if sum(turn.tokens for turn in result) <= budget_tokens:
            return result
        for window_size in (8, 6, 4, 2):
            if len(turns) > window_size:
                summary = self.summarize_turns(turns[:-window_size])
                result = [ConversationTurn("system", summary.summary, is_summary=True), *turns[-window_size:]]
            if sum(turn.tokens for turn in result) <= budget_tokens:
                return result
        return turns[-max(1, budget_tokens // 500):]

    def get_statistics(self, turns: list[ConversationTurn]) -> dict[str, Any]:
        total = sum(turn.tokens for turn in turns)
        summaries = sum(turn.is_summary for turn in turns)
        by_role: dict[str, int] = {}
        for turn in turns:
            by_role[turn.role] = by_role.get(turn.role, 0) + 1
        return {
            "total_turns": len(turns), "total_tokens": total, "summary_turns": summaries,
            "raw_turns": len(turns) - summaries, "by_role": by_role,
            "avg_tokens_per_turn": total / len(turns) if turns else 0,
        }

    def summary(self, turns: list[ConversationTurn]) -> str:
        stats = self.get_statistics(turns)
        return "\n".join([
            f"Conversation: {stats['total_turns']} turns, {stats['total_tokens']:,} tokens",
            f"  Raw turns: {stats['raw_turns']}",
            f"  Summarized: {stats['summary_turns']}",
            f"  Avg tokens/turn: {stats['avg_tokens_per_turn']:.0f}",
        ] + (["  By role:"] + [f"    {role}: {count}" for role, count in stats["by_role"].items()] if stats["by_role"] else []))
