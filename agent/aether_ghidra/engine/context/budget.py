from __future__ import annotations

from dataclasses import dataclass, field

from .config import get_context_setting


@dataclass
class ContextBudget:
    max_tokens: int = 128_000
    system_reserve: int = 2_000
    summary_reserve: int = 3_000
    memories_reserve: int = 5_000
    tool_buffer_reserve: int = 10_000
    summarize_trigger: float = 0.60
    truncate_trigger: float = 0.70
    hard_limit: float = 0.80
    _current_usage: int = field(default=0, init=False)
    _section_usage: dict[str, int] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.max_tokens = get_context_setting("budget", "max_tokens", default=self.max_tokens)
        self.system_reserve = get_context_setting("budget", "system_reserve", default=self.system_reserve)
        self.summary_reserve = get_context_setting("budget", "summary_reserve", default=self.summary_reserve)
        self.memories_reserve = get_context_setting("budget", "memories_reserve", default=self.memories_reserve)
        self.tool_buffer_reserve = get_context_setting("budget", "tool_buffer_reserve", default=self.tool_buffer_reserve)
        self.summarize_trigger = get_context_setting("budget", "summarize_trigger", default=self.summarize_trigger)
        self.truncate_trigger = get_context_setting("budget", "truncate_trigger", default=self.truncate_trigger)
        self.hard_limit = get_context_setting("budget", "hard_limit", default=self.hard_limit)

    @property
    def working_buffer(self) -> int:
        return self.max_tokens - self.allocated_tokens

    @property
    def allocated_tokens(self) -> int:
        return self.system_reserve + self.summary_reserve + self.memories_reserve + self.tool_buffer_reserve

    @property
    def current_usage(self) -> int: return self._current_usage
    @property
    def usage_ratio(self) -> float: return self._current_usage / self.max_tokens if self.max_tokens else 0.0
    @property
    def available_tokens(self) -> int: return max(0, self.max_tokens - self._current_usage)

    def update_usage(self, system_tokens: int, summary_tokens: int, memories_tokens: int, tool_buffer_tokens: int, conversation_tokens: int = 0) -> None:
        self._section_usage = {"system": system_tokens, "summary": summary_tokens, "memories": memories_tokens, "tool_buffer": tool_buffer_tokens, "conversation": conversation_tokens}
        self._current_usage = sum(self._section_usage.values())

    def needs_summarization(self) -> bool: return self.usage_ratio >= self.summarize_trigger
    def needs_truncation(self) -> bool: return self.usage_ratio >= self.truncate_trigger
    def at_hard_limit(self) -> bool: return self.usage_ratio >= self.hard_limit

    def get_section_usage(self, section: str) -> int: return self._section_usage.get(section, 0)

    def get_section_budget(self, section: str) -> int:
        return {"system": self.system_reserve, "summary": self.summary_reserve, "memories": self.memories_reserve, "tool_buffer": self.tool_buffer_reserve, "working": self.working_buffer}.get(section, 0)

    def get_target_tokens(self, section: str) -> int:
        budget = self.get_section_budget(section)
        ratio = 0.5 if self.at_hard_limit() else 0.75 if self.needs_truncation() else 0.9 if self.needs_summarization() else 1.0
        return max(int(budget * ratio), 100) if ratio < 1 else budget

    def reset(self) -> None:
        self._current_usage, self._section_usage = 0, {}

    def summary(self) -> str:
        return f"Context Budget: {self.current_usage:,} / {self.max_tokens:,} tokens ({self.usage_ratio:.1%})"
