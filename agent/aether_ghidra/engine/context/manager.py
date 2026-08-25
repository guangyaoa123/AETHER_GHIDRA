from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ..planning.prompts import format_plan_for_prompt
from .block_buffer import BlockBuffer
from .budget import ContextBudget
from .summarizer import ConversationSummarizer, ConversationTurn
from .tool_buffer import ToolOutputBuffer

logger = logging.getLogger(__name__)


@dataclass
class PromptSections:
    system: int = 0
    summary: int = 0
    checkpoint: int = 0
    memories: int = 0
    tool_buffer: int = 0
    conversation: int = 0
    current_query: int = 0

    @property
    def total(self) -> int:
        return self.system + self.summary + self.checkpoint + self.memories + self.tool_buffer + self.conversation + self.current_query

    @property
    def cache_stable(self) -> int:
        return self.system + self.summary + self.checkpoint

    @property
    def cache_volatile(self) -> int:
        return self.total - self.cache_stable


@dataclass
class AssembledPrompt:
    messages: list[dict[str, Any]]
    conversation_history: list[dict[str, Any]]


class ContextManager:
    def __init__(self, budget: ContextBudget | None = None, memory_store: Any = None, tool_buffer: ToolOutputBuffer | None = None, block_buffer: BlockBuffer | None = None, explorer: Any = None, summarizer_agent: Any = None) -> None:
        self.budget = budget or ContextBudget()
        self.memory_store = memory_store
        self.tool_buffer = tool_buffer or ToolOutputBuffer(max_tokens=self.budget.tool_buffer_reserve)
        self.block_buffer = block_buffer or BlockBuffer(max_tokens=max(100, int(self.budget.working_buffer * 0.5)))
        self.explorer = explorer
        self.summarizer_agent = summarizer_agent
        self.summarizer = ConversationSummarizer()
        self._plan_manager = None
        self._session_summary = ""
        self._checkpoint_summary = ""
        self._current_sections = PromptSections()
        self._files_analyzed: set[str] = set()
        self._agent_state_provider = None

    def set_plan_manager(self, plan_manager: Any) -> None:
        self._plan_manager = plan_manager

    def set_agent_state_provider(self, provider: Any) -> None:
        self._agent_state_provider = provider

    def set_session_summary(self, summary: str) -> None:
        self._session_summary = summary

    def set_checkpoint_summary(self, summary: str) -> None:
        self._checkpoint_summary = summary

    def mark_file_analyzed(self, path: str) -> None:
        self._files_analyzed.add(path)

    def get_files_analyzed(self) -> set[str]:
        return self._files_analyzed.copy()

    def add_tool_result(self, name: str, arguments: dict[str, Any], result: str, tool_call_id: str = "") -> None:
        self.tool_buffer.add(name, arguments, result, tool_call_id)

    def assemble_prompt(self, system_prompt: str, conversation_history: list[dict[str, Any]], checkpoint: Any = None, current_task: str = "", relevant_memories: list[Any] | None = None, plan: Any = None) -> AssembledPrompt:
        sections = PromptSections(system=len(system_prompt) // 4)
        system_sections = [system_prompt]
        if self._session_summary:
            system_sections.append(f"[SESSION SUMMARY]\n{self._session_summary}")
            sections.summary = len(self._session_summary) // 4 + 20
        if checkpoint:
            content = str(checkpoint.summary()) if hasattr(checkpoint, "summary") else str(checkpoint)
            system_sections.append(f"[CHECKPOINT]\n{content}")
            sections.checkpoint = len(content) // 4 + 20
        plan = plan or (self._plan_manager.active_plan if self._plan_manager else None)
        if plan:
            plan_content = format_plan_for_prompt(plan)
            if plan_content:
                system_sections.append(plan_content)
        if self._agent_state_provider is not None:
            try:
                state = self._agent_state_provider()
                if state:
                    system_sections.append(state)
            except Exception:
                logger.debug("Could not render agent state", exc_info=True)
        if self.explorer:
            system_sections.append(self._format_files_section())

        memories = relevant_memories
        if memories is None and self.memory_store and current_task:
            memories = self.memory_store.search_memories(current_task, top_k=5)
        if memories:
            content = self._format_memories(memories)
            system_sections.append(f"[RELEVANT FINDINGS]\n{content}")
            sections.memories = len(content) // 4 + 20

        self.block_buffer.clear()
        for message in conversation_history:
            if message.get("role") == "system" and "[CONVERSATION SUMMARY]" in str(message.get("content", "")):
                continue
            if message.get("role") == "tool" and message.get("tool_call_id"):
                record = self.tool_buffer.get_record_by_id(message["tool_call_id"])
                if record:
                    message = dict(message)
                    message["content"] = record.get_truncated_content()
            self.block_buffer.add_message(message)

        if self.budget.at_hard_limit() or self.block_buffer.needs_aggressive_truncation():
            self.block_buffer.truncate_to_budget(self.budget.get_target_tokens("working"))
        elif self.block_buffer.needs_summarization():
            self.block_buffer.summarize_oldest_blocks(summarizer_agent=self.summarizer_agent, plan=plan)

        history = self.block_buffer.get_summarized_conversation_history()
        conversation_messages = []
        for message in history:
            if message.get("role") == "system":
                if message.get("content"):
                    system_sections.append(message["content"])
            else:
                conversation_messages.append(message)
        messages = [{"role": "system", "content": "\n\n".join(system_sections)}, *conversation_messages]
        sections.tool_buffer = self.tool_buffer.current_tokens
        sections.conversation = self.block_buffer.current_tokens
        if current_task:
            messages.append({"role": "user", "content": current_task})
            sections.current_query = len(current_task) // 4
        self._current_sections = sections
        self.budget.update_usage(sections.system, sections.summary, sections.memories, sections.tool_buffer, sections.conversation + sections.current_query)
        return AssembledPrompt(messages, history)

    def summarize_conversation_history(self, conversation_history: list[dict[str, Any]], *, fallback_summary: str = "", preserve_recent_blocks: int = 2, summarizer_agent: Any = None, plan: Any = None) -> list[dict[str, Any]]:
        self.block_buffer.clear()
        for message in conversation_history:
            self.block_buffer.add_message(message)
        blocks = list(self.block_buffer.blocks)
        keep_count = max(0, min(preserve_recent_blocks, len(blocks)))
        blocks_to_summarize = blocks[:-keep_count] if keep_count else blocks
        blocks_to_keep = blocks[-keep_count:] if keep_count else []
        summary_text = ""
        if blocks_to_summarize:
            if summarizer_agent is not None:
                summary_text = summarizer_agent.summarize_blocks(blocks_to_summarize, plan=plan).chronological_summary
            else:
                turns = [
                    ConversationTurn(message.get("role", "unknown"), str(message.get("content") or ""), tool_call_id=message.get("tool_call_id"))
                    for block in blocks_to_summarize
                    for message in block.messages
                ]
                summary_text = self.summarizer.summarize_turns(turns).summary
        if not summary_text:
            summary_text = fallback_summary
        self.block_buffer.clear()
        if summary_text:
            self.block_buffer.add_to_variable_summary(summary_text, summarizer_agent=summarizer_agent)
        for block in blocks_to_keep:
            for message in block.messages:
                self.block_buffer.add_message(message)
        return self.block_buffer.get_summarized_conversation_history()

    def needs_truncation(self) -> bool:
        return self.budget.needs_truncation()

    def needs_summarization(self) -> bool:
        return self.budget.needs_summarization()

    def truncate(self, target_tokens: int | None = None) -> int:
        return self.tool_buffer.truncate(target_tokens or self.budget.get_target_tokens("tool_buffer"))

    def truncate_to_plan_boundary(self) -> int:
        return self.truncate(self.budget.tool_buffer_reserve // 4)

    def on_plan_completed(self, plan: Any = None) -> int:
        return self.truncate_to_plan_boundary()

    def _format_memories(self, memories: list[Any]) -> str:
        lines = ["Retrieved findings:"]
        for index, item in enumerate(memories[:5], 1):
            memory = item.memory if hasattr(item, "memory") else item
            content = memory.get_display_content() if hasattr(memory, "get_display_content") else str(memory)
            lines.append(f"  {index}. [{getattr(memory, 'category', '?')}] {content[:100]}...")
        return "\n".join(lines)

    def _format_files_section(self) -> str:
        if not self.explorer:
            return ""
        files = set(self.explorer.list_files())
        remaining = sorted(files - self._files_analyzed)
        return "\n".join([
            "[FILES]",
            f"Examined: {len(self._files_analyzed)}/{len(files)} files ({len(self._files_analyzed) * 100 // len(files) if files else 0}%)",
            f"Remaining: {len(remaining)} files",
            *(f"  - {path}" for path in remaining[:5]),
        ])

    def get_statistics(self) -> dict[str, Any]:
        return {
            "budget": {"total": self.budget.max_tokens, "current": self.budget.current_usage, "ratio": self.budget.usage_ratio},
            "sections": {
                "system": self._current_sections.system, "summary": self._current_sections.summary,
                "checkpoint": self._current_sections.checkpoint, "memories": self._current_sections.memories,
                "tool_buffer": self._current_sections.tool_buffer, "conversation": self._current_sections.conversation,
                "current_query": self._current_sections.current_query, "total": self._current_sections.total,
                "cache_stable": self._current_sections.cache_stable, "cache_volatile": self._current_sections.cache_volatile,
            },
            "tool_buffer": self.tool_buffer.get_statistics(),
            "block_buffer": self.block_buffer.get_statistics(),
        }

    def summary(self) -> str:
        stats = self.get_statistics()
        return f"Context Manager Status:\n{self.budget.summary()}\n\nBlock Buffer:\n{stats['block_buffer']}"

    def reset(self) -> None:
        self._session_summary = ""
        self._checkpoint_summary = ""
        self._current_sections = PromptSections()
        self.tool_buffer.clear()
        self.block_buffer.clear()
        self.budget.reset()
