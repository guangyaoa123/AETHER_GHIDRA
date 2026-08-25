from __future__ import annotations

from dataclasses import dataclass, field


SHARED_RULES_PROMPT = """Follow these rules:
1. Think step-by-step before calling tools.
2. Use available tools deliberately and only when they advance the task.
3. Keep the current plan accurate as work progresses.
4. Use stored memory to preserve important findings and decisions."""
SHARED_MEMORY_PROMPT = "MEMORY: Use memory tools to preserve important findings and decisions."
SHARED_PLANNING_PROMPT = "PLANNING: Keep a current plan while working on multi-step tasks."
SHARED_CONTEXT_PROMPT = "CONTEXT: Use summaries, checkpoint state, memories, and tool-call history to avoid repeated work."
DEFAULT_IDENTITY_PROMPT = "You are a general-purpose autonomous agent."
DEFAULT_CAPABILITY_PROMPT = "Use planning, memory, and configured tools to make progress on the task."


@dataclass(slots=True)
class PromptConfig:
    identity: str = DEFAULT_IDENTITY_PROMPT
    capability: str = DEFAULT_CAPABILITY_PROMPT
    output_format: str = ""
    runtime_appendix: str = ""
    shared_rules: str = SHARED_RULES_PROMPT
    shared_memory: str = SHARED_MEMORY_PROMPT
    shared_planning: str = SHARED_PLANNING_PROMPT
    shared_context: str = SHARED_CONTEXT_PROMPT
    extra_sections: list[str] = field(default_factory=list)


class PromptComposer:
    def compose(self, config: PromptConfig) -> str:
        sections = [
            config.identity, config.shared_rules, config.shared_memory,
            config.shared_planning, config.shared_context, config.capability,
            config.output_format, *config.extra_sections, config.runtime_appendix,
        ]
        return "\n\n".join(section.strip() for section in sections if section and section.strip())
