from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from .config import get_context_setting
from ...observability.conversation_logging import ConversationLogger

logger = logging.getLogger(__name__)


@dataclass
class SummarizedBlock:
    tool_name: str
    tool_args: str
    result_summary: str
    key_finding: str | None = None
    memory_category: str | None = None
    memory_priority: str | None = None


@dataclass
class BatchSummary:
    summary_by_action: list[dict[str, Any]]
    chronological_summary: str
    key_findings: list[dict[str, Any]]
    files_examined: list[str]
    total_blocks: int


class SummarizerAgent:
    SYSTEM_PROMPT = """You are a conversation summarizer for a reverse engineering agent.

Summarize tool calls and results as concise chronological analysis notes. Return
only JSON in this format:
{"chronological_summary": ["what was analyzed and discovered"],
 "key_findings": [{"key": "stable_key", "value": "finding", "category": "behavior", "priority": "HIGH"}],
 "files_examined": []}

Focus on discoveries, evidence, decisions, and concrete function/address names,
not a raw tool-call listing."""
    META_SYSTEM_PROMPT = """You consolidate two reverse-engineering session summaries.
Return only JSON: {"consolidated_session_summary": "..."}.
Deduplicate information, preserve unique technical details, and state what was
done, discovered, and what should happen next."""

    def __init__(self, api_key: str, memory_store: Any = None, model: str = "gpt-4.1-mini", base_url: str | None = None, client: Any = None) -> None:
        self.api_key = api_key
        self.memory_store = memory_store
        self.model = model
        self.summary_target_chars = get_context_setting("summarizer", "max_summary_tokens", default=3000) * 4
        self.conversation_logger = ConversationLogger()
        if client is not None:
            self.client = client
            return
        from openai import OpenAI
        self.client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)

    def summarize_blocks(self, blocks: list[Any], plan: Any = None) -> BatchSummary:
        summary_json = self._call_llm(self._blocks_to_input(blocks), plan)
        return self._parse_summary(summary_json)

    def meta_summarize(self, session_summary: str, variable_summary: str, target_length: int = 3500) -> str:
        content = (
            f"SESSION SUMMARY ({len(session_summary)} chars):\n{session_summary or '(empty)'}\n\n"
            f"VARIABLE SUMMARY ({len(variable_summary)} chars):\n{variable_summary}\n\n"
            f"TARGET LENGTH: {target_length} characters\n"
            "Consolidate these into one deduplicated summary without cutting off sentences."
        )
        try:
            request = {
                "model": self.model,
                "messages": [{"role": "system", "content": self.META_SYSTEM_PROMPT}, {"role": "user", "content": content}],
                "temperature": 0.3,
            }
            response = self.client.chat.completions.create(**request)
            self.conversation_logger.record_completion("summarizer", request, response)
            message = response.choices[0].message if response and response.choices else None
            text = getattr(message, "content", "") if message else ""
            return self._parse_meta_summary(text) if text else self._fallback_meta_summary(session_summary, variable_summary)
        except Exception:
            return self._fallback_meta_summary(session_summary, variable_summary)

    def _blocks_to_input(self, blocks: list[Any]) -> list[dict[str, Any]]:
        result = []
        for index, block in enumerate(blocks):
            item: dict[str, Any] = {"block_index": index, "tool_calls": [], "tool_responses": []}
            for message in block.messages:
                role = message.get("role")
                if role == "assistant" and message.get("tool_calls"):
                    for call in message["tool_calls"]:
                        function = call.get("function", {}) if isinstance(call, dict) else getattr(call, "function", None)
                        item["tool_calls"].append({
                            "name": function.get("name", "unknown") if isinstance(function, dict) else getattr(function, "name", "unknown"),
                            "arguments": function.get("arguments", "{}") if isinstance(function, dict) else getattr(function, "arguments", "{}"),
                        })
                elif role == "tool":
                    item["tool_responses"].append({"tool_call_id": message.get("tool_call_id", ""), "content": message.get("content", "")})
            result.append(item)
        return result

    def _call_llm(self, block_data: list[dict[str, Any]], plan: Any = None) -> str:
        prompt = (
            f"Summarize the following {len(block_data)} tool call blocks into approximately "
            f"{self.summary_target_chars} characters or fewer. Do not cut off sentences.\n\n"
            + json.dumps(block_data, indent=2, default=str)
        )
        try:
            request = {
                "model": self.model,
                "messages": [{"role": "system", "content": self.SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
                "temperature": 0.3,
            }
            response = self.client.chat.completions.create(**request)
            self.conversation_logger.record_completion("summarizer", request, response)
            message = response.choices[0].message if response and response.choices else None
            content = getattr(message, "content", "") if message else ""
            return content or self._fallback_summary(block_data)
        except Exception:
            return self._fallback_summary(block_data)

    @staticmethod
    def _fallback_summary(block_data: list[dict[str, Any]]) -> str:
        items = []
        for block in block_data:
            for call in block.get("tool_calls", []):
                result = "No result available"
                if block.get("tool_responses"):
                    result = " ".join(str(item.get("content", "")) for item in block["tool_responses"])
                    result = " ".join(result.split())
                    if len(result) > 500:
                        result = f"tool response of {len(result)} chars"
                items.append(f"Called {call['name']}() -> {result}")
        return json.dumps({"chronological_summary": items, "key_findings": [], "files_examined": []})

    @staticmethod
    def _extract_json(text: str) -> str:
        start, end = text.find("{"), text.rfind("}") + 1
        return text[start:end] if start >= 0 and end > start else text

    def _parse_summary(self, summary_text: str) -> BatchSummary:
        try:
            data = json.loads(self._extract_json(summary_text))
            grouped = data.get("summary_by_action", [])
            chronological = data.get("chronological_summary", [])
            if grouped:
                text = "\n".join(item.get("summary", "") for item in grouped if item.get("summary"))
            elif isinstance(chronological, list):
                text = "\n".join(
                    f"- {item.get('action', '')} -> {item.get('result', '')}" if isinstance(item, dict) and "action" in item else str(item)
                    for item in chronological
                )
            else:
                text = str(chronological or "")
            return BatchSummary(grouped, text, data.get("key_findings", []), data.get("files_examined", []), len(grouped or chronological))
        except (json.JSONDecodeError, TypeError, AttributeError):
            return BatchSummary([], summary_text, [], [], 0)

    def _parse_meta_summary(self, content: str) -> str:
        try:
            return json.loads(self._extract_json(content)).get("consolidated_session_summary", "") or content
        except (json.JSONDecodeError, AttributeError, TypeError):
            return content

    @staticmethod
    def _fallback_meta_summary(session_summary: str, variable_summary: str) -> str:
        if not session_summary:
            return variable_summary
        if not variable_summary:
            return session_summary
        return f"{session_summary}\n\n[Recent Additions]\n{variable_summary}"
