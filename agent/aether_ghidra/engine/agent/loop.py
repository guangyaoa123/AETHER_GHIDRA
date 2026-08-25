from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class AgentCancelled(RuntimeError):
    """Raised when a cooperative agent run is cancelled."""


def _parse_xml_tool_calls(content: str) -> list[dict[str, Any]]:
    if not content or "<tool_call>" not in content:
        return []
    calls = []
    for block in re.findall(r"<tool_call>([\s\S]*?)</tool_call>", content):
        function = re.search(r"<function=([A-Za-z0-9_]+)>", block)
        if not function:
            try:
                data = json.loads(block.strip())
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(data, dict) and "name" in data:
                calls.append({"id": f"xml_{time.time_ns()}", "type": "function", "function": {"name": data["name"], "arguments": json.dumps(data.get("arguments", {}))}})
            continue
        args = {name: value.strip() for name, value in re.findall(r"<parameter=([A-Za-z0-9_]+)>([\s\S]*?)</parameter>", block)}
        calls.append({"id": f"xml_{time.time_ns()}", "type": "function", "function": {"name": function.group(1), "arguments": json.dumps(args)}})
    return calls


def _reasoning_values(message: Any) -> list[Any]:
    values = [getattr(message, name) for name in ("reasoning", "reasoning_content", "reasoning_details") if getattr(message, name, None)]
    if hasattr(message, "model_dump"):
        try:
            dumped = message.model_dump()
            values.extend(dumped[name] for name in ("reasoning", "reasoning_content", "reasoning_details") if dumped.get(name))
        except Exception:
            pass
    return values


def extract_reasoning_trace(message: Any) -> str:
    rendered = []
    for value in _reasoning_values(message):
        item = value if isinstance(value, str) else json.dumps(value, indent=2, default=str)
        if item and item not in rendered: rendered.append(item)
    return "\n\n".join(rendered)


def extract_reasoning_text(message: Any) -> str:
    parts: list[str] = []
    for value in _reasoning_values(message):
        if isinstance(value, str): parts.append(value.strip())
        elif isinstance(value, dict): parts.append(str(value.get("text") or value.get("summary") or value.get("content") or "").strip())
        elif isinstance(value, list):
            parts.extend(str(item.get("text") or item.get("summary") or item.get("content") or "").strip() if isinstance(item, dict) else str(item).strip() for item in value)
    return "\n\n".join(dict.fromkeys(part for part in parts if part))


@dataclass
class AgentLoopState:
    task: str
    checkpoint: Any = None
    conversation_history: list[dict[str, Any]] = field(default_factory=list)
    iteration: int = 0
    tool_calls_made: list[dict[str, Any]] = field(default_factory=list)
    final_analysis: str = ""
    done: bool = False
    missed_tool_call_count: int = 0


@dataclass
class AgentLoopStep:
    state: AgentLoopState
    messages: list[dict[str, Any]] = field(default_factory=list)
    assistant_message: dict[str, Any] | None = None
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    final_analysis: str = ""
    done: bool = False


class AgentLoopExecutor:
    def __init__(self, client: Any, model: str, max_iterations: int, system_prompt: str, tools: list[dict[str, Any]], tool_handlers: dict[str, Any], context_manager: Any, plan_manager: Any, memory_store: Any, track_file_callback: Any = None, verbose_output_dir: str | None = "results", copy_reasoning_to_content: bool = False, llm_retry_count: int = 2, llm_retry_base_delay_sec: float = 1.0, conversation_logger: Any = None, cancel_event: Any = None, progress_callback: Any = None) -> None:
        self.client, self.model, self.max_iterations, self.system_prompt = client, model, max_iterations, system_prompt
        self.tools, self.tool_handlers, self.context_manager, self.plan_manager, self.memory_store = tools, tool_handlers, context_manager, plan_manager, memory_store
        self.track_file_callback, self.verbose_output_dir, self.copy_reasoning_to_content = track_file_callback, verbose_output_dir, copy_reasoning_to_content
        self.conversation_logger = conversation_logger
        self.llm_retry_count, self.llm_retry_base_delay_sec, self.logger = max(0, int(llm_retry_count)), max(0.0, float(llm_retry_base_delay_sec)), logging.getLogger(__name__)
        self.cancel_event = cancel_event
        self.progress_callback = progress_callback

    def _publish_progress(self, state: AgentLoopState) -> None:
        if self.progress_callback is not None:
            self.progress_callback(state)

    def _check_cancelled(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise AgentCancelled("Chat cancelled")

    @staticmethod
    def _is_retryable_error(exc: Exception) -> bool:
        status = getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)
        if isinstance(status, int): return status in {408, 409, 429} or status >= 500
        text = str(exc).lower()
        if any(item in text for item in ("invalid api key", "authentication", "unauthorized", "forbidden", "invalid_request", "bad request", "does not exist", "context_length_exceeded")): return False
        return any(item in text for item in ("timeout", "timed out", "temporarily unavailable", "connection reset", "connection refused", "connection aborted", "rate limit", "too many requests", "service unavailable", "internal server error", "bad gateway", "gateway timeout"))

    def _create_completion_with_retry(self, **request: Any) -> Any:
        for attempt in range(self.llm_retry_count + 1):
            self._check_cancelled()
            try:
                self.logger.debug("LLM completion start iteration=%s attempt=%s model=%s tools=%s", getattr(self, "_iteration", "?"), attempt + 1, self.model, len(self.tools))
                response = self.client.chat.completions.create(**request)
                if self.conversation_logger is not None:
                    self.conversation_logger.record_completion("chat", request, response)
                return response
            except Exception as exc:
                if self.cancel_event is not None and self.cancel_event.is_set():
                    raise AgentCancelled("Chat cancelled") from exc
                self.logger.warning("LLM completion failed attempt=%s/%s error=%s", attempt + 1, self.llm_retry_count + 1, exc)
                if attempt >= self.llm_retry_count or not self._is_retryable_error(exc): raise
                if self.cancel_event is not None:
                    if self.cancel_event.wait(self.llm_retry_base_delay_sec * (2 ** attempt)):
                        raise AgentCancelled("Chat cancelled")
                else:
                    time.sleep(self.llm_retry_base_delay_sec * (2 ** attempt))
        raise RuntimeError("LLM completion retry loop exited unexpectedly.")

    @staticmethod
    def _call_parts(call: Any) -> tuple[str, Any, str]:
        function = call.function if hasattr(call, "function") else call["function"]
        name = function.name if hasattr(function, "name") else function["name"]
        arguments = function.arguments if hasattr(function, "arguments") else function["arguments"]
        call_id = getattr(call, "id", "") if not isinstance(call, dict) else call.get("id", "")
        return name, arguments, call_id

    def _build_history_assistant_message(self, message: Any) -> dict[str, Any]:
        dumped = message.model_dump() if hasattr(message, "model_dump") else {"role": getattr(message, "role", "assistant"), "content": getattr(message, "content", "")}
        result = {"role": dumped.get("role", "assistant"), "content": dumped.get("content") or ""}
        if dumped.get("tool_calls") or getattr(message, "tool_calls", None): result["tool_calls"] = dumped.get("tool_calls") or message.tool_calls
        reasoning = extract_reasoning_text(message)
        if self.copy_reasoning_to_content and reasoning: result["content"] = reasoning
        elif not result["content"] and reasoning: result["content"] = reasoning
        return result

    def execute_tool(self, call: Any) -> str:
        self._check_cancelled()
        name, arguments, call_id = self._call_parts(call)
        self.logger.debug("tool start name=%s call_id=%s argument_keys=%s", name, call_id, sorted(arguments.keys()) if isinstance(arguments, dict) else "json")
        if name not in self.tool_handlers: return f"Error: Unknown tool '{name}'"
        try:
            args = json.loads(arguments) if isinstance(arguments, str) else arguments
            result = str(self.tool_handlers[name](**args))
            if self.context_manager: self.context_manager.add_tool_result(name, args, result, tool_call_id=call_id)
            self.logger.debug("tool complete name=%s call_id=%s result_chars=%s", name, call_id, len(result))
            return result
        except Exception as exc:
            if isinstance(exc, AgentCancelled):
                raise
            self.logger.error("tool failed name=%s call_id=%s error_type=%s", name, call_id, type(exc).__name__)
            return f"Error executing {name}: {exc}"

    def create_state(self, task: str, checkpoint: Any = None, conversation_history: list[dict[str, Any]] | None = None) -> AgentLoopState:
        return AgentLoopState(task, checkpoint, [] if conversation_history is None else conversation_history)

    def step(self, state: AgentLoopState | None = None, *, task: str | None = None, checkpoint: Any = None) -> AgentLoopStep:
        self._check_cancelled()
        if state is None:
            if task is None: raise ValueError("step() requires either an AgentLoopState or a task.")
            state = self.create_state(task, checkpoint)
        if state.done: return AgentLoopStep(state, final_analysis=state.final_analysis, done=True)
        if self.client is None:
            state.done, state.final_analysis = True, "No LLM client configured."
            return AgentLoopStep(state, final_analysis=state.final_analysis, done=True)
        if self.max_iterations >= 0 and state.iteration >= self.max_iterations:
            state.done = True
            if not state.final_analysis: state.final_analysis = f"Maximum iterations ({self.max_iterations}) reached."
            if self.plan_manager: self.plan_manager.clear()
            return AgentLoopStep(state, final_analysis=state.final_analysis, done=True)
        state.iteration += 1
        self._iteration = state.iteration
        self.logger.debug("agent step iteration=%s history_messages=%s", state.iteration, len(state.conversation_history))
        assembled = self.context_manager.assemble_prompt(system_prompt=self.system_prompt, conversation_history=state.conversation_history, checkpoint=state.checkpoint, current_task=state.task if state.iteration == 1 else "", plan=getattr(self.plan_manager, "active_plan", None))
        state.conversation_history = assembled.conversation_history
        response = self._create_completion_with_retry(model=self.model, messages=assembled.messages, tools=self.tools, tool_choice="auto")
        assistant = response.choices[0].message
        raw_calls = getattr(assistant, "tool_calls", None) or _parse_xml_tool_calls(getattr(assistant, "content", "") or "")
        history_message = self._build_history_assistant_message(assistant)
        if raw_calls and not history_message.get("tool_calls"): history_message["tool_calls"] = raw_calls
        state.conversation_history.append(history_message)
        self._publish_progress(state)
        if raw_calls:
            self.logger.debug("agent step received tool_calls=%s iteration=%s", len(raw_calls), state.iteration)
            results = []
            for call in raw_calls:
                self._check_cancelled()
                name, arguments, call_id = self._call_parts(call)
                result = self.execute_tool(call)
                if isinstance(arguments, str):
                    try:
                        parsed = json.loads(arguments)
                    except json.JSONDecodeError:
                        parsed = arguments
                else:
                    parsed = arguments
                record = {"name": name, "arguments": parsed, "result": result}
                state.tool_calls_made.append(record)
                results.append({**record, "tool_call_id": call_id})
                state.conversation_history.append({"role": "tool", "content": result, "tool_call_id": call_id})
                self._publish_progress(state)
            state.missed_tool_call_count = 0
            return AgentLoopStep(state, assembled.messages, history_message, results, done=False)
        state.final_analysis = getattr(assistant, "content", "") or extract_reasoning_text(assistant)
        self.logger.debug("agent step final iteration=%s final_chars=%s", state.iteration, len(state.final_analysis))
        state.done = True
        plan = getattr(self.plan_manager, "active_plan", None) if self.plan_manager else None
        if plan and not plan.is_complete():
            state.missed_tool_call_count += 1
            if state.missed_tool_call_count <= 1:
                state.done = False
                state.conversation_history.append({"role": "system", "content": "[SYSTEM_ADVICE] An active plan has pending tasks. Call a tool to continue, or delete_plan when the plan is complete."})
            elif self.plan_manager:
                self.plan_manager.clear()
        return AgentLoopStep(state, assembled.messages, history_message, final_analysis=state.final_analysis, done=state.done)

    def run(self, task: str, checkpoint: Any = None) -> dict[str, Any]:
        if self.client is None:
            return {"task": task, "iterations": 0, "tool_calls": [], "final_analysis": "No LLM client configured.", "context_stats": self.context_manager.get_statistics(), "plan_stats": self.plan_manager.summary() if hasattr(self.plan_manager, "summary") else None}
        state = self.create_state(task, checkpoint)
        while not state.done and (self.max_iterations < 0 or state.iteration < self.max_iterations): self.step(state)
        return {"task": task, "iterations": state.iteration, "tool_calls": state.tool_calls_made, "final_analysis": state.final_analysis, "context_stats": self.context_manager.get_statistics(), "plan_stats": self.plan_manager.summary() if hasattr(self.plan_manager, "summary") else None}
