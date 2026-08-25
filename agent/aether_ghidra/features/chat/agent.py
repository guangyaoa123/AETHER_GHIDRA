from __future__ import annotations

import json
import logging
import threading
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable

from ...integrations.ghidra.chatbot_backend import GhidraChatbotBackendBridge
from ...engine import (
    AgentLoopExecutor,
    AgentCancelled,
    CallbackAgent,
    ContextBudget,
    ContextManager,
    HierarchicalRetrievalAgent,
    KeywordRetrievalAgent,
    MemoryPriority,
    MemoryStore,
    MultiAgentRuntime,
    OpenAILLMClient,
    SummarizerAgent,
    PlanManager,
)
from ...config.settings import load_config
from ...config.tool_policy import load_tool_config
from ...observability.conversation_logging import ConversationLogger
from ..annotation.history import AnnotationHistory
from ..annotation.staging import MutationStaging
from ...tools.catalog import CHATBOT_TOOL_SPECS, TOOL_GROUP_BY_NAME, ChatbotToolbox, ToolNames


logger = logging.getLogger("aether_ghidra.chatbot")
MAX_FUNCTION_LIST_SIZE = 10


class TaskStatus(StrEnum):
    NOT_STARTED = "Not Started"
    IN_PROGRESS = "In Progress"
    COMPLETED = "Completed"
    FAILED = "Failed"


class ChatbotContextSummarizer:
    def __init__(self, *, summarizer_agent: SummarizerAgent | None = None, toolbox: ChatbotToolbox | None = None) -> None:
        self.summarizer_agent = summarizer_agent
        self.toolbox = toolbox

    async def summarize(self, state: "ChatbotAgentState", finalize: bool = False) -> str:
        if len(state.conversation_history) < 2:
            return "Not enough history to summarize."
        manager = state.context_manager
        manager.block_buffer.clear()
        for message in state.conversation_history:
            manager.block_buffer.add_message(message)
        blocks = list(manager.block_buffer.blocks)
        blocks_to_summarize = blocks[:-2] if len(blocks) > 2 else blocks
        if self.summarizer_agent is not None:
            summary_text = self.summarizer_agent.summarize_blocks(
                blocks_to_summarize,
                plan=state.plan_manager.active_plan,
            ).chronological_summary
        else:
            summary_text = "\n".join(manager.block_buffer._generate_summary(block) for block in blocks_to_summarize)
        if not summary_text:
            summary_text = "\n".join(
                f"{message.get('role', 'unknown')}: {message.get('content', '')}"
                for message in state.conversation_history
            )
        manager.block_buffer.add_to_variable_summary(summary_text, summarizer_agent=self.summarizer_agent)
        final_text = manager.block_buffer.get_combined_summary()
        if self.toolbox is not None:
            self.toolbox.save_summary(final_text)
        return final_text


def _create_summarizer_agent(memory_store: Any | None = None) -> SummarizerAgent:
    config = load_config()
    return SummarizerAgent(
        api_key=config["OPENAI_API_KEY"],
        memory_store=memory_store,
        model=config.get("OPENAI_MODEL", "gpt-4o-mini"),
        base_url=config.get("OPENAI_BASE_URL") or None,
    )


class ChatbotAgentState:
    def __init__(self, program_id: str, bridge: GhidraChatbotBackendBridge) -> None:
        self.program_id = program_id
        self.bridge = bridge
        self.runtime = MultiAgentRuntime()
        self.runtime.add_agent(CallbackAgent("chatbot", lambda *_: None, description="AETHER chatbot"))
        self.memory_store = self.runtime.get_agent_memory_store("chatbot")
        self.plan_manager = self.runtime.get_agent_plan_manager("chatbot")
        self._configure_memory_retrieval()
        self.context_manager = ContextManager(budget=ContextBudget(), memory_store=self.memory_store)
        self.context_manager.set_plan_manager(self.plan_manager)
        self.context_manager.set_agent_state_provider(self.render_memory_statistics)
        logger.info("initialized chatbot state program_id=%s retrieval=%s", program_id, type(self.memory_store.retrieval_agent).__name__)

    def _configure_memory_retrieval(self) -> None:
        try:
            config = load_config()
            api_key = config.get("OPENAI_API_KEY")
            if not api_key:
                self.memory_store.set_retrieval_agent(KeywordRetrievalAgent(self.memory_store))
                return
            client = OpenAILLMClient(
                api_key=api_key,
                model=config.get("OPENAI_MEMORY_MODEL") or config.get("OPENAI_MODEL", "gpt-4o-mini"),
                base_url=config.get("OPENAI_BASE_URL") or None,
            )
            self.memory_store.set_retrieval_agent(HierarchicalRetrievalAgent(self.memory_store, client))
        except Exception as exc:
            logger.warning("Falling back to keyword memory retrieval: %s", exc)
            self.memory_store.set_retrieval_agent(KeywordRetrievalAgent(self.memory_store))

    @property
    def context(self) -> dict[str, Any]:
        return self.runtime.get_agent_context("chatbot")

    @property
    def conversation_history(self) -> list[dict[str, Any]]:
        return self.runtime.get_agent_conversation_history("chatbot")

    @conversation_history.setter
    def conversation_history(self, history: list[dict[str, Any]]) -> None:
        self.runtime.set_agent_conversation_history("chatbot", history)

    @property
    def function_list(self) -> list[dict[str, Any]]:
        return self.context.setdefault("function_list", [])

    def add_to_function_list(self, function_name: str) -> str:
        function = self.bridge.resolve_function(function_name)
        if function is None:
            return f"Error: Function '{function_name}' not found."
        if function in self.function_list:
            return f"'{function_name}' is already in the analysis list."
        if len(self.function_list) >= MAX_FUNCTION_LIST_SIZE:
            return f"Function List is full (max {MAX_FUNCTION_LIST_SIZE})"
        self.function_list.append(function)
        return f"Added '{function_name}' to analysis list."

    def remove_from_function_list(self, function_name: str) -> None:
        function = self.bridge.resolve_function(function_name)
        if function is None or function not in self.function_list:
            raise KeyError(f"Function '{function_name}' not found in analysis list.")
        self.function_list.remove(function)

    def add_memory(self, key: str, value: Any, category: str, priority: str = "MEDIUM", tags: list[str] | None = None) -> None:
        try:
            selected_priority = MemoryPriority[priority.upper()]
        except KeyError:
            selected_priority = MemoryPriority.MEDIUM
        for memory_id, memory in self.memory_store.memories.items():
            if memory.key == key:
                self.memory_store.update_memory(memory_id, value=value, key=key, tags=list(tags or memory.tags))
                memory.category = category
                memory.priority = selected_priority
                return
        self.memory_store.add_memory(key=key, value=value, category=category, priority=selected_priority, tags=list(tags or ["short_term"]))

    def remove_memory(self, *, key: str | None = None, index: int | None = None, memory_id: str | None = None) -> None:
        if key is None and index is None and memory_id is None:
            raise ValueError("Must provide a memory_id, key, or index to remove memory.")
        items = list(self.memory_store.memories.values())
        if memory_id is None and index is not None:
            if not 0 <= index < len(items):
                raise IndexError(f"Memory with index {index} not found.")
            memory_id = items[index].id
        if memory_id is None and key is not None:
            memory_id = next((item.id for item in items if item.key == key), None)
        if memory_id is None or memory_id not in self.memory_store.memories:
            raise KeyError(f"Memory with key '{key}' not found.")
        self.memory_store.delete_memory(memory_id)

    def add_action_plan(self, description: str, task_descriptions: list[str], index: int | None = None) -> None:
        self.plan_manager.create_plan(description, [{"description": task} for task in task_descriptions], set_active=True)

    def _plan(self, plan_index: int):
        plans = self.plan_manager.all_plans
        if not 0 <= plan_index < len(plans):
            raise IndexError(f"ActionPlan with index {plan_index} not found.")
        return plans[plan_index]

    def add_task_to_plan(self, plan_index: int, description: str, index: int | None = None) -> None:
        plan = self._plan(plan_index)
        plan.add_action(description, index=index)

    def update_task(self, plan_index: int, task_index: int, status: str) -> None:
        plan = self._plan(plan_index)
        if not 0 <= task_index < len(plan.actions):
            raise IndexError(f"Task with index {task_index} not found in plan {plan_index}.")
        status_map = {
            TaskStatus.NOT_STARTED.value: "pending",
            TaskStatus.IN_PROGRESS.value: "in_progress",
            TaskStatus.COMPLETED.value: "completed",
            TaskStatus.FAILED.value: "failed",
        }
        plan.actions[task_index].status = next(item for item in type(plan.actions[task_index].status) if item.value == status_map[status])

    def remove_task_from_plan(self, plan_index: int, task_index: int) -> None:
        plan = self._plan(plan_index)
        if not 0 <= task_index < len(plan.actions):
            raise IndexError(f"Task with index {task_index} not found in plan {plan_index}.")
        del plan.actions[task_index]

    def remove_action_plan(self, plan_index: int) -> None:
        plan = self._plan(plan_index)
        self.plan_manager.remove_plan(plan.id)

    def render_memory_statistics(self) -> str:
        stats = self.memory_store.get_statistics()
        return "\n".join([
            "[MEMORY STATISTICS]",
            f"Total Memories: {stats['total_memories']}",
            f"Categories: {stats.get('categories', {})}",
            f"Priorities: {stats.get('priorities', {})}",
        ])

    def save_summary(self, summary: str) -> None:
        self.conversation_history = self.context_manager.summarize_conversation_history(
            self.conversation_history,
            fallback_summary=summary,
            plan=self.plan_manager.active_plan,
        )

    def clear(self) -> None:
        self.memory_store.clear()
        self.plan_manager.clear()
        self.context.clear()
        self.conversation_history.clear()
        self.context_manager.reset()

    def __str__(self) -> str:
        memories = list(self.memory_store.memories.values())
        plans = self.plan_manager.all_plans
        plan_text = "No active plans." if not plans else "\n".join(plan.summary() for plan in plans)
        functions = ", ".join(self.bridge.get_function_name(item) for item in self.function_list) or "none"
        return (
            "ChatbotAgentState:\n"
            f"- Memory Store: {len(memories)} memories\n"
            f"- Plan Manager:\n{plan_text}\n"
            f"- Function List: [{functions}]"
        )


class _ClientDefaults:
    def __init__(self, client: Any, defaults: dict[str, Any]) -> None:
        self._client = client
        self._defaults = defaults
        self.chat = self
        self.completions = self

    def create(self, **request: Any) -> Any:
        payload = dict(request)
        payload.update({key: value for key, value in self._defaults.items() if value is not None})
        return self._client.chat.completions.create(**payload)

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if close is not None:
            close()


class ChatbotAgent:
    def __init__(self, program_id: str, bridge: GhidraChatbotBackendBridge | None = None) -> None:
        self.program_id = program_id
        self.bridge = bridge or GhidraChatbotBackendBridge(program_id)
        self.state = ChatbotAgentState(program_id, self.bridge)
        self.toolbox = ChatbotToolbox(self.state, self.bridge)
        self.config = load_config()
        self.conversation_logger = ConversationLogger(self.config)
        self._active_lock = threading.RLock()
        self._active_client: Any = None
        self._active_cancel: threading.Event | None = None
        self.exposed_tools = {
            name for name, enabled in load_tool_config(
                (item.value for item in ToolNames), TOOL_GROUP_BY_NAME
            ).items() if enabled
        }

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        return self.toolbox.get_tool_definitions(self.exposed_tools)

    async def summarize(self, finalize: bool = False) -> str:
        summarizer = ChatbotContextSummarizer(
            summarizer_agent=_create_summarizer_agent(self.state.memory_store),
            toolbox=self.toolbox,
        )
        return await summarizer.summarize(self.state, finalize)

    def _client(self) -> Any:
        try:
            import httpx
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError("The Python agent requires the 'openai' and 'httpx' packages.") from exc
        api_key = self.config.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not configured.")
        # Preserve legacy transport behavior: OpenAI-compatible endpoint, 600s timeout,
        # and disabled certificate verification.
        http_client = httpx.Client(verify=False, timeout=600.0)
        raw = OpenAI(api_key=api_key, base_url=self.config.get("OPENAI_BASE_URL"), http_client=http_client)
        return _ClientDefaults(
            raw,
            {
                "max_tokens": self.config.get("CHATBOT_MAX_TOKENS", 65_536),
                "temperature": 0.7,
                "extra_body": self.config.get("OPENAI_EXTRA_BODY") or None,
            },
        )

    def _prompt(self) -> str:
        prompt_path = Path(__file__).parent / "prompts" / "base_chat.txt"
        try:
            prompt = prompt_path.read_text(encoding="utf-8")
        except OSError:
            prompt = "You are an interactive Ghidra reverse engineering agent. Use native tools and explain findings clearly."
        for tool in ToolNames:
            prompt = prompt.replace(f"{{ToolNames.{tool.name}}}", tool.value)
        for status in TaskStatus:
            prompt = prompt.replace(f"{{TaskStatus.{status.name}}}", status.value)
        return prompt + "\n\n" + self._tool_status()

    def _tool_status(self) -> str:
        available = sorted(item["function"]["name"] for item in self.get_tool_definitions())
        disabled = sorted(set(name.value for name in ToolNames) - self.exposed_tools)
        return "\n--- AGENT TOOL STATUS ---\nAVAILABLE TOOLS:\n" + "\n".join(f"* {name}" for name in available) + ("\nDISABLED BY USER:\n" + "\n".join(f"* {name}" for name in disabled) if disabled else "")

    def _handlers(self) -> dict[str, Any]:
        enabled = self.exposed_tools
        max_calls = int(self.config.get("CHATBOT_MAX_TOOL_CALLS", 10))
        max_output = int(self.config.get("CHATBOT_MAX_CUMULATIVE_TOOL_OUTPUT", 0))
        state = {"calls": 0, "output": 0}

        def make(name: str):
            def handler(**arguments: Any) -> str:
                if name not in enabled:
                    return f"[SYSTEM_ERROR] Tool '{name}' is BLOCKED. Reason: DISABLED_BY_USER_SETTINGS."
                if max_calls and state["calls"] >= max_calls:
                    return f"[SYSTEM_ERROR] Tool '{name}' is BLOCKED. Reason: COUNT_LIMIT ({state['calls']}/{max_calls})."
                if max_output and state["output"] >= max_output:
                    return f"[SYSTEM_ERROR] Tool '{name}' is BLOCKED. Reason: LENGTH_LIMIT ({state['output']}/{max_output} chars)."
                state["calls"] += 1
                result = self.toolbox.execute_named(name, arguments)
                state["output"] += len(result)
                return result
            return handler

        return {name.value: make(name.value) for name in ToolNames}

    def cancel_current(self) -> None:
        with self._active_lock:
            cancel = self._active_cancel
            client = self._active_client
        if cancel is not None:
            cancel.set()
        if client is not None:
            close = getattr(client, "close", None)
            if close is not None:
                close()

    def run(
        self,
        task: str,
        *,
        address: dict[str, Any] | None = None,
        cancel: threading.Event | None = None,
        progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        logger.info("agent run start program_id=%s task_chars=%s address=%s tools=%s", self.program_id, len(task), address, len(self.exposed_tools))
        cancel = cancel or threading.Event()
        if cancel.is_set():
            raise AgentCancelled("Chat cancelled")
        user_content = task
        if address:
            user_content = f"[Selected Ghidra address: {json.dumps(address)}]\n{task}"
        self.state.conversation_history.append({"role": "user", "content": "USER QUERY: " + user_content})
        staging = MutationStaging(immediate_rename=self._immediate_rename)
        self.toolbox.staging = staging
        applied = None

        def report_progress(loop_state: Any) -> None:
            if progress is not None:
                progress({
                    "conversation_history": list(loop_state.conversation_history),
                    "tool_calls": list(loop_state.tool_calls_made),
                    "final_analysis": loop_state.final_analysis,
                    "iteration": loop_state.iteration,
                    "done": loop_state.done,
                })

        try:
            client = self._client()
            with self._active_lock:
                self._active_client = client
                self._active_cancel = cancel
            executor = AgentLoopExecutor(
                client=client,
                model=self.config.get("OPENAI_MODEL", "gpt-4o-mini"),
                max_iterations=int(self.config.get("CHATBOT_MAX_ITERATIONS", -1)),
                system_prompt=self._prompt(),
                tools=self.get_tool_definitions(),
                tool_handlers=self._handlers(),
                context_manager=self.state.context_manager,
                plan_manager=self.state.plan_manager,
                memory_store=self.state.memory_store,
                verbose_output_dir=None,
                llm_retry_count=int(self.config.get("CHATBOT_REQUEST_RETRIES", 2)),
                llm_retry_base_delay_sec=float(self.config.get("CHATBOT_REQUEST_RETRY_DELAY_SEC", 1.0)),
                conversation_logger=self.conversation_logger,
                cancel_event=cancel,
                progress_callback=report_progress,
            )
            loop_state = executor.create_state("", conversation_history=self.state.conversation_history)
            report_progress(loop_state)
            while not loop_state.done and (loop_state.iteration < 0 or int(self.config.get("CHATBOT_MAX_ITERATIONS", -1)) < 0 or loop_state.iteration < int(self.config.get("CHATBOT_MAX_ITERATIONS", -1))):
                step = executor.step(loop_state)
                loop_state = step.state
            self.state.conversation_history = loop_state.conversation_history
            applied = staging.commit(
                lambda capability, arguments: self.bridge.invoke(self.program_id, capability, arguments)
            ) if loop_state.done and staging.operations else None
            if applied is not None:
                self._journal_batch(applied, task, address)
        except Exception:
            if applied is None:
                immediate = staging.immediate_result()
                if immediate is not None:
                    self._journal_batch(immediate, task, address)
            staging.discard()
            raise
        finally:
            with self._active_lock:
                active_client = self._active_client
                self._active_client = None
                self._active_cancel = None
            if active_client is not None:
                close = getattr(active_client, "close", None)
                if close is not None:
                    close()
            self.toolbox.staging = None
        logger.info(
            "agent run complete program_id=%s iterations=%s tool_calls=%s history_messages=%s",
            self.program_id,
            loop_state.iteration,
            len(loop_state.tool_calls_made),
            len(loop_state.conversation_history),
        )
        result = {
            "program_id": self.program_id,
            "final_analysis": loop_state.final_analysis,
            "tool_calls": loop_state.tool_calls_made,
            "iterations": loop_state.iteration,
            "conversation_history": self.state.conversation_history,
            "state": str(self.state),
        }
        if applied is not None:
            result["annotation_batch"] = applied
        return result

    def _immediate_rename(self, operation: dict[str, Any]) -> dict[str, Any]:
        result = self.bridge.invoke(self.program_id, "rename_function", {
            "address": operation["target"]["function_address"],
            "name": operation["value"],
        })
        return {
            "batch_id": "immediate-" + str(operation["id"]),
            "operations": [{
                "id": operation["id"],
                "kind": operation["kind"],
                "target": operation["target"],
                "before": operation.get("_before", ""),
                "after": result.get("name", operation["value"]),
            }],
        }

    def _journal_batch(self, applied: dict[str, Any], task: str, address: dict[str, Any] | None) -> None:
        metadata = next((item for item in self.bridge.list_programs() if item.get("program_id") == self.program_id), {})
        program_key = str(metadata.get("sha256") or metadata.get("md5") or self.program_id)
        AnnotationHistory(program_key).append({
            "batch_id": applied.get("batch_id"),
            "program_id": self.program_id,
            "program_key": program_key,
            "mode": "chat",
            "request": task,
            "address": address,
            "operations": applied.get("operations", []),
        })
