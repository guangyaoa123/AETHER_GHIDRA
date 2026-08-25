from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable

from .loop import AgentLoopExecutor
from ..context import ContextBudget, ContextManager
from ..memory import MemoryPriority, MemoryStore
from ..planning import PlanManager
from ..prompts import DEFAULT_CAPABILITY_PROMPT, DEFAULT_IDENTITY_PROMPT, PromptComposer, PromptConfig

SimplePlanManager = PlanManager


@dataclass
class BackboneCheckpoint:
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    session_id: str = ""
    total_tool_calls: int = 0
    total_memories: int = 0
    iterations_in_session: int = 0
    next_task: str | None = None
    agent_state: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]: return asdict(self)
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BackboneCheckpoint": return cls(**data)
    def summary(self) -> str: return f"Backbone Checkpoint ({self.timestamp})\nSession: {self.session_id or 'N/A'}\nTool calls: {self.total_tool_calls}\nMemories: {self.total_memories}\nNext task: {self.next_task or 'None'}"


class BackboneCheckpointManager:
    def __init__(self, export_state: Callable[[], dict[str, Any]], import_state: Callable[[dict[str, Any]], None]) -> None:
        self._export_state, self._import_state = export_state, import_state

    def save_checkpoint(self, checkpoint: BackboneCheckpoint, filepath: str) -> str:
        with open(filepath, "w", encoding="utf-8") as handle:
            json.dump({"checkpoint": checkpoint.to_dict(), "state": self._export_state()}, handle, indent=2, default=str)
        return filepath

    def load_checkpoint(self, filepath: str) -> BackboneCheckpoint:
        with open(filepath, encoding="utf-8") as handle:
            payload = json.load(handle)
        self._import_state(payload.get("state", {}))
        return BackboneCheckpoint.from_dict(payload["checkpoint"])


class GenericBackboneAgent:
    def __init__(self, *, system_prompt: str | None = None, prompt_config: PromptConfig | dict[str, Any] | None = None, client: Any = None, model: str | None = None, max_iterations: int = 20, memory_store: MemoryStore | None = None, plan_manager: PlanManager | None = None, context_manager: ContextManager | None = None, verbose_output_dir: str | None = "results") -> None:
        self.prompt_composer = PromptComposer()
        self.prompt_config = self._build_prompt_config(prompt_config)
        self.system_prompt = system_prompt or self.prompt_composer.compose(self.prompt_config)
        self.client, self.model, self.max_iterations = client, model or os.getenv("OPENAI_MODEL", "gpt-4.1-mini"), max_iterations
        self.memory_store, self.plan_manager = memory_store or MemoryStore(), plan_manager or PlanManager()
        self.context_manager = context_manager or ContextManager(budget=ContextBudget(), memory_store=self.memory_store)
        self.context_manager.set_plan_manager(self.plan_manager)
        self._checkpoint: BackboneCheckpoint | None = None
        self._session_id, self._initial_task = "", None
        self._registered_tools: list[dict[str, Any]] = []
        self._tool_handlers: dict[str, Callable[..., str]] = {}
        self.checkpoint_manager = BackboneCheckpointManager(self._export_state, self._import_state)
        self._register_core_tools()
        self.executor = AgentLoopExecutor(client=self.client, model=self.model, max_iterations=self.max_iterations, system_prompt=self.system_prompt, tools=self._registered_tools, tool_handlers=self._tool_handlers, context_manager=self.context_manager, plan_manager=self.plan_manager, memory_store=self.memory_store, verbose_output_dir=verbose_output_dir)

    def _build_prompt_config(self, config: PromptConfig | dict[str, Any] | None) -> PromptConfig:
        if config is None: return PromptConfig(identity=DEFAULT_IDENTITY_PROMPT, capability=DEFAULT_CAPABILITY_PROMPT)
        if isinstance(config, PromptConfig): return config
        return PromptConfig(identity=config.get("identity", DEFAULT_IDENTITY_PROMPT), capability=config.get("capability", DEFAULT_CAPABILITY_PROMPT), output_format=config.get("output_format", ""), runtime_appendix=config.get("runtime_appendix", ""), extra_sections=list(config.get("extra_sections", [])))

    @property
    def tools(self) -> list[dict[str, Any]]: return list(self._registered_tools)
    @property
    def tool_handlers(self) -> dict[str, Callable[..., str]]: return dict(self._tool_handlers)

    def register_tool(self, *, name: str, description: str, parameters: dict[str, Any], handler: Callable[..., str]) -> None:
        if name in self._tool_handlers: raise ValueError(f"Tool '{name}' is already registered.")
        self._registered_tools.append({"type": "function", "function": {"name": name, "description": description, "parameters": parameters}})
        self._tool_handlers[name] = handler

    def _register_core_tools(self) -> None:
        self.register_tool(name="create_plan", description="Create a new action plan.", parameters={"type": "object", "properties": {"goal": {"type": "string"}, "actions": {"type": "array"}}, "required": ["goal", "actions"]}, handler=self.create_plan)
        self.register_tool(name="update_plan", description="Update the current plan.", parameters={"type": "object", "properties": {}}, handler=self.update_plan)
        self.register_tool(name="delete_plan", description="Delete the current plan.", parameters={"type": "object", "properties": {}}, handler=self.delete_plan)
        self.register_tool(name="add_memory", description="Store a finding in memory.", parameters={"type": "object", "properties": {}, "required": ["key", "value", "category"]}, handler=self.add_memory)
        self.register_tool(name="add_memory_auto", description="Store a finding with automatic placement.", parameters={"type": "object", "properties": {}, "required": ["key", "value", "category"]}, handler=self.add_memory_auto)
        self.register_tool(name="search_memories", description="Search stored memories.", parameters={"type": "object", "properties": {"query": {"type": "string"}}}, handler=self.search_memories)
        self.register_tool(name="get_context_statistics", description="Get context statistics.", parameters={"type": "object", "properties": {}}, handler=self.get_context_statistics_tool)
        self.register_tool(name="get_memory_statistics", description="Get memory statistics.", parameters={"type": "object", "properties": {}}, handler=self.get_memory_statistics_tool)

    def create_plan(self, goal: str, actions: list[dict[str, Any]]) -> str:
        plan = self.plan_manager.create_plan(goal, actions, set_active=True)
        return f"Plan created: {plan.goal}\n\nActions:\n" + "\n".join(f"  - [{item.id}] {item.description}" for item in plan.actions) + "\n\nPlan details are now shown in your context."

    def update_plan(self, add_actions: list[dict[str, Any]] | None = None, remove_action_ids: list[str] | None = None, start_action_ids: list[str] | None = None, complete_actions: list[dict[str, Any]] | None = None, fail_actions: list[dict[str, Any]] | None = None) -> str:
        plan = self.plan_manager.active_plan
        if not plan: return "Error: No active plan. Create a plan first using create_plan."
        updates = []
        for item in add_actions or []:
            action = self.plan_manager.add_action_to_plan(plan, item.get("description", ""), item.get("depends_on"), item.get("after_action_id"), item.get("parent_action_id"))
            updates.append(f"Added: [{action.id}] {action.description}")
        for action_id in remove_action_ids or []:
            if not self.plan_manager.remove_action(plan, action_id): return f"Error: Action not found: {action_id}"
            updates.append(f"Removed: [{action_id}]")
        for action_id in start_action_ids or []:
            action = plan.get_action(action_id)
            if action is None: return f"Error: Action not found: {action_id}"
            self.plan_manager.start_action(action); updates.append(f"Started: [{action.id}] {action.description}")
        for item in complete_actions or []:
            action = plan.get_action(item.get("action_id", ""))
            if action is None: return f"Error: Action not found: {item.get('action_id', '')}"
            self.plan_manager.complete_action(action, item.get("result"), item.get("memory_refs"), self.context_manager); updates.append(f"Completed: [{action.id}] {action.description}")
        for item in fail_actions or []:
            action = plan.get_action(item.get("action_id", ""))
            if action is None: return f"Error: Action not found: {item.get('action_id', '')}"
            self.plan_manager.fail_action(action, item.get("error", "")); updates.append(f"Failed: [{action.id}] {action.description}")
        if not updates: return "No updates specified."
        complete, total = plan.progress()
        return f"Plan updated: {', '.join(updates)}\n\nProgress: {complete}/{total} actions complete"

    def delete_plan(self, reason: str | None = None) -> str:
        plan = self.plan_manager.active_plan
        if not plan: return "No active plan to delete."
        plan.mark_abandoned()
        return f"Plan deleted: {plan.goal[:50]}...{f' Reason: {reason}' if reason else ''}"

    def add_memory(self, key: str, value: str, category: str, priority: str = "MEDIUM", tags: list[str] | None = None) -> str:
        try: selected = MemoryPriority[priority.upper()]
        except KeyError: selected = MemoryPriority.MEDIUM
        item = self.memory_store.add_memory(key, value, category, selected, list(tags or []))
        return f"Memory stored successfully (ID: {item.id}, Category: {category}, Priority: {selected.name})"

    def add_memory_auto(self, key: str, value: str, category: str, priority: str = "MEDIUM", tags: list[str] | None = None) -> str:
        try: selected = MemoryPriority[priority.upper()]
        except KeyError: selected = MemoryPriority.MEDIUM
        item = self.memory_store.add_memory_auto(key, value, category, priority=selected, tags=list(tags or []))
        return f"Memory stored successfully (ID: {item.id}, Category: {category}, Priority: {selected.name})"

    def search_memories(self, query: str, top_k: int = 5) -> str:
        results = self.memory_store.search_memories(query, top_k)
        if not results: return f"No memories found matching: {query}"
        return "\n".join([f"Found {len(results)} memories for '{query}':"] + [f"{i}. [{item.memory.category}] {item.memory.key} (memory_id={item.memory.id}): {item.memory.get_display_content()}" for i, item in enumerate(results, 1)])

    def get_context_statistics_tool(self) -> str: return json.dumps(self.context_manager.get_statistics(), indent=2, default=str)
    def get_memory_statistics_tool(self) -> str: return json.dumps(self.memory_store.get_statistics(), indent=2, default=str)

    def create_checkpoint(self, next_task: str | None = None) -> BackboneCheckpoint:
        self._checkpoint = BackboneCheckpoint(session_id=self._session_id, total_tool_calls=len(self.context_manager.tool_buffer.records), total_memories=self.memory_store.get_statistics()["total_memories"], next_task=next_task, agent_state={"initial_task": self._initial_task, "plan": self.plan_manager.active_plan.to_dict() if self.plan_manager.active_plan else None})
        return self._checkpoint

    def load_checkpoint(self, filepath: str) -> BackboneCheckpoint:
        self._checkpoint = self.checkpoint_manager.load_checkpoint(filepath)
        self._initial_task = self._checkpoint.agent_state.get("initial_task")
        self.plan_manager.active_plan = self._checkpoint.agent_state.get("plan")
        return self._checkpoint

    def get_resume_prompt(self) -> str: return (self._checkpoint.next_task or self._initial_task or "Continue the task.") if self._checkpoint else ""

    def run(self, task: str | None = None, checkpoint: BackboneCheckpoint | None = None, checkpoint_file: str | None = None, use_resume_prompt: bool = True) -> dict[str, Any]:
        if checkpoint_file:
            self.load_checkpoint(checkpoint_file)
            if use_resume_prompt: task = self.get_resume_prompt()
        elif checkpoint:
            self._checkpoint = checkpoint
            self._initial_task = checkpoint.agent_state.get("initial_task")
            self.plan_manager.active_plan = checkpoint.agent_state.get("plan")
            if use_resume_prompt: task = self.get_resume_prompt()
        task = task or "Work on the current goal."
        self._initial_task = self._initial_task or task
        result = self.executor.run(task, self._checkpoint)
        self.create_checkpoint()
        result["checkpoint"], result["session_id"] = self._checkpoint, self._session_id
        return result

    def _export_state(self) -> dict[str, Any]:
        return {"memory_store": self.memory_store.export_to_dict(), "plan": self.plan_manager.active_plan.to_dict() if self.plan_manager.active_plan else None, "context": {"session_summary": self.context_manager._session_summary, "checkpoint_summary": self.context_manager._checkpoint_summary}}

    def _import_state(self, state: dict[str, Any]) -> None:
        self.memory_store.import_from_dict(state.get("memory_store", {}))
        self.plan_manager.active_plan = state.get("plan")
        context = state.get("context", {})
        self.context_manager.set_session_summary(context.get("session_summary", ""))
        self.context_manager.set_checkpoint_summary(context.get("checkpoint_summary", ""))
