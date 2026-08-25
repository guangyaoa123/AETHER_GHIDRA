from __future__ import annotations

from abc import ABC
from collections.abc import Callable
from copy import deepcopy
import json
from typing import Any

from ..memory import MemoryPriority


class RuntimeTool(ABC):
    def __init__(self, name: str, description: str = "") -> None:
        self.name, self.description = name, description

    def clone(self) -> "RuntimeTool":
        return deepcopy(self)


class PlanningTool(RuntimeTool):
    def __init__(self) -> None:
        super().__init__("planning", "Mandatory task planning tool for managing plans and progress.")

    def create_plan(self, ctx: Any, goal: str, actions: list[dict[str, Any]]) -> str:
        plan = ctx.plan_manager.create_plan(goal, actions, set_active=True)
        rendered = "\n".join(f"  - [{item.id}] {item.description}" for item in plan.actions)
        return f"Plan created: {plan.goal}\n\nActions:\n{rendered}\n\nPlan details are now shown in your context."

    def update_plan(self, ctx: Any, add_actions: list[dict[str, Any]] | None = None, remove_action_ids: list[str] | None = None, start_action_ids: list[str] | None = None, complete_actions: list[dict[str, Any]] | None = None, fail_actions: list[dict[str, Any]] | None = None) -> str:
        plan = ctx.plan_manager.active_plan
        if not plan:
            return "Error: No active plan. Create a plan first using create_plan."
        updates = []
        for item in add_actions or []:
            action = ctx.plan_manager.add_action_to_plan(plan, item.get("description", ""), item.get("depends_on"), item.get("after_action_id"), item.get("parent_action_id"))
            updates.append(f"Added: [{action.id}] {action.description}")
        for action_id in remove_action_ids or []:
            if not ctx.plan_manager.remove_action(plan, action_id):
                return f"Error: Action not found: {action_id}"
            updates.append(f"Removed: [{action_id}]")
        for action_id in start_action_ids or []:
            action = plan.get_action(action_id)
            if action is None:
                return f"Error: Action not found: {action_id}"
            ctx.plan_manager.start_action(action)
            updates.append(f"Started: [{action.id}] {action.description}")
        for item in complete_actions or []:
            action = plan.get_action(item.get("action_id", ""))
            if action is None:
                return f"Error: Action not found: {item.get('action_id', '')}"
            ctx.plan_manager.complete_action(action, item.get("result"), item.get("memory_refs"))
            updates.append(f"Completed: [{action.id}] {action.description}")
        for item in fail_actions or []:
            action = plan.get_action(item.get("action_id", ""))
            if action is None:
                return f"Error: Action not found: {item.get('action_id', '')}"
            ctx.plan_manager.fail_action(action, item.get("error", ""))
            updates.append(f"Failed: [{action.id}] {action.description}")
        if not updates:
            return "No updates specified."
        complete, total = plan.progress()
        return f"Plan updated: {', '.join(updates)}\n\nProgress: {complete}/{total} actions complete"

    def delete_plan(self, ctx: Any, reason: str | None = None) -> str:
        plan = ctx.plan_manager.active_plan
        if not plan:
            return "No active plan to delete."
        plan.mark_abandoned()
        return f"Plan deleted: {plan.goal[:50]}...{f' Reason: {reason}' if reason else ''}"


class ContextTool(RuntimeTool):
    def __init__(self) -> None:
        super().__init__("context", "Mandatory context tool for per-agent working state.")

    def get(self, ctx: Any, key: str, default: Any = None) -> Any:
        return ctx.state.get(key, default)

    def set(self, ctx: Any, key: str, value: Any) -> Any:
        ctx.state[key] = value
        return value

    def snapshot(self, ctx: Any) -> dict[str, Any]:
        return dict(ctx.state)


class MemoryTool(RuntimeTool):
    def __init__(self) -> None:
        super().__init__("memory", "Mandatory memory tool backed by the runtime memory store.")

    def _normalize_item(self, item: Any) -> dict[str, Any]:
        payload = dict(item) if isinstance(item, dict) else {"key": str(item), "value": str(item), "category": "runtime", "metadata": {"payload": item}}
        payload.setdefault("value", json.dumps(payload, default=str))
        payload.setdefault("key", payload.get("type") or payload.get("task") or "memory")
        payload.setdefault("category", payload.get("type") or "runtime")
        payload.setdefault("tags", [])
        metadata = dict(payload.get("metadata", {}))
        for key, value in payload.items():
            if key not in {"key", "value", "category", "priority", "tags", "metadata"}:
                metadata[key] = value
        payload["metadata"] = metadata
        return payload

    def remember(self, ctx: Any, item: Any) -> Any:
        payload = self._normalize_item(item)
        priority = payload.get("priority", "MEDIUM")
        try:
            priority = MemoryPriority[priority.upper()] if isinstance(priority, str) else priority
        except KeyError:
            priority = MemoryPriority.MEDIUM
        return ctx.memory_store.add_memory(payload["key"], payload["value"], payload["category"], priority, payload["tags"], payload["metadata"])

    def list_memories(self, ctx: Any) -> list[Any]:
        return list(ctx.memory_store.memories.values())

    def search_memories(self, ctx: Any, query: str, top_k: int = 5) -> list[Any]:
        return ctx.memory_store.search_memories(query, top_k)


class FunctionTool(RuntimeTool):
    def __init__(self, name: str, handler: Callable[..., Any], *, description: str = "") -> None:
        super().__init__(name, description)
        self._handler = handler

    def invoke(self, ctx: Any, *args: Any, **kwargs: Any) -> Any:
        return self._handler(ctx, *args, **kwargs)


class AgentToolbox:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def names(self) -> list[str]:
        return sorted(self._ctx._runtime.get_agent_tools(self._ctx.agent_id))

    def get(self, name: str) -> RuntimeTool | None:
        return self._ctx._runtime.get_agent_tools(self._ctx.agent_id).get(name)

    def require(self, name: str) -> RuntimeTool:
        tool = self.get(name)
        if tool is None:
            raise KeyError(f"Tool '{name}' is not available for agent '{self._ctx.agent_id}'.")
        return tool

    def __contains__(self, name: str) -> bool:
        return self.get(name) is not None

    def __getitem__(self, name: str) -> RuntimeTool:
        return self.require(name)
