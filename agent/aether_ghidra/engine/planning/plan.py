from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class PlanStatus(Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


class ActionStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Action:
    description: str
    id: str = field(default_factory=lambda: str(uuid4()))
    status: ActionStatus = ActionStatus.PENDING
    sub_actions: list["Action"] = field(default_factory=list)
    parent_id: str | None = None
    result: str | None = None
    memory_refs: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    error: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None

    @property
    def steps(self) -> list["Action"]:
        return self.sub_actions

    def is_ready(self) -> bool:
        return self.status == ActionStatus.PENDING

    def get_effective_status(self) -> ActionStatus:
        if not self.sub_actions:
            return self.status
        statuses = [child.get_effective_status() for child in self.sub_actions]
        if all(status in (ActionStatus.COMPLETED, ActionStatus.SKIPPED) for status in statuses):
            return ActionStatus.COMPLETED
        if any(status in (ActionStatus.IN_PROGRESS, ActionStatus.COMPLETED) for status in statuses) or self.status == ActionStatus.IN_PROGRESS:
            return ActionStatus.IN_PROGRESS
        return self.status

    def mark_started(self) -> None:
        self.status = ActionStatus.IN_PROGRESS

    def mark_completed(self, result: str | None = None, memory_refs: list[str] | None = None) -> None:
        self.status = ActionStatus.COMPLETED
        self.completed_at = datetime.now()
        if result is not None:
            self.result = result
        if memory_refs is not None:
            self.memory_refs = list(memory_refs)

    def mark_failed(self, error: str) -> None:
        self.status = ActionStatus.FAILED
        self.error = error
        self.completed_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "description": self.description, "status": self.status.value,
            "parent_id": self.parent_id, "sub_actions": [item.to_dict() for item in self.sub_actions],
            "result": self.result, "memory_refs": list(self.memory_refs),
            "depends_on": list(self.depends_on), "error": self.error,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Action":
        action = cls(
            id=data.get("id", str(uuid4())), description=data["description"],
            status=ActionStatus(data.get("status", "pending")), parent_id=data.get("parent_id"),
            result=data.get("result"), memory_refs=list(data.get("memory_refs", [])),
            depends_on=list(data.get("depends_on", [])), error=data.get("error"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
        )
        action.sub_actions = [cls.from_dict(item) for item in data.get("sub_actions", [])]
        return action


@dataclass
class Plan:
    goal: str
    id: str = field(default_factory=lambda: str(uuid4()))
    description: str = ""
    status: PlanStatus = PlanStatus.ACTIVE
    actions: list[Action] = field(default_factory=list)
    parent_plan_id: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def steps(self) -> list[Action]:
        return self.actions

    def add_action(self, description: str, depends_on: list[str] | None = None, index: int | None = None, parent_id: str | None = None) -> Action:
        action = Action(description, depends_on=list(depends_on or []), parent_id=parent_id)
        if parent_id and (parent := self.get_action(parent_id)) is not None:
            (parent.sub_actions.insert(index, action) if index is not None else parent.sub_actions.append(action))
        elif index is not None:
            self.actions.insert(index, action)
        else:
            self.actions.append(action)
        return action

    def get_action(self, action_id: str) -> Action | None:
        for action in self.iter_actions():
            if action.id == action_id:
                return action
        return None

    def iter_actions(self) -> list[Action]:
        result: list[Action] = []
        def walk(actions: list[Action]) -> None:
            for action in actions:
                result.append(action)
                walk(action.sub_actions)
        walk(self.actions)
        return result

    def get_ready_actions(self) -> list[Action]:
        return [action for action in self.iter_actions() if action.is_ready()]

    def get_next_action(self) -> Action | None:
        return next(iter(self.get_ready_actions()), None)

    def get_completed_actions(self) -> list[Action]:
        return [action for action in self.iter_actions() if action.status == ActionStatus.COMPLETED]

    def get_in_progress_actions(self) -> list[Action]:
        return [action for action in self.iter_actions() if action.get_effective_status() == ActionStatus.IN_PROGRESS]

    def is_complete(self) -> bool:
        actions = self.iter_actions()
        return bool(actions) and all(action.get_effective_status() in (ActionStatus.COMPLETED, ActionStatus.SKIPPED) for action in actions)

    def progress(self) -> tuple[int, int]:
        actions = self.iter_actions()
        return sum(action.get_effective_status() in (ActionStatus.COMPLETED, ActionStatus.SKIPPED) for action in actions), len(actions)

    def progress_percent(self) -> float:
        complete, total = self.progress()
        return complete / total * 100 if total else 0.0

    def mark_completed(self) -> None:
        self.status, self.completed_at = PlanStatus.COMPLETED, datetime.now()

    def mark_abandoned(self) -> None:
        self.status, self.completed_at = PlanStatus.ABANDONED, datetime.now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "goal": self.goal, "description": self.description, "status": self.status.value,
            "actions": [action.to_dict() for action in self.actions], "parent_plan_id": self.parent_plan_id,
            "created_at": self.created_at.isoformat(), "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Plan":
        plan = cls(
            id=data.get("id", str(uuid4())), goal=data["goal"], description=data.get("description", ""),
            status=PlanStatus(data.get("status", "active")), parent_plan_id=data.get("parent_plan_id"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            metadata=dict(data.get("metadata", {})),
        )
        plan.actions = [Action.from_dict(item) for item in data.get("actions", [])]
        return plan

    def summary(self) -> str:
        return render_plan_for_prompt(self)


def render_plan_for_prompt(plan: Plan) -> str:
    complete, total = plan.progress()
    lines = ["[ACTIVE PLAN]", f"Goal: {plan.goal}", f"Status: {plan.status.value.upper()} ({complete}/{total} actions complete)", "", "Next Actions:"]
    lines.extend(f"  - [{action.id}] {action.description}" for action in plan.get_ready_actions()[:3])
    lines.append("\nAction Tree:")
    for action in plan.actions:
        lines.append(f"  [{action.status.value}] [{action.id}] {action.description}")
        lines.extend(f"    [{child.status.value}] [{child.id}] {child.description}" for child in action.sub_actions)
    return "\n".join(lines)


class PlanManager:
    def __init__(self) -> None:
        self._plans: dict[str, Plan] = {}
        self._active_plan_id: str | None = None

    @property
    def active_plan(self) -> Plan | None:
        return self._plans.get(self._active_plan_id) if self._active_plan_id else None

    @active_plan.setter
    def active_plan(self, value: Plan | dict[str, Any] | None) -> None:
        if value is None:
            self._active_plan_id = None
            return
        plan = Plan.from_dict(value) if isinstance(value, dict) else value
        self._plans[plan.id], self._active_plan_id = plan, plan.id

    @property
    def all_plans(self) -> list[Plan]:
        return list(self._plans.values())

    def create_plan(self, goal: str, actions: list[dict[str, Any]] | None = None, description: str = "", set_active: bool = True, index: int | None = None) -> Plan:
        plan = Plan(goal, description=description)
        for item in actions or []:
            plan.add_action(item.get("description", ""), item.get("depends_on"))
        self._plans[plan.id] = plan
        if set_active:
            self._active_plan_id = plan.id
        return plan

    def set_active_plan(self, plan_id: str) -> bool:
        if plan_id not in self._plans:
            return False
        self._active_plan_id = plan_id
        return True

    def get_next_action(self, plan: Plan | None = None) -> Action | None:
        return (plan or self.active_plan).get_next_action() if (plan or self.active_plan) else None

    def complete_action(self, action: Action, result: str | None = None, memory_refs: list[str] | None = None, context_manager: Any | None = None) -> None:
        action.mark_completed(result, memory_refs)
        plan = self._get_plan_for_action(action.id)
        if plan and plan.is_complete():
            plan.mark_completed()
            if context_manager and hasattr(context_manager, "on_plan_completed"):
                context_manager.on_plan_completed(plan)

    def start_action(self, action: Action) -> None:
        action.mark_started()

    def fail_action(self, action: Action, error: str) -> None:
        action.mark_failed(error)

    def skip_action(self, action: Action) -> None:
        action.status, action.completed_at = ActionStatus.SKIPPED, datetime.now()

    def remove_action(self, plan: Plan, action_id: str) -> bool:
        action = plan.get_action(action_id)
        if action is None:
            return False
        if action.parent_id and (parent := plan.get_action(action.parent_id)) is not None:
            parent.sub_actions = [item for item in parent.sub_actions if item.id != action_id]
        else:
            plan.actions = [item for item in plan.actions if item.id != action_id]
        return True

    def add_action_to_plan(self, plan: Plan, description: str, depends_on: list[str] | None = None, after_action_id: str | None = None, parent_id: str | None = None) -> Action:
        siblings = plan.get_action(parent_id).sub_actions if parent_id and plan.get_action(parent_id) else plan.actions
        index = next((i + 1 for i, item in enumerate(siblings) if item.id == after_action_id), None) if after_action_id else None
        return plan.add_action(description, depends_on, index, parent_id)

    def create_sub_plan(self, parent_plan: Plan, goal: str, actions: list[dict[str, Any]]) -> Plan:
        plan = self.create_plan(goal, actions, set_active=False)
        plan.parent_plan_id = parent_plan.id
        return plan

    def _get_plan_for_action(self, action_id: str) -> Plan | None:
        return next((plan for plan in self._plans.values() if plan.get_action(action_id)), None)

    def get_plan(self, plan_id: str) -> Plan | None:
        return self._plans.get(plan_id)

    def remove_plan(self, plan_id: str) -> bool:
        if plan_id not in self._plans:
            return False
        del self._plans[plan_id]
        if self._active_plan_id == plan_id:
            self._active_plan_id = next(iter(self._plans), None)
        return True

    def clear(self) -> None:
        self._plans.clear()
        self._active_plan_id = None

    def get_all_memory_refs(self, plan: Plan | None = None) -> list[str]:
        return [ref for action in (plan or self.active_plan).iter_actions() for ref in action.memory_refs] if (plan or self.active_plan) else []

    def summary(self) -> str:
        return self.active_plan.summary() if self.active_plan else "No active plan."
