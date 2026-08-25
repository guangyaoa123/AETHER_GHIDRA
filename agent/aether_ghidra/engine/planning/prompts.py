from __future__ import annotations

from .plan import Action, Plan, render_plan_for_prompt


def format_plan_for_prompt(plan: Plan | None, **_limits: int | None) -> str:
    return render_plan_for_prompt(plan) if plan else ""


def format_plan_summary_short(plan: Plan | None) -> str:
    if not plan:
        return ""
    complete, total = plan.progress()
    return f"[Plan: {plan.goal[:30]}... | {complete}/{total} | In Progress: {len(plan.get_in_progress_actions())}]"


def format_action_for_memory(action: Action) -> dict[str, object]:
    return {"action_id": action.id, "description": action.description, "status": action.status.value, "result": action.result, "memory_refs": action.memory_refs}
