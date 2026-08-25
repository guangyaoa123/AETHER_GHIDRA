from __future__ import annotations

import ast
import json
import re
from enum import StrEnum
from typing import Any

from ..features.annotation.staging import MutationStaging
from ..integrations.ghidra.chatbot_backend import GhidraChatbotBackendBridge


class ToolNames(StrEnum):
    ADD_ACTION_PLAN = "add_action_plan"
    ADD_TASK_TO_PLAN = "add_task_to_plan"
    UPDATE_TASK = "update_task"
    REMOVE_TASK_FROM_PLAN = "remove_task_from_plan"
    REMOVE_ACTION_PLAN = "remove_action_plan"
    ADD_MEMORY = "add_memory"
    REMOVE_MEMORY = "remove_memory"
    SEARCH_MEMORY = "search_memory"
    LIST_FUNCTIONS = "list_functions"
    SEARCH_FUNCTION_INDEX = "search_function_index"
    GET_FUNCTION_PSEUDOCODE = "get_function_pseudocode"
    ADD_TO_FUNCTION_LIST = "add_to_function_list"
    REMOVE_FROM_FUNCTION_LIST = "remove_from_function_list"
    GET_DATA_AT_ADDRESS = "get_data_at_address"
    GET_XREFS_TO = "get_xrefs_to"
    RENAME_FUNCTION = "rename_function"
    RENAME_VARIABLE = "rename_variable"
    RETYPE_VARIABLE = "retype_variable"
    UPDATE_FUNCTION_DEFINITION = "update_function_definition"
    SET_FUNCTION_COMMENT = "set_function_comment"
    SET_CODE_UNIT_COMMENT = "set_code_unit_comment"
    SAVE_SUMMARY = "save_summary"


class ToolGroup(StrEnum):
    PROGRAM_READ = "program_read"
    ANALYSIS_CONTEXT = "analysis_context"
    PROGRAM_WRITE = "program_write"
    PLANNING = "planning"
    MEMORY = "memory"
    CONVERSATION = "conversation"
    ANNOTATION_READ = "annotation_read"
    ANNOTATION_WRITE = "annotation_write"


TOOL_GROUPS: dict[ToolGroup, tuple[ToolNames, ...]] = {
    ToolGroup.PROGRAM_READ: (
        ToolNames.LIST_FUNCTIONS,
        ToolNames.GET_FUNCTION_PSEUDOCODE,
        ToolNames.GET_DATA_AT_ADDRESS,
        ToolNames.GET_XREFS_TO,
        ToolNames.SEARCH_FUNCTION_INDEX,
    ),
    ToolGroup.ANALYSIS_CONTEXT: (
        ToolNames.ADD_TO_FUNCTION_LIST,
        ToolNames.REMOVE_FROM_FUNCTION_LIST,
    ),
    ToolGroup.PROGRAM_WRITE: (
        ToolNames.RENAME_FUNCTION,
        ToolNames.RENAME_VARIABLE,
        ToolNames.RETYPE_VARIABLE,
        ToolNames.UPDATE_FUNCTION_DEFINITION,
        ToolNames.SET_FUNCTION_COMMENT,
        ToolNames.SET_CODE_UNIT_COMMENT,
    ),
    ToolGroup.PLANNING: (
        ToolNames.ADD_ACTION_PLAN,
        ToolNames.ADD_TASK_TO_PLAN,
        ToolNames.UPDATE_TASK,
        ToolNames.REMOVE_TASK_FROM_PLAN,
        ToolNames.REMOVE_ACTION_PLAN,
    ),
    ToolGroup.MEMORY: (
        ToolNames.ADD_MEMORY,
        ToolNames.REMOVE_MEMORY,
        ToolNames.SEARCH_MEMORY,
    ),
    ToolGroup.CONVERSATION: (ToolNames.SAVE_SUMMARY,),
}

TOOL_GROUP_BY_NAME = {
    tool.value: group.value for group, tools in TOOL_GROUPS.items() for tool in tools
}
TOOL_GROUP_BY_NAME.update({
    "get_function_call_tree": ToolGroup.ANNOTATION_READ.value,
    "get_annotation_context": ToolGroup.ANNOTATION_READ.value,
    "apply_annotation_batch": ToolGroup.ANNOTATION_WRITE.value,
})

# Capabilities are kept here with the tool catalog so direct capability calls
# cannot silently bypass the same policy used by chatbot tools.
CAPABILITY_TO_TOOL = {
    "list_functions": ToolNames.LIST_FUNCTIONS.value,
    "get_function_pseudocode": ToolNames.GET_FUNCTION_PSEUDOCODE.value,
    "get_data_at_address": ToolNames.GET_DATA_AT_ADDRESS.value,
    "get_xrefs_to": ToolNames.GET_XREFS_TO.value,
    "rename_function": ToolNames.RENAME_FUNCTION.value,
    "rename_variable": ToolNames.RENAME_VARIABLE.value,
    "retype_variable": ToolNames.RETYPE_VARIABLE.value,
    "update_function_definition": ToolNames.UPDATE_FUNCTION_DEFINITION.value,
    "set_function_comment": ToolNames.SET_FUNCTION_COMMENT.value,
    "set_code_unit_comment": ToolNames.SET_CODE_UNIT_COMMENT.value,
    "get_function_call_tree": "get_function_call_tree",
    "get_annotation_context": "get_annotation_context",
    "apply_annotation_batch": "apply_annotation_batch",
}


def _spec(description: str, properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {"description": description, "parameters": {"type": "object", "properties": properties, "required": required or []}}


CHATBOT_TOOL_SPECS: dict[ToolNames, dict[str, Any]] = {
    ToolNames.ADD_ACTION_PLAN: _spec("Create and insert a new action plan.", {"plan_index": {"type": "string"}, "description": {"type": "string"}}, ["plan_index", "description"]),
    ToolNames.ADD_TASK_TO_PLAN: _spec("Add a task to an existing action plan.", {"plan_index": {"type": "string"}, "task_index": {"type": "string"}, "description": {"type": "string"}}, ["plan_index", "task_index", "description"]),
    ToolNames.UPDATE_TASK: _spec("Update a task status.", {"plan_index": {"type": "string"}, "task_index": {"type": "string"}, "status": {"type": "string"}}, ["plan_index", "task_index", "status"]),
    ToolNames.REMOVE_TASK_FROM_PLAN: _spec("Remove a task from an action plan.", {"plan_index": {"type": "string"}, "task_index": {"type": "string"}}, ["plan_index", "task_index"]),
    ToolNames.REMOVE_ACTION_PLAN: _spec("Remove a completed or abandoned action plan.", {"plan_index": {"type": "string"}}, ["plan_index"]),
    ToolNames.ADD_MEMORY: _spec("Store a memory for later analysis context.", {"key": {"type": "string"}, "value": {"type": "string"}, "category": {"type": "string"}, "priority": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}}, ["key", "value", "category"]),
    ToolNames.REMOVE_MEMORY: _spec("Remove a memory by id, key, or display index.", {"memory_id": {"type": "string"}, "key": {"type": "string"}, "index": {"type": "string"}}),
    ToolNames.SEARCH_MEMORY: _spec("Search stored memories.", {"query": {"type": "string"}, "top_k": {"type": "string"}}, ["query"]),
    ToolNames.LIST_FUNCTIONS: _spec("List functions in the current Ghidra Program. Optional regex pattern and limit.", {"pattern": {"type": "string"}, "limit": {"type": "string"}}),
    ToolNames.SEARCH_FUNCTION_INDEX: _spec("Search the persisted whole-program function index and return a reverse engineering briefing.", {"query": {"type": "string"}}, ["query"]),
    ToolNames.GET_FUNCTION_PSEUDOCODE: _spec("Commit the function's current decompiler locals and parameters, then retrieve address-aware pseudocode by function name.", {"function_name": {"type": "string"}}, ["function_name"]),
    ToolNames.ADD_TO_FUNCTION_LIST: _spec("Add a function to the active analysis list.", {"func_name": {"type": "string"}}, ["func_name"]),
    ToolNames.REMOVE_FROM_FUNCTION_LIST: _spec("Remove a function from the active analysis list.", {"func_name": {"type": "string"}}, ["func_name"]),
    ToolNames.GET_DATA_AT_ADDRESS: _spec("Inspect bytes, disassembly, strings, and context at a Ghidra address or symbol.", {"location": {"type": "string"}, "count": {"type": "string"}}, ["location"]),
    ToolNames.GET_XREFS_TO: _spec("List cross-references to an address or function.", {"location": {"type": "string"}}, ["location"]),
    ToolNames.RENAME_FUNCTION: _spec("Immediately rename a Ghidra function. The new name is visible to subsequent tool calls.", {"function_name": {"type": "string"}, "name": {"type": "string"}}, ["function_name", "name"]),
    ToolNames.RENAME_VARIABLE: _spec("Stage a local or parameter variable rename identified by function_name and variable_name.", {"function_name": {"type": "string"}, "variable_name": {"type": "string"}, "name": {"type": "string"}}, ["function_name", "variable_name", "name"]),
    ToolNames.RETYPE_VARIABLE: _spec("Stage a local or function-parameter data type change.", {"function_name": {"type": "string"}, "variable_name": {"type": "string"}, "data_type": {"type": "string"}}, ["function_name", "variable_name", "data_type"]),
    ToolNames.UPDATE_FUNCTION_DEFINITION: _spec("Stage an atomic function prototype update. The ordered parameter list may add, remove, rename, reorder, or retype arguments. Omit storage to use the existing calling convention; specify register or stack storage for custom placement.", {"function_name": {"type": "string"}, "return_type": {"type": "string"}, "parameters": {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}, "data_type": {"type": "string"}, "storage": {"type": "object"}}, "required": ["name", "data_type"]}}, "varargs": {"type": "boolean"}}, ["function_name", "return_type", "parameters"]),
    ToolNames.SET_FUNCTION_COMMENT: _spec("Stage a Ghidra function comment update. Changes are committed atomically after the agent run.", {"function_name": {"type": "string"}, "comment": {"type": "string"}}, ["function_name", "comment"]),
    ToolNames.SET_CODE_UNIT_COMMENT: _spec("Stage a comment on a frozen Ghidra code location.", {"location": {"oneOf": [{"type": "string"}, {"type": "object"}]}, "comment_kind": {"type": "string", "enum": ["eol", "pre", "post", "plate", "repeatable"]}, "comment": {"type": "string"}}, ["location", "comment_kind", "comment"]),
    ToolNames.SAVE_SUMMARY: _spec("Compress the conversation history into a summary.", {"summary": {"type": "string"}}, ["summary"]),
}


class ChatbotToolbox:
    def __init__(self, state: Any, bridge: GhidraChatbotBackendBridge, staging: MutationStaging | None = None) -> None:
        self.state = state
        self.bridge = bridge
        self.staging = staging
        self.registry = {name: getattr(self, name.value) for name in ToolNames}

    def get_tool_definitions(self, enabled_tools: set[str] | None = None) -> list[dict[str, Any]]:
        names = {name.value for name in ToolNames} if enabled_tools is None else enabled_tools
        return [{"type": "function", "function": {"name": name.value, "description": spec["description"], "parameters": spec["parameters"]}} for name, spec in CHATBOT_TOOL_SPECS.items() if name.value in names]

    def execute_named(self, name: str, arguments: dict[str, Any] | None = None) -> str:
        try:
            return str(self.registry[ToolNames(name)](**(arguments or {})))
        except Exception as exc:
            return f"Error executing {name}: {exc}"

    def add_action_plan(self, plan_index: str, description: str) -> str:
        try:
            self.state.add_action_plan(description, [], int(plan_index))
            return f"Action plan {plan_index} added: {description}"
        except ValueError:
            return f"Error: Invalid plan_index '{plan_index}'. Must be an integer."

    def add_task_to_plan(self, plan_index: str, task_index: str, description: str) -> str:
        try:
            self.state.add_task_to_plan(int(plan_index), description, int(task_index))
            return f"Task {task_index} added to plan {plan_index}: {description}"
        except (ValueError, IndexError) as exc:
            return f"Error: {exc}"

    def update_task(self, plan_index: str, task_index: str, status: str) -> str:
        try:
            self.state.update_task(int(plan_index), int(task_index), status)
            return f"Task {task_index} in plan {plan_index} updated to {status}"
        except (ValueError, IndexError) as exc:
            return f"Error: {exc}"

    def remove_task_from_plan(self, plan_index: str, task_index: str) -> str:
        try:
            self.state.remove_task_from_plan(int(plan_index), int(task_index))
            return f"Task {task_index} removed from plan {plan_index}"
        except (ValueError, IndexError) as exc:
            return f"Error: {exc}"

    def remove_action_plan(self, plan_index: str) -> str:
        try:
            self.state.remove_action_plan(int(plan_index))
            return f"Action plan {plan_index} removed"
        except (ValueError, IndexError) as exc:
            return f"Error: {exc}"

    def add_memory(self, key: str, value: str, category: str, priority: str = "MEDIUM", tags: Any = None) -> str:
        parsed_tags = self._tags(tags) or ["short_term"]
        self.state.add_memory(key, value, category=category or "chatbot_short_term", priority=priority, tags=parsed_tags)
        return f"Memory stored successfully (Key: {key}, Category: {category}, Priority: {priority.upper()})"

    def remove_memory(self, memory_id: str | None = None, key: str | None = None, index: str | None = None) -> str:
        try:
            self.state.remove_memory(memory_id=memory_id or None, key=key or None, index=int(index) if index else None)
            return f"Memory with id '{memory_id}' removed" if memory_id else f"Memory with key '{key}' removed"
        except (ValueError, KeyError, IndexError) as exc:
            return f"Error: {exc}"

    def search_memory(self, query: str, top_k: str = "5") -> str:
        if not query.strip():
            return "Error: query is required for search_memory."
        results = self.state.memory_store.search_memories(query, max(1, min(int(top_k or 5), 20)))
        if not results:
            return f"No memory results found for '{query}'."
        return "\n".join([f"Found {len(results)} memory result(s) for '{query}':"] + [f"  {index}. [{item.memory.category}] {item.memory.get_display_content()}" for index, item in enumerate(results, 1)])

    def list_functions(self, pattern: str = "", limit: str = "500") -> str:
        try:
            raw_functions = self.bridge.list_functions(pattern, max(1, min(int(limit or 500), 1000)))
            functions = raw_functions.get("functions", []) if isinstance(raw_functions, dict) else raw_functions
        except Exception as exc:
            return f"Error: {exc}"
        if not functions:
            return "No functions matched the pattern."
        result = "\n".join(f"{item.get('name')} @ {item.get('address', {}).get('offset', '')}" for item in functions)
        return result + (f"\n... (Output truncated at {limit} functions. Use 'pattern' to narrow down your search.)" if len(functions) >= int(limit or 500) else "")

    def get_function_pseudocode(self, function_name: str) -> str:
        result = self.bridge.get_function_pseudocode(function_name)
        code = result.get("code") if isinstance(result, dict) else result
        return code or f"Function '{function_name}' not found."

    def search_function_index(self, query: str) -> str:
        from ..features.indexing.manager import FunctionIndexManager
        from ..features.indexing.search import search_index
        metadata = self.bridge.get_program_metadata()
        return search_index(FunctionIndexManager.get(metadata), query)

    def add_to_function_list(self, func_name: str) -> str:
        return self.state.add_to_function_list(func_name)

    def remove_from_function_list(self, func_name: str) -> str:
        try:
            self.state.remove_from_function_list(func_name)
            return f"Function '{func_name}' removed from the list"
        except KeyError as exc:
            return f"Error: {exc}"

    def get_data_at_address(self, location: str, count: str = "16") -> str:
        try:
            result = self.bridge.get_data_at_address(location, int(count or 16)) or {}
        except Exception as exc:
            return f"Error: Could not resolve address/name '{location}': {exc}"
        if not result.get("ea"):
            return f"Error: Could not resolve address/name '{location}'."
        return json.dumps(result, indent=2, default=str)

    def get_xrefs_to(self, location: str) -> str:
        try:
            result = self.bridge.get_xrefs_to(location) or {}
        except Exception as exc:
            return f"Error: {exc}"
        return json.dumps(result, indent=2, default=str) if result.get("total", 0) else f"No cross-references found for '{location}'."

    def rename_function(self, function_name: str, name: str) -> str:
        if self.staging is None:
            raise RuntimeError("Mutation tools require an active run staging buffer.")
        return self.staging.stage_function("rename_function", function_name, name, self._function_resolver())

    def rename_variable(self, function_name: str, variable_name: str, name: str) -> str:
        if self.staging is None:
            raise RuntimeError("Mutation tools require an active run staging buffer.")
        return self.staging.stage_variable(function_name, variable_name, name, self._function_resolver())

    def retype_variable(self, function_name: str, variable_name: str, data_type: str) -> str:
        if self.staging is None:
            raise RuntimeError("Mutation tools require an active run staging buffer.")
        return self.staging.stage_variable_type(function_name, variable_name, data_type, self._function_resolver())

    def update_function_definition(self, function_name: str, return_type: str,
        parameters: list[dict[str, Any]], varargs: bool = False) -> str:
        if self.staging is None:
            raise RuntimeError("Mutation tools require an active run staging buffer.")
        return self.staging.stage_function_definition(
            function_name, return_type, parameters, varargs, self._function_resolver())

    def set_function_comment(self, function_name: str, comment: str) -> str:
        if self.staging is None:
            raise RuntimeError("Mutation tools require an active run staging buffer.")
        return self.staging.stage_function("set_function_comment", function_name, comment, self._function_resolver())

    def set_code_unit_comment(self, location: Any, comment_kind: str, comment: str) -> str:
        if self.staging is None:
            raise RuntimeError("Mutation tools require an active run staging buffer.")
        return self.staging.stage_code_comment(location, comment_kind, comment)

    def _function_resolver(self):
        return getattr(self.bridge, "resolve_function", lambda _function_name: None)

    def save_summary(self, summary: str) -> str:
        self.state.save_summary(summary)
        return "Conversation history summarized."

    @staticmethod
    def _tags(tags: Any) -> list[str]:
        if not tags:
            return []
        if isinstance(tags, (list, tuple)):
            return [str(item) for item in tags]
        if isinstance(tags, str):
            try:
                value = ast.literal_eval(tags)
                if isinstance(value, (list, tuple)):
                    return [str(item) for item in value]
            except (SyntaxError, ValueError):
                pass
            return [item.strip() for item in tags.split(",") if item.strip()]
        return [str(tags)]
