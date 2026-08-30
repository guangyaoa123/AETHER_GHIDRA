from __future__ import annotations

import ast
import json
import re
from enum import StrEnum
from typing import Any

from ..features.annotation.staging import MutationStaging
from ..integrations.ghidra.chatbot_backend import GhidraChatbotBackendBridge
from ..integrations.ghidra.identity import class_reference, data_type_path as normalize_data_type_path, function_ref as normalize_function_ref, structured_address, structure_path as normalize_structure_path


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
    GET_FUNCTION = "get_function"
    GET_DATA_AT_ADDRESS = "get_data_at_address"
    GET_XREFS_TO = "get_xrefs_to"
    RESOLVE_PSEUDOCODE_CALL = "resolve_pseudocode_call"
    LIST_STRUCT = "list_struct"
    GET_STRUCT = "get_struct"
    CREATE_STRUCT = "create_struct"
    ADD_FIELDS = "add_fields"
    UPDATE_FIELDS = "update_fields"
    REMOVE_FIELDS = "remove_fields"
    RESIZE_STRUCT = "resize_struct"
    CREATE_CLASS = "create_class"
    UPDATE_CLASS = "update_class"
    DELETE_CLASS = "delete_class"
    RENAME_FUNCTION = "rename_function"
    RENAME_VARIABLE = "rename_variable"
    RETYPE_VARIABLE = "retype_variable"
    UPDATE_FUNCTION_DEFINITION = "update_function_definition"
    SET_FUNCTION_COMMENT = "set_function_comment"
    SET_CODE_UNIT_COMMENT = "set_code_unit_comment"
    SAVE_SUMMARY = "save_summary"


class ToolGroup(StrEnum):
    PROGRAM_READ = "program_read"
    PROGRAM_WRITE = "program_write"
    PLANNING = "planning"
    MEMORY = "memory"
    CONVERSATION = "conversation"
    ANNOTATION_READ = "annotation_read"
    ANNOTATION_WRITE = "annotation_write"


TOOL_GROUPS: dict[ToolGroup, tuple[ToolNames, ...]] = {
    ToolGroup.PROGRAM_READ: (
        ToolNames.LIST_FUNCTIONS,
        ToolNames.GET_FUNCTION,
        ToolNames.GET_DATA_AT_ADDRESS,
        ToolNames.GET_XREFS_TO,
        ToolNames.RESOLVE_PSEUDOCODE_CALL,
        ToolNames.LIST_STRUCT,
        ToolNames.GET_STRUCT,
        ToolNames.SEARCH_FUNCTION_INDEX,
    ),
    ToolGroup.PROGRAM_WRITE: (
        ToolNames.RENAME_FUNCTION,
        ToolNames.RENAME_VARIABLE,
        ToolNames.RETYPE_VARIABLE,
        ToolNames.UPDATE_FUNCTION_DEFINITION,
        ToolNames.SET_FUNCTION_COMMENT,
        ToolNames.SET_CODE_UNIT_COMMENT,
        ToolNames.CREATE_STRUCT,
        ToolNames.ADD_FIELDS,
        ToolNames.UPDATE_FIELDS,
        ToolNames.REMOVE_FIELDS,
        ToolNames.RESIZE_STRUCT,
        ToolNames.CREATE_CLASS,
        ToolNames.UPDATE_CLASS,
        ToolNames.DELETE_CLASS,
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
    "get_function": ToolNames.GET_FUNCTION.value,
    "get_data_at_address": ToolNames.GET_DATA_AT_ADDRESS.value,
    "get_xrefs_to": ToolNames.GET_XREFS_TO.value,
    "resolve_pseudocode_call": ToolNames.RESOLVE_PSEUDOCODE_CALL.value,
    "list_struct": ToolNames.LIST_STRUCT.value,
    "get_struct": ToolNames.GET_STRUCT.value,
    "create_struct": ToolNames.CREATE_STRUCT.value,
    "add_fields": ToolNames.ADD_FIELDS.value,
    "update_fields": ToolNames.UPDATE_FIELDS.value,
    "remove_fields": ToolNames.REMOVE_FIELDS.value,
    "resize_struct": ToolNames.RESIZE_STRUCT.value,
    "create_class": ToolNames.CREATE_CLASS.value,
    "update_class": ToolNames.UPDATE_CLASS.value,
    "delete_class": ToolNames.DELETE_CLASS.value,
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


ADDRESS_SCHEMA = {
    "type": "object",
    "properties": {"space": {"type": "string"}, "offset": {"type": "string"}},
    "required": ["space", "offset"],
    "additionalProperties": False,
}
FUNCTION_REF_SCHEMA = {
    "type": "object",
    "properties": {
        "address": ADDRESS_SCHEMA, "name": {"type": "string"}, "qualified_name": {"type": "string"}, "signature": {"type": "string"},
        "namespace": {"type": "string"}, "comment": {"type": "string"},
        "external": {"type": "boolean"}, "thunk": {"type": "boolean"},
        "default_name": {"type": "boolean"}, "return_type": {"type": "string"},
        "calling_convention": {"type": "string"}, "varargs": {"type": "boolean"},
        "custom_storage": {"type": "boolean"}, "parameters": {"type": "array"},
    },
    "required": ["address"],
    "additionalProperties": True,
}
CLASS_REF_SCHEMA = {
    "type": "object",
    "properties": {"class_id": {"type": "string"}, "structure_path": {"type": "string"}},
    "minProperties": 1,
    "additionalProperties": False,
}
FIELD_SCHEMA = {
    "type": "object",
    "properties": {
        "offset": {"type": "integer"}, "name": {"type": "string"},
        "data_type_path": {"type": "string"}, "length": {"type": "integer"},
        "comment": {"type": "string"},
    },
    "required": ["offset", "data_type_path"],
}
UPDATE_FIELD_SCHEMA = {
    "type": "object",
    "properties": {
        "offset": {"type": "integer"}, "name": {"type": "string"},
        "data_type_path": {"type": "string"}, "length": {"type": "integer"},
        "comment": {"type": "string"},
    },
    "required": ["offset"],
}


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
    ToolNames.GET_FUNCTION: _spec("Retrieve one exact function by function_ref, committing current decompiler locals and parameters and returning metadata, address-aware pseudocode, and resolved calls.", {"function_ref": FUNCTION_REF_SCHEMA}, ["function_ref"]),
    ToolNames.GET_DATA_AT_ADDRESS: _spec("Inspect bytes, disassembly, strings, and context at this exact structured address.", {"location": ADDRESS_SCHEMA, "count": {"type": "string"}}, ["location"]),
    ToolNames.GET_XREFS_TO: _spec("List cross-references to this exact structured address.", {"location": ADDRESS_SCHEMA}, ["location"]),
    ToolNames.RESOLVE_PSEUDOCODE_CALL: _spec("Resolve one pseudocode call at an exact call site in an exact caller. Returns a rich function_ref; display_name is only a hint.", {"caller_address": ADDRESS_SCHEMA, "call_site": ADDRESS_SCHEMA, "display_name": {"type": "string"}}, ["caller_address", "call_site"]),
    ToolNames.LIST_STRUCT: _spec("List Ghidra structures, including class-backed structures and inheritance summaries.", {"pattern": {"type": "string"}, "kind": {"type": "string", "enum": ["struct", "class"]}, "limit": {"type": "string"}}),
    ToolNames.GET_STRUCT: _spec("Inspect a Ghidra structure or class-backed structure by its exact full structure_path.", {"structure_path": {"type": "string"}}, ["structure_path"]),
    ToolNames.RENAME_FUNCTION: _spec("Immediately rename the exact function_ref. The new name is visible to subsequent tool calls.", {"function_ref": FUNCTION_REF_SCHEMA, "name": {"type": "string"}}, ["function_ref", "name"]),
    ToolNames.RENAME_VARIABLE: _spec("Stage a local or parameter variable rename identified by exact function_ref and variable_name.", {"function_ref": FUNCTION_REF_SCHEMA, "variable_name": {"type": "string"}, "name": {"type": "string"}}, ["function_ref", "variable_name", "name"]),
    ToolNames.RETYPE_VARIABLE: _spec("Stage a local or function-parameter data type path change for an exact function_ref.", {"function_ref": FUNCTION_REF_SCHEMA, "variable_name": {"type": "string"}, "data_type_path": {"type": "string"}}, ["function_ref", "variable_name", "data_type_path"]),
    ToolNames.UPDATE_FUNCTION_DEFINITION: _spec("Stage an atomic function prototype update for an exact function_ref. The ordered parameter list may add, remove, rename, reorder, or retype arguments.", {"function_ref": FUNCTION_REF_SCHEMA, "return_type": {"oneOf": [{"type": "string"}, {"type": "object"}]}, "return_type_path": {"type": "string"}, "parameters": {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}, "data_type_path": {"type": "string"}, "storage": {"type": "object"}}, "required": ["name", "data_type_path"]}}, "varargs": {"type": "boolean"}}, ["function_ref", "return_type", "parameters"]),
    ToolNames.SET_FUNCTION_COMMENT: _spec("Stage a Ghidra function comment update for an exact function_ref. Changes are committed atomically after the agent run.", {"function_ref": FUNCTION_REF_SCHEMA, "comment": {"type": "string"}}, ["function_ref", "comment"]),
    ToolNames.SET_CODE_UNIT_COMMENT: _spec("Stage a comment on this exact structured address in the frozen Ghidra context.", {"location": ADDRESS_SCHEMA, "comment_kind": {"type": "string", "enum": ["eol", "pre", "post", "plate", "repeatable"]}, "comment": {"type": "string"}}, ["location", "comment_kind", "comment"]),
    ToolNames.CREATE_STRUCT: _spec("Immediately create a native Ghidra structure. Fields identify data types with data_type_path.", {"name": {"type": "string"}, "category": {"type": "string"}, "size": {"type": "integer"}, "fields": {"type": "array", "items": FIELD_SCHEMA}}, ["name"]),
    ToolNames.ADD_FIELDS: _spec("Immediately add non-overlapping fields to a Ghidra structure identified by its exact structure_path.", {"structure_path": {"type": "string"}, "fields": {"type": "array", "items": FIELD_SCHEMA}}, ["structure_path", "fields"]),
    ToolNames.UPDATE_FIELDS: _spec("Immediately update fields in a Ghidra structure identified by its exact structure_path.", {"structure_path": {"type": "string"}, "fields": {"type": "array", "items": UPDATE_FIELD_SCHEMA}}, ["structure_path", "fields"]),
    ToolNames.REMOVE_FIELDS: _spec("Immediately remove defined fields from a Ghidra structure identified by its exact structure_path.", {"structure_path": {"type": "string"}, "offsets": {"type": "array", "items": {"type": "integer"}}, "fields": {"type": "array", "items": UPDATE_FIELD_SCHEMA}}, ["structure_path"]),
    ToolNames.RESIZE_STRUCT: _spec("Immediately resize a Ghidra structure identified by its exact structure_path.", {"structure_path": {"type": "string"}, "size": {"type": "integer"}}, ["structure_path", "size"]),
    ToolNames.CREATE_CLASS: _spec("Immediately associate a C++ class model with a native Ghidra structure. Use structure_path for an existing backing structure; fields identify data types with data_type_path.", {"name": {"type": "string"}, "structure_path": {"type": "string"}, "category": {"type": "string"}, "size": {"type": "integer"}, "fields": {"type": "array", "items": FIELD_SCHEMA}, "bases": {"type": "array", "items": {"type": "object"}}, "vtables": {"type": "array", "items": {"type": "object"}}, "methods": {"type": "array", "items": {"type": "object"}}, "rtti": {"type": "object"}}, ["name"]),
    ToolNames.UPDATE_CLASS: _spec("Immediately update a class model selected by class_ref or structure_path.", {"class_ref": CLASS_REF_SCHEMA, "structure_path": {"type": "string"}, "bases": {"type": "array", "items": {"type": "object"}}, "vtables": {"type": "array", "items": {"type": "object"}}, "methods": {"type": "array", "items": {"type": "object"}}, "rtti": {"type": "object"}, "confidence": {"type": "string"}}, []),
    ToolNames.DELETE_CLASS: _spec("Immediately remove AETHER class metadata without deleting the backing Ghidra structure. Select it by class_ref or structure_path.", {"class_ref": CLASS_REF_SCHEMA, "structure_path": {"type": "string"}}, []),
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

    def list_functions(self, pattern: str = "", limit: str = "50") -> str:
        try:
            raw_functions = self.bridge.list_functions(pattern, max(1, min(int(limit or 50), 1000)))
            functions = raw_functions.get("functions", []) if isinstance(raw_functions, dict) else raw_functions
        except Exception as exc:
            return f"Error: {exc}"
        if not functions:
            return "No functions matched the pattern."
        result = "\n".join(json.dumps({
            "address": item.get("address"),
            "definition": item.get("definition", item.get("signature", "")),
        }, default=str) for item in functions)
        return result + (f"\n... (Output truncated at {limit} functions. Use 'pattern' to narrow down your search.)" if len(functions) >= int(limit or 50) else "")

    def get_function(self, function_ref: dict[str, Any]) -> str:
        target = normalize_function_ref(function_ref)
        result = self.bridge.get_function(target)
        if not isinstance(result, dict):
            return str(result)
        if not result.get("address"):
            return f"Function target '{target['address']}' not found."
        result.pop("function_ref", None)
        return json.dumps(result, indent=2, default=str)

    def search_function_index(self, query: str) -> str:
        from ..features.indexing.manager import FunctionIndexManager
        from ..features.indexing.search import search_index
        metadata = self.bridge.get_program_metadata()
        return search_index(FunctionIndexManager.get(metadata), query)

    def get_data_at_address(self, location: dict[str, Any], count: str = "16") -> str:
        try:
            result = self.bridge.get_data_at_address(structured_address(location, "location"), int(count or 16)) or {}
        except Exception as exc:
            return f"Error: Could not resolve address/name '{location}': {exc}"
        if not result.get("ea"):
            return f"Error: Could not resolve address/name '{location}'."
        return json.dumps(result, indent=2, default=str)

    def get_xrefs_to(self, location: dict[str, Any]) -> str:
        try:
            result = self.bridge.get_xrefs_to(structured_address(location, "location")) or {}
        except Exception as exc:
            return f"Error: {exc}"
        return json.dumps(result, indent=2, default=str) if result.get("total", 0) else f"No cross-references found for '{location}'."

    def resolve_pseudocode_call(self, caller_address: dict[str, Any], call_site: dict[str, Any], display_name: str = "") -> str:
        try:
            result = self.bridge.resolve_pseudocode_call(caller_address, call_site, display_name or None)
            return json.dumps(result, indent=2, default=str)
        except Exception as exc:
            return f"Error: {exc}"

    def list_struct(self, pattern: str = "", kind: str = "", limit: str = "100") -> str:
        try:
            result = self.bridge._invoke("list_struct", {
                "pattern": pattern, "kind": kind, "limit": max(1, min(int(limit or 100), 1000))})
            return json.dumps(self._decorate_structures(result), indent=2, default=str)
        except Exception as exc:
            return f"Error: {exc}"

    def get_struct(self, structure_path: str) -> str:
        try:
            result = self.bridge._invoke("get_struct", {"path": normalize_structure_path(structure_path)})
            return json.dumps(self._decorate_structure(result), indent=2, default=str)
        except Exception as exc:
            return f"Error: {exc}"

    def _write_struct(self, capability: str, arguments: dict[str, Any]) -> str:
        try:
            return json.dumps(self.bridge._invoke(capability, arguments), indent=2, default=str)
        except Exception as exc:
            return f"Error: {exc}"

    def create_struct(self, name: str, category: str = "", size: int = 0, fields: Any = None) -> str:
        return self._write_struct("create_struct", {"name": name, "category": category, "size": size, "fields": self._fields(fields or [], require_data_type=True)})

    def add_fields(self, structure_path: str, fields: list[dict[str, Any]]) -> str:
        return self._write_struct("add_fields", {"path": normalize_structure_path(structure_path), "fields": self._fields(fields, require_data_type=True)})

    def update_fields(self, structure_path: str, fields: list[dict[str, Any]]) -> str:
        return self._write_struct("update_fields", {"path": normalize_structure_path(structure_path), "fields": self._fields(fields)})

    def remove_fields(self, structure_path: str, offsets: Any = None, fields: Any = None) -> str:
        return self._write_struct("remove_fields", {"path": normalize_structure_path(structure_path), "offsets": offsets or [], "fields": self._fields(fields or [])})

    def resize_struct(self, structure_path: str, size: int) -> str:
        return self._write_struct("resize_struct", {"path": normalize_structure_path(structure_path), "size": size})

    def create_class(self, name: str, structure_path: str = "", category: str = "", size: int = 0,
        fields: Any = None, bases: Any = None, vtables: Any = None, methods: Any = None,
        rtti: Any = None) -> str:
        arguments = {"name": name, "category": category, "size": size, "fields": self._fields(fields or [], require_data_type=True),
            "vtables": vtables or [], "methods": methods or [], "rtti": rtti}
        if structure_path:
            arguments["structure"] = normalize_structure_path(structure_path)
        if bases:
            arguments["bases"] = self._class_bases(bases)
        else:
            arguments["bases"] = []
        return self._write_struct("create_class", arguments)

    def update_class(self, class_ref: Any = None, structure_path: str = "", bases: Any = None, vtables: Any = None,
        methods: Any = None, rtti: Any = None, confidence: str = "") -> str:
        arguments = self._class_target(class_ref, structure_path)
        for key, value in {"bases": bases, "vtables": vtables, "methods": methods,
            "rtti": rtti, "confidence": confidence}.items():
            if value not in (None, ""):
                arguments[key] = self._class_bases(value) if key == "bases" else value
        return self._write_struct("update_class", arguments)

    def delete_class(self, class_ref: Any = None, structure_path: str = "") -> str:
        return self._write_struct("delete_class", self._class_target(class_ref, structure_path))

    def rename_function(self, function_ref: dict[str, Any], name: str) -> str:
        if self.staging is None:
            raise RuntimeError("Mutation tools require an active run staging buffer.")
        return self.staging.stage_function("rename_function", function_ref, name, self._function_resolver())

    def rename_variable(self, function_ref: dict[str, Any], variable_name: str, name: str) -> str:
        if self.staging is None:
            raise RuntimeError("Mutation tools require an active run staging buffer.")
        return self.staging.stage_variable(function_ref, variable_name, name, self._function_resolver())

    def retype_variable(self, function_ref: dict[str, Any], variable_name: str, data_type_path: str) -> str:
        if self.staging is None:
            raise RuntimeError("Mutation tools require an active run staging buffer.")
        return self.staging.stage_variable_type(function_ref, variable_name, data_type_path, self._function_resolver())

    def update_function_definition(self, function_ref: dict[str, Any], return_type: Any = None,
        parameters: list[dict[str, Any]] | None = None, varargs: bool = False,
        return_type_path: Any = None) -> str:
        if self.staging is None:
            raise RuntimeError("Mutation tools require an active run staging buffer.")
        if return_type_path is not None:
            if return_type is not None:
                raise ValueError("Provide return_type or return_type_path, not both")
            return_type = return_type_path
        if return_type is None or parameters is None:
            raise ValueError("return_type and parameters are required")
        return self.staging.stage_function_definition(
            function_ref, return_type, parameters, varargs, self._function_resolver())

    def set_function_comment(self, function_ref: dict[str, Any], comment: str) -> str:
        if self.staging is None:
            raise RuntimeError("Mutation tools require an active run staging buffer.")
        return self.staging.stage_function("set_function_comment", function_ref, comment, self._function_resolver())

    def set_code_unit_comment(self, location: Any, comment_kind: str, comment: str) -> str:
        if self.staging is None:
            raise RuntimeError("Mutation tools require an active run staging buffer.")
        return self.staging.stage_code_comment(location, comment_kind, comment)

    def _function_resolver(self):
        resolver = getattr(self.bridge, "resolve_function", lambda _function_ref: None)
        return lambda target: resolver(normalize_function_ref(target))

    def _class_target(self, class_ref_value: Any, structure_path_value: str) -> dict[str, Any]:
        if class_ref_value is not None:
            reference = class_reference(class_ref_value)
        elif structure_path_value:
            path = normalize_structure_path(structure_path_value)
            reference = {"structure_path": path}
        else:
            raise ValueError("Provide class_ref or structure_path.")
        arguments: dict[str, Any] = {}
        if reference.get("class_id"):
            arguments["class_id"] = reference["class_id"]
        if reference.get("name"):
            arguments["name"] = reference["name"]
        if reference.get("structure_path"):
            arguments["structure"] = reference["structure_path"]
        if not arguments:
            raise ValueError("class_ref must include a class_id or structure_path")
        return arguments

    @classmethod
    def _decorate_structures(cls, result: Any) -> Any:
        if not isinstance(result, dict):
            return result
        decorated = dict(result)
        if isinstance(result.get("structures"), list):
            decorated["structures"] = [cls._decorate_structure(item) for item in result["structures"]]
        return decorated

    @staticmethod
    def _decorate_structure(result: Any) -> Any:
        if not isinstance(result, dict):
            return result
        decorated = dict(result)
        path = decorated.get("path")
        if path:
            decorated.setdefault("structure_path", path)
        class_details = decorated.get("class")
        if path:
            decorated.setdefault("class_ref", {"structure_path": path})
        return decorated

    @staticmethod
    def _fields(fields: Any, *, require_data_type: bool = False) -> list[dict[str, Any]]:
        if not isinstance(fields, list):
            raise ValueError("fields must be an array")
        normalized = []
        for field in fields:
            if not isinstance(field, dict):
                raise ValueError("Each field must be an object")
            item = dict(field)
            if "data_type" in item and "data_type_path" not in item:
                raise ValueError("Use data_type_path for field data types")
            if "data_type_path" in item:
                item["data_type"] = normalize_data_type_path(item.pop("data_type_path"))
            elif require_data_type:
                raise ValueError("Each field requires data_type_path")
            normalized.append(item)
        return normalized

    @staticmethod
    def _class_bases(bases: Any) -> list[Any]:
        if not isinstance(bases, list):
            raise ValueError("bases must be an array")
        normalized = []
        for base in bases:
            if not isinstance(base, dict):
                raise ValueError("Each base must be a class_ref or structure_path object")
            item = dict(base)
            reference = item.pop("class_ref", None)
            if reference is not None:
                reference_normalized = class_reference(reference)
                if reference_normalized.get("class_id"):
                    item["class_id"] = reference_normalized["class_id"]
                if reference_normalized.get("name"):
                    item["name"] = reference_normalized["name"]
                if reference_normalized.get("structure_path"):
                    item["structure"] = reference_normalized["structure_path"]
            if "structure_path" in item:
                item["structure"] = normalize_structure_path(item.pop("structure_path"))
            normalized.append(item)
        return normalized

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
