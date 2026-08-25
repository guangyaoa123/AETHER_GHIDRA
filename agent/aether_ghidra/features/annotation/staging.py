from __future__ import annotations

import json
from typing import Any, Callable


MUTATION_KINDS = frozenset({
    "rename_function",
    "rename_variable",
    "retype_variable",
    "update_function_definition",
    "set_function_comment",
    "set_code_unit_comment",
})
COMMENT_KINDS = frozenset({"eol", "pre", "post", "plate", "repeatable"})


def address_key(value: Any) -> str:
    if isinstance(value, dict):
        return f"{value.get('space', '')}:{value.get('offset', '')}"
    return str(value or "")


class MutationStaging:
    """Collect validated mutations until one atomic bridge batch is committed."""

    def __init__(
        self,
        context: dict[str, Any] | None = None,
        immediate_rename: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self.operations: list[dict[str, Any]] = []
        self.context = context
        self._targets: set[str] = set()
        self._function_aliases: dict[str, dict[str, Any]] = {}
        self._immediate_rename = immediate_rename
        self._immediate_results: list[dict[str, Any]] = []

    def function_target(self, function_name: str, resolver: Callable[[str], dict[str, Any] | None]) -> dict[str, Any]:
        aliased = self._function_aliases.get(function_name)
        if aliased is not None:
            return aliased
        if self.context is not None:
            matches = [item for item in self.context.get("functions", []) if str(item.get("name")) == function_name]
            if len(matches) != 1:
                raise ValueError(f"Function '{function_name}' is not in the frozen annotation context.")
            return matches[0]
        function = resolver(function_name)
        if function is None:
            raise ValueError(f"Function '{function_name}' not found.")
        return function

    def stage_function(self, kind: str, function_name: str, value: str, resolver: Callable[[str], dict[str, Any] | None]) -> str:
        function = self.function_target(function_name, resolver)
        operation = {"kind": kind, "target": {"function_address": function["address"]}, "value": str(value)}
        if kind == "rename_function" and self._immediate_rename is not None:
            operation["_immediate"] = True
            operation["_before"] = function.get("name", function_name)
            target_key = self._target_key(operation)
            if target_key in self._targets:
                raise ValueError("A mutation for this target is already staged.")
            self._targets.add(target_key)
            operation["id"] = f"immediate-{len(self.operations)}"
            try:
                result = self._immediate_rename(operation)
            except Exception:
                self._targets.remove(target_key)
                raise
            self.operations.append(operation)
            self._immediate_results.append(result)
            self._function_aliases[str(value)] = function
            return f"Applied {kind} for '{function_name}'."
        self._add(operation)
        if kind == "rename_function":
            self._function_aliases[str(value)] = function
        return f"Staged {kind} for '{function_name}'."

    def stage_variable(
        self,
        function_name: str,
        variable_name: str,
        value: str,
        resolver: Callable[[str], dict[str, Any] | None],
    ) -> str:
        function = self.function_target(function_name, resolver)
        variables = [item for item in function.get("variables", []) if item.get("name") == variable_name]
        if self.context is not None and len(variables) != 1:
            raise ValueError(f"Variable '{variable_name}' is not uniquely present in the frozen annotation context.")
        if variables and variables[0].get("auto_parameter"):
            raise ValueError(f"Variable '{variable_name}' is an auto-parameter and cannot be renamed.")
        target = {"function_address": function["address"], "variable_name": variable_name}
        self._add({"kind": "rename_variable", "target": target, "value": str(value)})
        return f"Staged rename_variable for '{function_name}:{variable_name}'."

    def stage_variable_type(
        self,
        function_name: str,
        variable_name: str,
        data_type: str,
        resolver: Callable[[str], dict[str, Any] | None],
    ) -> str:
        function = self.function_target(function_name, resolver)
        variables = [item for item in function.get("variables", []) if item.get("name") == variable_name]
        if self.context is not None and len(variables) != 1:
            raise ValueError(f"Variable '{variable_name}' is not uniquely present in the frozen annotation context.")
        target = {"function_address": function["address"], "variable_name": variable_name}
        self._add({"kind": "retype_variable", "target": target, "value": str(data_type).strip()})
        return f"Staged retype_variable for '{function_name}:{variable_name}'."

    def stage_function_definition(
        self,
        function_name: str,
        return_type: str,
        parameters: list[dict[str, Any]],
        varargs: bool = False,
        resolver: Callable[[str], dict[str, Any] | None] | None = None,
    ) -> str:
        if resolver is None:
            raise ValueError("A function resolver is required.")
        function = self.function_target(function_name, resolver)
        if not isinstance(parameters, list):
            raise ValueError("parameters must be an array.")
        normalized: list[dict[str, Any]] = []
        seen_names: set[str] = set()
        for parameter in parameters:
            if not isinstance(parameter, dict):
                raise ValueError("Each parameter must be an object.")
            name = str(parameter.get("name", "")).strip()
            data_type = str(parameter.get("data_type", "")).strip()
            if not name or not data_type or name in seen_names:
                raise ValueError("Each parameter needs a unique name and data_type.")
            seen_names.add(name)
            item = {"name": name, "data_type": data_type}
            if "storage" in parameter:
                item["storage"] = parameter["storage"]
            normalized.append(item)
        definition = {
            "return_type": str(return_type).strip(),
            "parameters": normalized,
            "varargs": bool(varargs),
        }
        if not definition["return_type"]:
            raise ValueError("return_type is required.")
        self._add({
            "kind": "update_function_definition",
            "target": {"function_address": function["address"]},
            "value": json.dumps(definition, separators=(",", ":")),
            "definition": definition,
        })
        return f"Staged update_function_definition for '{function_name}'."

    def stage_code_comment(self, location: Any, comment_kind: str, comment: str) -> str:
        if comment_kind not in COMMENT_KINDS:
            raise ValueError(f"Unsupported comment_kind '{comment_kind}'.")
        key = address_key(location)
        if not key:
            raise ValueError("location is required.")
        if self.context is not None:
            code_units = list(self.context.get("code_units", []))
            code_units.extend(
                item
                for function in self.context.get("functions", [])
                for item in function.get("code_units", [])
            )
            anchors = {address_key(item.get("address")) for item in code_units}
            if not any(key == candidate or key.endswith(candidate.split(":", 1)[-1]) for candidate in anchors):
                raise ValueError("Code-comment location is not in the frozen annotation context.")
        self._add({
            "kind": "set_code_unit_comment",
            "target": {"address": location},
            "comment_kind": comment_kind,
            "value": str(comment),
        })
        return f"Staged set_code_unit_comment at '{key}'."

    def _add(self, operation: dict[str, Any]) -> None:
        function_address = operation.get("target", {}).get("function_address")
        if function_address is not None:
            for existing in self.operations:
                if existing.get("target", {}).get("function_address") != function_address:
                    continue
                if {existing.get("kind"), operation.get("kind")} & {"update_function_definition"}:
                    raise ValueError("A full function-definition update conflicts with another mutation for this function.")
        target_key = self._target_key(operation)
        if target_key in self._targets:
            raise ValueError("A mutation for this target is already staged.")
        self._targets.add(target_key)
        operation["id"] = f"staged-{len(self.operations)}"
        self.operations.append(operation)

    @staticmethod
    def _target_key(operation: dict[str, Any]) -> str:
        return f"{operation['kind']}:{json.dumps(operation['target'], sort_keys=True, default=str)}"

    def discard(self) -> None:
        self.operations.clear()
        self._targets.clear()
        self._function_aliases.clear()
        self._immediate_results.clear()

    def immediate_result(self) -> dict[str, Any] | None:
        if not self._immediate_results:
            return None
        return {
            "batch_id": self._immediate_results[-1].get("batch_id"),
            "operations": [
                operation
                for result in self._immediate_results
                for operation in result.get("operations", [])
            ],
        }

    def commit(self, invoke: Callable[[str, dict[str, Any]], dict[str, Any]]) -> dict[str, Any] | None:
        pending = [operation for operation in self.operations if not operation.get("_immediate")]
        immediate = self.immediate_result()
        if not pending and immediate is None:
            return None
        applied_operations = list((immediate or {}).get("operations", []))
        pending_result = None
        if pending:
            pending_result = invoke("apply_annotation_batch", {"operations": pending})
            applied_operations.extend(pending_result.get("operations", []))
        batch_id = (pending_result or immediate).get("batch_id")
        return {"batch_id": batch_id, "operations": applied_operations}
