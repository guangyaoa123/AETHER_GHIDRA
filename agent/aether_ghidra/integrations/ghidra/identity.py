from __future__ import annotations

import json
from typing import Any


def structured_address(value: Any, label: str = "address") -> dict[str, Any]:
    """Normalize flexible address spellings into {"space": ..., "offset": ...}.

    Accepted inputs, all unambiguous:
    - {"space": "ram", "offset": "00542150"} (canonical; space is optional and
      defaults to the Program's default address space on the Java side)
    - {"address": {...}} nested wrappers
    - a JSON string encoding an address object (common double-encoding from
      LLM tool calls)
    - "ram:0x542150", "ram:00542150", "0x542150", "00542150"
    - integer offsets
    """
    expected = (f'{label} must be a structured address object like {{"space": "ram", "offset": "00542150"}} '
                f'or an address string like "ram:0x542150"')
    value = _unwrap_address_value(value)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        space = value.get("space")
        if space is not None and str(space).strip():
            result["space"] = str(space).strip()
        result["offset"] = _normalized_offset(value.get("offset"), label, expected)
        return result
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError(f"{label} must not be empty; {expected}")
        if ":" in text:
            space, _, offset = text.partition(":")
            result = {"offset": _normalized_offset(offset, label, expected)}
            if space.strip():
                result["space"] = space.strip()
            return result
        return {"offset": _normalized_offset(text, label, expected)}
    if isinstance(value, int) and not isinstance(value, bool):
        return {"offset": format(value, "x")}
    raise ValueError(f"{expected}; got {type(value).__name__}")


def _unwrap_address_value(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{"):
            try:
                value = json.loads(text)
            except json.JSONDecodeError:
                pass
    if isinstance(value, dict) and "offset" not in value and "address" in value:
        return _unwrap_address_value(value["address"])
    return value


def _normalized_offset(value: Any, label: str, expected: str) -> str:
    if value is None or isinstance(value, bool):
        raise ValueError(f"{label} requires a non-empty offset; {expected}")
    if isinstance(value, int):
        return format(value, "x")
    text = str(value).strip()
    if not text:
        raise ValueError(f"{label} requires a non-empty offset; {expected}")
    if text.lower().startswith("0x"):
        text = text[2:].strip()
    try:
        int(text, 16)
    except ValueError:
        raise ValueError(f"{label} offset '{value}' is not a valid hex offset; {expected}") from None
    return text


def function_address(function_ref: Any) -> dict[str, Any]:
    """Return an address from a function reference, rejecting name-only targets."""
    if not isinstance(function_ref, dict):
        raise ValueError("function_ref must be an object containing a structured address")
    return structured_address(function_ref.get("address"), "function_ref.address")


def data_type_path(value: Any, label: str = "data_type_path") -> str:
    if isinstance(value, dict):
        value = value.get("data_type_path") or value.get("path")
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty data type path")
    return value.strip()


def type_specification(value: Any, label: str = "data_type_path") -> str:
    """Normalize a type spec, tolerating a leading slash before a bare name.

    "/undefined4" and "/int" become "undefined4" and "int"; full datatype
    paths ("/ClassDataTypes/Board/Board") and pointer forms are preserved
    (the Java bridge also tolerates "/undefined4 *").
    """
    text = data_type_path(value, label)
    if text.startswith("/") and "/" not in text[1:]:
        return text[1:].strip()
    return text


def function_ref(function_ref_value: Any) -> dict[str, Any]:
    address = function_address(function_ref_value)
    result = dict(function_ref_value)
    result["address"] = address
    return result


def structure_path(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("structure_path is required and must be a non-empty path")
    return value.strip()


def class_reference(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("class_ref must be an object containing a class_id or structure_path")
    class_id = value.get("class_id")
    path = value.get("structure_path") or value.get("path")
    result: dict[str, str] = {}
    if class_id is not None and str(class_id).strip():
        result["class_id"] = str(class_id).strip()
    if path is not None and str(path).strip():
        result["structure_path"] = str(path).strip()
    if not result:
        raise ValueError("class_ref requires a class_id or structure_path")
    return result


_FUNCTION_CAPABILITIES = frozenset({
    "get_function", "rename_function", "rename_variable",
    "retype_variable", "update_function_definition", "set_function_comment",
    "get_function_call_tree",
})
_LOCATION_CAPABILITIES = frozenset({"get_data_at_address", "get_xrefs_to"})
_PSEUDOCODE_CALL_CAPABILITY = "resolve_pseudocode_call"
_STRUCTURE_CAPABILITIES = frozenset({
    "get_struct", "add_fields", "update_fields", "remove_fields", "resize_struct",
})


def normalize_bridge_arguments(capability: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize public identity fields before they reach the permissive Java RPC."""
    result = dict(arguments or {})
    if capability == "get_function_by_name" or "function_name" in result or "func_name" in result:
        raise ValueError("Bare function-name targets are not supported; use a structured function_ref")

    if capability in _FUNCTION_CAPABILITIES:
        reference = result.pop("function_ref", None)
        if reference is not None:
            if "address" in result:
                raise ValueError("Provide function_ref or address, not both")
            result["address"] = function_address(reference)
        else:
            result["address"] = structured_address(result.get("address"), "address")

    if capability in _LOCATION_CAPABILITIES:
        if "function_ref" in result:
            raise ValueError("Use location for address targets, not function_ref")
        result["location"] = structured_address(result.get("location"), "location")

    if capability == _PSEUDOCODE_CALL_CAPABILITY:
        result["caller_address"] = structured_address(result.get("caller_address"), "caller_address")
        result["call_site"] = structured_address(result.get("call_site"), "call_site")
        if "display_name" in result and result["display_name"] is not None:
            if not isinstance(result["display_name"], str):
                raise ValueError("display_name must be a string")

    if capability in _STRUCTURE_CAPABILITIES:
        if "structure_path" in result:
            result["path"] = structure_path(result.pop("structure_path"))
        elif capability == "get_struct" and "path" not in result:
            raise ValueError("structure_path is required")
        elif capability != "get_struct" and "path" not in result:
            raise ValueError("structure_path is required")
        if isinstance(result.get("fields"), list):
            result["fields"] = _normalize_fields(result["fields"])

    if capability in {"create_struct", "create_class"} and isinstance(result.get("fields"), list):
        result["fields"] = _normalize_fields(result["fields"])
    if capability in {"create_class", "update_class", "delete_class"}:
        if "class_ref" in result:
            reference = class_reference(result.pop("class_ref"))
            if reference.get("class_id"):
                result["class_id"] = reference["class_id"]
            if reference.get("name"):
                result["name"] = reference["name"]
            if reference.get("structure_path"):
                result["structure"] = reference["structure_path"]
        if "structure_path" in result:
            result["structure"] = structure_path(result.pop("structure_path"))
        if isinstance(result.get("bases"), list):
            result["bases"] = _normalize_class_bases(result["bases"])

    if capability == "set_code_unit_comment":
        location = result.get("location", result.get("address"))
        result["location"] = structured_address(location, "location")

    if capability == "get_annotation_context":
        functions = result.get("functions")
        if not isinstance(functions, list):
            raise ValueError("functions must be an array of structured function references")
        result["functions"] = [{"address": function_address(item.get("function_ref", item) if isinstance(item, dict) else item)} for item in functions]

    if capability == "apply_annotation_batch":
        operations = result.get("operations")
        if not isinstance(operations, list):
            raise ValueError("operations must be an array")
        normalized_operations = []
        for operation in operations:
            if not isinstance(operation, dict):
                raise ValueError("Each annotation operation must be an object")
            item = dict(operation)
            target = dict(item.get("target") or {})
            if item.get("kind") == "set_code_unit_comment":
                target["address"] = structured_address(target.get("address"), "location")
            else:
                target_ref = target.get("function_ref")
                if target_ref is not None:
                    target["function_address"] = function_address(target_ref)
                    target.pop("function_ref", None)
                else:
                    target["function_address"] = structured_address(target.get("function_address"), "function_address")
            item["target"] = target
            if item.get("kind") == "update_function_definition":
                definition = item.get("definition")
                if isinstance(definition, dict):
                    definition = _normalize_definition(definition)
                    item["definition"] = definition
                    item["value"] = json.dumps(definition, separators=(",", ":"))
            normalized_operations.append(item)
        result["operations"] = normalized_operations

    if capability == "retype_variable" and "data_type_path" in result:
        result["data_type"] = type_specification(result.pop("data_type_path"))
    if capability == "update_function_definition":
        if "return_type_path" in result:
            if "return_type" in result:
                raise ValueError("Provide return_type or return_type_path, not both")
            result["return_type"] = data_type_path(result.pop("return_type_path"), "return_type_path")
        result.update(_normalize_definition(result))
    return result


def _normalize_fields(fields: list[Any]) -> list[dict[str, Any]]:
    normalized = []
    for field in fields:
        if not isinstance(field, dict):
            raise ValueError("Each field must be an object")
        item = dict(field)
        if "data_type_path" in item:
            item["data_type"] = type_specification(item.pop("data_type_path"))
        normalized.append(item)
    return normalized


def _normalize_class_bases(bases: list[Any]) -> list[dict[str, Any]]:
    normalized = []
    for base in bases:
        if not isinstance(base, dict):
            raise ValueError("Each base must be a class reference object")
        item = dict(base)
        reference_value = item.pop("class_ref", None)
        if reference_value is not None:
            reference = class_reference(reference_value)
            if reference.get("class_id"):
                item["class_id"] = reference["class_id"]
            if reference.get("name"):
                item["name"] = reference["name"]
            if reference.get("structure_path"):
                item["structure"] = reference["structure_path"]
        if "structure_path" in item:
            item["structure"] = structure_path(item.pop("structure_path"))
        normalized.append(item)
    return normalized


def _normalize_definition(definition: dict[str, Any]) -> dict[str, Any]:
    result = dict(definition)
    if "return_type_path" in result:
        if "return_type" in result:
            raise ValueError("Provide return_type or return_type_path, not both")
        result["return_type"] = data_type_path(result.pop("return_type_path"), "return_type_path")
    if isinstance(result.get("return_type"), dict):
        result["return_type"] = data_type_path(result["return_type"], "return_type")
    parameters = result.get("parameters")
    if isinstance(parameters, list):
        result["parameters"] = _normalize_fields_in_definition(parameters)
    return result


def _normalize_fields_in_definition(parameters: list[Any]) -> list[dict[str, Any]]:
    normalized = []
    for parameter in parameters:
        if not isinstance(parameter, dict):
            raise ValueError("Each parameter must be an object")
        item = dict(parameter)
        if "data_type_path" in item:
            item["data_type"] = data_type_path(item.pop("data_type_path"))
        normalized.append(item)
    return normalized
