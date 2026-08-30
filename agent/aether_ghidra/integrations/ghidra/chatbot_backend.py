from __future__ import annotations

from typing import Any

from .bridge_client import BridgeClient
from .identity import function_address, function_ref as normalize_function_ref, normalize_bridge_arguments, structured_address


class GhidraChatbotBackendBridge:
    """Legacy chatbot bridge shape backed only by explicit Ghidra RPC calls."""

    def __init__(self, program_id: str, bridge: BridgeClient | None = None) -> None:
        self.program_id = program_id
        self.client = bridge or BridgeClient()

    def _invoke(self, capability: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.client.invoke(self.program_id, capability, normalize_bridge_arguments(capability, arguments))

    def invoke(self, program_id: str, capability: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Expose the common program-scoped bridge shape used by workflows."""
        if program_id != self.program_id:
            raise ValueError("Bridge program_id does not match this session")
        return self._invoke(capability, arguments)

    def list_programs(self) -> list[dict[str, Any]]:
        return self.client.list_programs()

    def get_program_metadata(self) -> dict[str, Any]:
        return self._invoke("get_program_metadata")

    def resolve_function(self, function_ref_value: Any) -> dict[str, Any] | None:
        try:
            return self._invoke("get_function", {"address": function_address(function_ref_value)})
        except Exception:
            return None

    def list_functions(
        self,
        pattern: str = "",
        limit: int = 50,
        offset: int = 0,
        include_call_relationships: bool = False,
    ) -> dict[str, Any]:
        return self._invoke("list_functions", {
            "pattern": pattern,
            "limit": limit,
            "offset": offset,
            "include_call_relationships": include_call_relationships,
        })

    def get_function(self, function_ref_value: Any, *, read_only: bool = False) -> dict[str, Any]:
        target = normalize_function_ref(function_ref_value)
        result = self._invoke("get_function", {
            "address": target["address"],
            "read_only": read_only,
        })
        if not isinstance(result, dict):
            return result
        result = dict(result)
        raw_function_ref = result.get("function_ref") or result
        try:
            result["function_ref"] = normalize_function_ref(raw_function_ref)
        except ValueError:
            result["function_ref"] = target
        result["calls"] = self._structured_calls(result.get("calls", []), target["address"])
        return result

    def get_data_at_address(self, location: Any, count: int = 16) -> dict[str, Any] | None:
        return self._invoke("get_data_at_address", {"location": structured_address(location, "location"), "count": count})

    def get_xrefs_to(self, location: Any) -> dict[str, Any] | None:
        return self._invoke("get_xrefs_to", {"location": structured_address(location, "location")})

    def resolve_pseudocode_call(
        self, caller_address: Any, call_site: Any, display_name: str | None = None,
    ) -> dict[str, Any]:
        arguments: dict[str, Any] = {
            "caller_address": structured_address(caller_address, "caller_address"),
            "call_site": structured_address(call_site, "call_site"),
        }
        if display_name not in (None, ""):
            arguments["display_name"] = display_name
        result = self._invoke("resolve_pseudocode_call", arguments)
        if isinstance(result, dict):
            result = dict(result)
            caller = result.get("caller")
            caller_value = result.get("caller_address")
            if caller_value is None and isinstance(caller, dict):
                caller_value = caller.get("address")
            result["caller_address"] = structured_address(caller_value or caller_address, "caller_address")
            result["call_site"] = structured_address(result.get("call_site", call_site), "call_site")
            result["display_name"] = str(result.get("display_name") or result.get("name") or display_name or "")
            candidate = result.get("function_ref") or result.get("function")
            if candidate is None and result.get("target_address") is not None:
                candidate = {"address": result["target_address"], "name": result.get("name", "")}
            if candidate is None and "address" in result:
                candidate = result
            try:
                result["function_ref"] = normalize_function_ref(candidate)
            except ValueError:
                result["function_ref"] = None
            result.pop("function", None)
        return result

    @staticmethod
    def _structured_calls(calls: Any, caller_address: dict[str, Any]) -> list[dict[str, Any]]:
        if not isinstance(calls, list):
            return []
        result = []
        for call in calls:
            if not isinstance(call, dict):
                continue
            try:
                target = normalize_function_ref({
                    "address": call.get("target_address"),
                    "name": call.get("name", ""),
                })
                result.append({
                    "caller_address": structured_address(caller_address, "caller_address"),
                    "call_site": structured_address(call.get("call_site"), "call_site"),
                    "display_name": target.get("name", ""),
                    "function_ref": target,
                })
            except ValueError:
                continue
        return result

    def rename_function(self, function_ref_value: Any, name: str) -> str:
        function = self.resolve_function(function_ref_value)
        if not function:
            return "Function target not found."
        target = function_ref(function_ref_value)
        result = self._invoke("rename_function", {"address": target["address"], "name": name})
        return f"Renamed '{function.get('name', target['address'])}' to '{result.get('name', name)}'."

    def set_function_comment(self, function_ref_value: Any, comment: str) -> str:
        function = self.resolve_function(function_ref_value)
        if not function:
            return "Function target not found."
        self._invoke("set_function_comment", {
            "address": function_address(function_ref_value),
            "comment": comment,
        })
        return f"Updated comment for '{function.get('name', function_address(function_ref_value))}'."
