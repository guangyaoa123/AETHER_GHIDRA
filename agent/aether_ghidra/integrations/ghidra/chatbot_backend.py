from __future__ import annotations

from typing import Any

from .bridge_client import BridgeClient


class GhidraChatbotBackendBridge:
    """Legacy chatbot bridge shape backed only by explicit Ghidra RPC calls."""

    def __init__(self, program_id: str, bridge: BridgeClient | None = None) -> None:
        self.program_id = program_id
        self.client = bridge or BridgeClient()

    def _invoke(self, capability: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.client.invoke(self.program_id, capability, arguments)

    def invoke(self, program_id: str, capability: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Expose the common program-scoped bridge shape used by workflows."""
        if program_id != self.program_id:
            raise ValueError("Bridge program_id does not match this session")
        return self._invoke(capability, arguments)

    def list_programs(self) -> list[dict[str, Any]]:
        return self.client.list_programs()

    def get_program_metadata(self) -> dict[str, Any]:
        return self._invoke("get_program_metadata")

    def resolve_function(self, function_name: str) -> dict[str, Any] | None:
        try:
            return self._invoke("get_function_by_name", {"function_name": function_name})
        except Exception:
            return None

    def get_function_name(self, function_ref: Any) -> str:
        if isinstance(function_ref, dict):
            return str(function_ref.get("name", function_ref.get("address", "")))
        return str(function_ref)

    def list_functions(self, pattern: str = "", limit: int = 500, offset: int = 0) -> dict[str, Any]:
        return self._invoke("list_functions", {"pattern": pattern, "limit": limit, "offset": offset})

    def get_function_pseudocode(self, function_name: Any, *, read_only: bool = False) -> dict[str, Any]:
        arguments = {"function_name": function_name} if isinstance(function_name, str) else {"address": function_name}
        arguments["read_only"] = read_only
        return self._invoke("get_function_pseudocode", arguments)

    def get_data_at_address(self, location: str, count: int = 16) -> dict[str, Any] | None:
        return self._invoke("get_data_at_address", {"location": location, "count": count})

    def get_xrefs_to(self, location: str) -> dict[str, Any] | None:
        return self._invoke("get_xrefs_to", {"location": location})

    def rename_function(self, function_name: str, name: str) -> str:
        function = self.resolve_function(function_name)
        if not function:
            return f"Function '{function_name}' not found."
        result = self._invoke("rename_function", {"address": function["address"], "name": name})
        return f"Renamed '{function_name}' to '{result.get('name', name)}'."

    def set_function_comment(self, function_name: str, comment: str) -> str:
        function = self.resolve_function(function_name)
        if not function:
            return f"Function '{function_name}' not found."
        self._invoke("set_function_comment", {"address": function["address"], "comment": comment})
        return f"Updated comment for '{function_name}'."
