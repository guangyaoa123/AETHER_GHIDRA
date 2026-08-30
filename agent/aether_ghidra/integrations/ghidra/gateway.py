"""Backend-neutral Program access for agent workflows."""

from __future__ import annotations

from typing import Any, Protocol

from .bridge_client import BridgeClient
from .chatbot_backend import GhidraChatbotBackendBridge


class ProgramGateway(Protocol):
    """Logical access to one Program, independent of its hosting mode."""

    program_id: str

    def invoke(
        self,
        program_id: str,
        capability: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...

    def get_program_metadata(self) -> dict[str, Any]: ...

    def list_functions(
        self,
        pattern: str = "",
        limit: int = 50,
        offset: int = 0,
        include_call_relationships: bool = False,
    ) -> dict[str, Any]: ...

    def get_function(self, function_ref: Any, *, read_only: bool = False) -> dict[str, Any]: ...


class AnalysisBackend(Protocol):
    """Backend lifecycle surface used by the agent application."""

    def list_programs(self) -> list[dict[str, Any]]: ...

    def gateway_for(self, program_id: str) -> ProgramGateway: ...


class GhidraProgramGateway(GhidraChatbotBackendBridge):
    """Current Ghidra implementation of the backend-neutral gateway."""

    def __init__(self, program_id: str, client: BridgeClient | None = None) -> None:
        super().__init__(program_id, client)


class GhidraAnalysisBackend:
    """Ghidra bridge adapter hidden behind the agent backend boundary."""

    def __init__(self, client: BridgeClient | None = None) -> None:
        self.client = client or BridgeClient()

    def list_programs(self) -> list[dict[str, Any]]:
        return self.client.list_programs()

    def gateway_for(self, program_id: str) -> ProgramGateway:
        return GhidraProgramGateway(program_id, self.client)
