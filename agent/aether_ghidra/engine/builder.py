from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .core import MultiAgentRuntime
from .agent.base import CallbackAgent
from .tools import FunctionTool, RuntimeTool


@dataclass(slots=True)
class ToolSpec:
    kind: str
    name: str | None = None
    description: str = ""
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AgentSpec:
    agent_id: str
    handler: str
    description: str = ""
    tools: list[ToolSpec] = field(default_factory=list)


class AgentBuilder:
    def __init__(self, runtime: MultiAgentRuntime) -> None:
        self.runtime = runtime
        self._handler_registry: dict[str, Callable[..., Any]] = {}
        self._tool_registry: dict[str, Callable[..., RuntimeTool]] = {}
        self._function_tool_registry: dict[str, Callable[..., Any]] = {}

    def register_handler(self, name: str, handler: Callable[..., Any]) -> "AgentBuilder":
        self._handler_registry[name] = handler
        return self

    def register_tool_factory(self, kind: str, factory: Callable[..., RuntimeTool]) -> "AgentBuilder":
        self._tool_registry[kind] = factory
        return self

    def register_function_tool(self, name: str, handler: Callable[..., Any]) -> "AgentBuilder":
        self._function_tool_registry[name] = handler
        return self

    def create_agent(self, agent_id: str, *, handler: Callable[..., Any], description: str = "", tools: Iterable[RuntimeTool] | None = None) -> CallbackAgent:
        return self.runtime.create_agent(agent_id, handler, description=description, tools=list(tools or ()))

    def create_agent_from_spec(self, spec: AgentSpec | Mapping[str, Any]) -> CallbackAgent:
        if isinstance(spec, Mapping):
            spec = self._parse_agent_spec(spec)
        if spec.handler not in self._handler_registry:
            raise KeyError(f"Unknown handler '{spec.handler}'.")
        return self.create_agent(spec.agent_id, handler=self._handler_registry[spec.handler], description=spec.description, tools=[self._build_tool(item) for item in spec.tools])

    def create_agents_from_config(self, config: dict[str, Any]) -> list[CallbackAgent]:
        return [self.create_agent_from_spec(item) for item in config.get("agents", [])]

    def _parse_agent_spec(self, data: Mapping[str, Any]) -> AgentSpec:
        return AgentSpec(data["agent_id"], data["handler"], data.get("description", ""), [self._parse_tool_spec(item) for item in data.get("tools", [])])

    def _parse_tool_spec(self, data: ToolSpec | Mapping[str, Any]) -> ToolSpec:
        return data if isinstance(data, ToolSpec) else ToolSpec(data["kind"], data.get("name"), data.get("description", ""), dict(data.get("params", {})))

    def _build_tool(self, spec: ToolSpec) -> RuntimeTool:
        if spec.kind == "function":
            if not spec.name:
                raise ValueError("Function tool specs require a tool name.")
            if spec.name not in self._function_tool_registry:
                raise KeyError(f"Unknown function tool '{spec.name}'.")
            return FunctionTool(spec.name, self._function_tool_registry[spec.name], description=spec.description)
        if spec.kind not in self._tool_registry:
            raise KeyError(f"Unknown tool kind '{spec.kind}'.")
        params = dict(spec.params)
        if spec.name is not None: params.setdefault("name", spec.name)
        if spec.description: params.setdefault("description", spec.description)
        return self._tool_registry[spec.kind](**params)
