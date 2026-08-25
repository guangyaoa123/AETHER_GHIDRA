from __future__ import annotations

from collections import deque
from typing import Any, Callable, Iterable

from .agent.base import AgentContext, CallbackAgent
from .memory import MemoryStore
from .models import Message, PublishedEvent
from .planning import PlanManager
from .tools import ContextTool, FunctionTool, MemoryTool, PlanningTool, RuntimeTool


class MultiAgentRuntime:
    """Small domain-neutral message runtime used by the chatbot engine."""

    def __init__(self) -> None:
        self.shared_state: dict[str, Any] = {}
        self._agents: dict[str, CallbackAgent] = {}
        self._contexts: dict[str, dict[str, Any]] = {}
        self._memories: dict[str, MemoryStore] = {}
        self._plans: dict[str, PlanManager] = {}
        self._tools: dict[str, dict[str, RuntimeTool]] = {}
        self._conversations: dict[str, list[dict[str, Any]]] = {}
        self._queue: deque[Message] = deque()
        self._history: list[Message] = []
        self._events: list[PublishedEvent] = []

    @property
    def history(self) -> list[Message]:
        return list(self._history)

    @property
    def events(self) -> list[PublishedEvent]:
        return list(self._events)

    def create_agent(
        self,
        agent_id: str,
        handler: Callable[..., Any],
        *,
        description: str = "",
        tools: Iterable[RuntimeTool] | None = None,
    ) -> CallbackAgent:
        agent = CallbackAgent(agent_id, handler, description=description, tools=list(tools or ()))
        self.add_agent(agent)
        return agent

    def add_agent(self, agent: CallbackAgent) -> CallbackAgent:
        agent_id = agent.agent_id
        if agent_id in self._agents:
            raise ValueError(f"Agent '{agent_id}' is already registered.")
        self._agents[agent_id] = agent
        self._contexts[agent_id] = {}
        self._memories[agent_id] = MemoryStore()
        self._plans[agent_id] = PlanManager()
        self._conversations[agent_id] = []
        builtins: list[RuntimeTool] = [ContextTool(), MemoryTool(), PlanningTool()]
        builtins.extend(tool.clone() for tool in agent.tools)
        self._tools[agent_id] = {tool.name: tool for tool in builtins}
        agent.on_registered(AgentContext(self, agent_id))
        return agent

    def send(
        self,
        sender: str,
        recipient: str,
        content: Any,
        *,
        topic: str = "message",
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Message:
        if recipient not in self._agents and recipient != "system":
            raise KeyError(f"Unknown recipient '{recipient}'.")
        message = Message(sender, recipient, content, topic, correlation_id, dict(metadata or {}))
        self._queue.append(message)
        self._history.append(message)
        return message

    def broadcast(self, sender: str, content: Any, *, topic: str = "broadcast", metadata: dict[str, Any] | None = None) -> list[Message]:
        return [self.send(sender, agent_id, content, topic=topic, metadata=metadata) for agent_id in self._agents if agent_id != sender]

    def run(self, max_messages: int | None = None) -> int:
        processed = 0
        while self._queue and (max_messages is None or processed < max_messages):
            message = self._queue.popleft()
            if message.recipient in self._agents:
                agent = self._agents[message.recipient]
                agent.handle_message(message, AgentContext(self, agent.agent_id))
            processed += 1
        return processed

    def publish(self, publisher: str, key: str, value: Any) -> None:
        self._events.append(PublishedEvent(key, value, publisher))

    def get_agent_context(self, agent_id: str) -> dict[str, Any]:
        return self._contexts[agent_id]

    def get_agent_memory_store(self, agent_id: str) -> MemoryStore:
        return self._memories[agent_id]

    def get_agent_plan_manager(self, agent_id: str) -> PlanManager:
        return self._plans[agent_id]

    def get_agent_tools(self, agent_id: str) -> dict[str, RuntimeTool]:
        return self._tools[agent_id]

    def get_agent_conversation_history(self, agent_id: str) -> list[dict[str, Any]]:
        return self._conversations[agent_id]

    def set_agent_conversation_history(self, agent_id: str, history: list[dict[str, Any]]) -> None:
        self._conversations[agent_id] = history

    def clear_agent_conversation_history(self, agent_id: str) -> None:
        self._conversations[agent_id].clear()
