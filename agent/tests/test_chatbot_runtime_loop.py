from __future__ import annotations

import unittest

from aether_ghidra.engine.agent.loop import AgentLoopExecutor
from aether_ghidra.engine.context import ContextManager
from aether_ghidra.engine.planning import PlanManager


class Message:
    def __init__(self, content: str = "", tool_calls=None):
        self.role = "assistant"
        self.content = content
        self.tool_calls = tool_calls


class Function:
    def __init__(self, name: str, arguments: str):
        self.name, self.arguments = name, arguments


class ToolCall:
    def __init__(self, call_id: str, name: str, arguments: str):
        self.id, self.function = call_id, Function(name, arguments)


class Client:
    def __init__(self, messages):
        self.messages = list(messages)
        self.requests = []
        self.chat = self
        self.completions = self

    def create(self, **request):
        self.requests.append(request)
        return type("Response", (), {"choices": [type("Choice", (), {"message": self.messages.pop(0)})()]})()


class RetryClient(Client):
    def __init__(self, messages):
        super().__init__(messages)
        self.failed = True

    def create(self, **request):
        if self.failed:
            self.failed = False
            raise TimeoutError("timed out")
        return super().create(**request)


class ChatbotRuntimeLoopTests(unittest.TestCase):
    def executor(self, client, *, max_iterations=4, plan_manager=None, retry_count=0):
        return AgentLoopExecutor(
            client=client,
            model="fake",
            max_iterations=max_iterations,
            system_prompt="system",
            tools=[],
            tool_handlers={"echo": lambda value: f"echo:{value}"},
            context_manager=ContextManager(),
            plan_manager=plan_manager or PlanManager(),
            memory_store=None,
            verbose_output_dir=None,
            llm_retry_count=retry_count,
            llm_retry_base_delay_sec=0,
        )

    def test_native_tool_calls_append_assistant_then_matching_tool_message(self):
        client = Client([Message(tool_calls=[ToolCall("call-1", "echo", '{"value":"x"}')]), Message("finished")])
        executor = self.executor(client)
        state = executor.create_state("work")

        first = executor.step(state)
        second = executor.step(state)

        self.assertFalse(first.done)
        self.assertEqual([item["role"] for item in state.conversation_history], ["assistant", "tool", "assistant"])
        self.assertEqual(state.conversation_history[1]["tool_call_id"], "call-1")
        self.assertEqual(first.tool_results[0]["result"], "echo:x")
        self.assertTrue(second.done)

    def test_xml_fallback_and_retry_are_supported(self):
        xml = Message('<tool_call><function=echo><parameter=value>fallback</parameter></function></tool_call>')
        client = RetryClient([xml, Message("done")])
        executor = self.executor(client, retry_count=1)
        result = executor.run("work")

        self.assertEqual(result["tool_calls"][0]["arguments"], {"value": "fallback"})
        self.assertEqual(len(client.requests), 2)

    def test_incomplete_plan_allows_one_continuation_then_clears(self):
        manager = PlanManager()
        manager.create_plan("goal", [{"description": "pending"}])
        client = Client([Message("premature"), Message("still premature")])
        executor = self.executor(client, plan_manager=manager)
        state = executor.create_state("work")

        first = executor.step(state)
        second = executor.step(state)

        self.assertFalse(first.done)
        self.assertTrue(second.done)
        self.assertIn("active plan has pending tasks", client.requests[1]["messages"][0]["content"])
        self.assertIsNone(manager.active_plan)

    def test_max_iterations_returns_terminal_state(self):
        client = Client([Message(tool_calls=[ToolCall("call-1", "echo", '{"value":"x"}')])])
        executor = self.executor(client, max_iterations=1)
        state = executor.create_state("work")
        executor.step(state)
        terminal = executor.step(state)

        self.assertTrue(terminal.done)
        self.assertEqual(terminal.final_analysis, "Maximum iterations (1) reached.")


if __name__ == "__main__":
    unittest.main()
