from __future__ import annotations

import json
import threading
import unittest

from aether_ghidra.engine import AgentCancelled
from aether_ghidra.features.chat.agent import ChatbotAgent


class FakeBridge:
    def resolve_function(self, function_name: str):
        return {"name": function_name, "address": {"space": "ram", "offset": "1000"}}

    def get_function_name(self, function_ref):
        return function_ref["name"]

    def list_functions(self, pattern: str = "", limit: int = 500):
        return [{"name": "entry", "address": {"space": "ram", "offset": "1000"}}]

    def get_function_pseudocode(self, function_name: str):
        return f"void {function_name}(void) {{}}"

    def get_data_at_address(self, location: str, count: int = 16):
        return {"ea": location, "bytes": "90"}

    def get_xrefs_to(self, location: str):
        return {"total": 0, "references": []}

    def rename_function(self, function_name: str, name: str):
        return f"Renamed '{function_name}' to '{name}'."

    def set_function_comment(self, function_name: str, comment: str):
        return f"Updated comment for '{function_name}'."


class FakeMessage:
    def __init__(self, content="", tool_calls=None):
        self.role = "assistant"
        self.content = content
        self.tool_calls = tool_calls


class FakeClient:
    def __init__(self):
        self.chat = self
        self.completions = self
        self.calls = []
        self.responses = [
            FakeMessage(
                tool_calls=[
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {"name": "list_functions", "arguments": json.dumps({"limit": "10"})},
                    }
                ]
            ),
            FakeMessage("The entry function is available for analysis."),
        ]

    def create(self, **request):
        self.calls.append(request)
        return type("Response", (), {"choices": [type("Choice", (), {"message": self.responses.pop(0)})()]})()


class ChatbotAgentTests(unittest.TestCase):
    def test_native_tool_call_and_conversation_persist(self):
        agent = ChatbotAgent("program-1", FakeBridge())
        client = FakeClient()
        agent._client = lambda: client

        result = agent.run("Inspect the entry point")

        self.assertEqual(result["final_analysis"], "The entry function is available for analysis.")
        self.assertEqual(len(result["tool_calls"]), 1)
        self.assertEqual(result["tool_calls"][0]["name"], "list_functions")
        self.assertEqual(len(agent.state.conversation_history), 4)
        self.assertIn("list_functions", client.calls[0]["tools"][8]["function"]["name"])

    def test_cancelled_run_stops_before_model_request(self):
        agent = ChatbotAgent("program-1", FakeBridge())
        client = FakeClient()
        agent._client = lambda: client
        cancel = threading.Event()
        cancel.set()

        with self.assertRaises(AgentCancelled):
            agent.run("Inspect the entry point", cancel=cancel)
        self.assertEqual(client.calls, [])


if __name__ == "__main__":
    unittest.main()
