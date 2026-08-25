from __future__ import annotations

import unittest

from aether_ghidra.integrations.ghidra.chatbot_backend import GhidraChatbotBackendBridge


class FakeClient:
    def __init__(self) -> None:
        self.calls = []

    def invoke(self, program_id, capability, arguments):
        self.calls.append((program_id, capability, arguments))
        return {"ok": True}

    def list_programs(self):
        return [{"program_id": "program-1"}]


class ChatbotBackendTests(unittest.TestCase):
    def test_exposes_workflow_invoke_shape(self) -> None:
        client = FakeClient()
        bridge = GhidraChatbotBackendBridge("program-1", client)
        self.assertEqual(bridge.invoke("program-1", "get_function_call_tree", {"address": "1000"}), {"ok": True})
        self.assertEqual(client.calls, [("program-1", "get_function_call_tree", {"address": "1000"})])

    def test_lists_programs_for_history(self) -> None:
        bridge = GhidraChatbotBackendBridge("program-1", FakeClient())
        self.assertEqual(bridge.list_programs(), [{"program_id": "program-1"}])

    def test_rejects_wrong_program(self) -> None:
        bridge = GhidraChatbotBackendBridge("program-1", FakeClient())
        with self.assertRaises(ValueError):
            bridge.invoke("program-2", "get_function_call_tree", {})


if __name__ == "__main__":
    unittest.main()
