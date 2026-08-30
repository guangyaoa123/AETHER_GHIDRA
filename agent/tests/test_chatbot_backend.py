from __future__ import annotations

import json
import unittest

from aether_ghidra.integrations.ghidra.chatbot_backend import GhidraChatbotBackendBridge
from aether_ghidra.tools.catalog import ChatbotToolbox


class FakeClient:
    def __init__(self) -> None:
        self.calls = []

    def invoke(self, program_id, capability, arguments):
        self.calls.append((program_id, capability, arguments))
        if capability == "resolve_pseudocode_call":
            return {"function_ref": {
                "address": {"space": "ram", "offset": "1200"},
                "name": arguments.get("display_name", "resolved"),
                "namespace": "Example",
            }}
        if capability == "get_function":
            return {
                "address": {"space": "ram", "offset": "1000"},
                "name": "entry", "namespace": "Main",
                "code": "void entry() {}", "calls": [
                {
                    "call_site": {"space": "ram", "offset": "1008"},
                    "target_address": {"space": "ram", "offset": "1100"},
                    "name": "helper",
                },
                {"name": "unsafe-name-only"},
            ]}
        return {"ok": True}

    def list_programs(self):
        return [{"program_id": "program-1"}]


class ChatbotBackendTests(unittest.TestCase):
    def test_exposes_workflow_invoke_shape(self) -> None:
        client = FakeClient()
        bridge = GhidraChatbotBackendBridge("program-1", client)
        address = {"space": "ram", "offset": "1000"}
        self.assertEqual(bridge.invoke("program-1", "get_function_call_tree", {"address": address}), {"ok": True})
        self.assertEqual(client.calls, [("program-1", "get_function_call_tree", {"address": address})])

    def test_lists_programs_for_history(self) -> None:
        bridge = GhidraChatbotBackendBridge("program-1", FakeClient())
        self.assertEqual(bridge.list_programs(), [{"program_id": "program-1"}])

    def test_rejects_wrong_program(self) -> None:
        bridge = GhidraChatbotBackendBridge("program-1", FakeClient())
        with self.assertRaises(ValueError):
            bridge.invoke("program-2", "get_function_call_tree", {})

    def test_function_calls_use_structured_address_and_not_name_resolution(self) -> None:
        client = FakeClient()
        bridge = GhidraChatbotBackendBridge("program-1", client)
        target = {"address": {"space": "ram", "offset": "1000"}, "name": "entry"}

        bridge.get_function(target, read_only=True)

        self.assertEqual(client.calls[-1], (
            "program-1", "get_function",
            {"address": target["address"], "read_only": True},
        ))
        self.assertIsNone(bridge.resolve_function("entry"))
        self.assertEqual(len(client.calls), 1)

    def test_pseudocode_calls_are_normalized_to_function_refs(self) -> None:
        bridge = GhidraChatbotBackendBridge("program-1", FakeClient())
        result = bridge.get_function({"address": {"space": "ram", "offset": "1000"}})

        self.assertEqual(result["calls"], [{
            "caller_address": {"space": "ram", "offset": "1000"},
            "call_site": {"space": "ram", "offset": "1008"},
            "display_name": "helper",
            "function_ref": {
                "address": {"space": "ram", "offset": "1100"},
                "name": "helper",
            },
        }])
        self.assertEqual(result["function_ref"]["namespace"], "Main")

        rendered = ChatbotToolbox(None, bridge).get_function({
            "address": {"space": "ram", "offset": "1000"},
        })
        self.assertEqual(json.loads(rendered)["calls"], result["calls"])

    def test_location_calls_require_structured_addresses(self) -> None:
        client = FakeClient()
        bridge = GhidraChatbotBackendBridge("program-1", client)
        location = {"space": "ram", "offset": "1004"}

        bridge.get_data_at_address(location)
        bridge.get_xrefs_to(location)

        self.assertEqual(client.calls[-2:], [
            ("program-1", "get_data_at_address", {"location": location, "count": 16}),
            ("program-1", "get_xrefs_to", {"location": location}),
        ])
        with self.assertRaisesRegex(ValueError, "structured address"):
            bridge.get_data_at_address("entry")
        with self.assertRaisesRegex(ValueError, "structured address"):
            bridge.get_xrefs_to("entry")

    def test_resolve_pseudocode_call_uses_caller_and_call_site_addresses(self) -> None:
        client = FakeClient()
        bridge = GhidraChatbotBackendBridge("program-1", client)
        caller = {"space": "ram", "offset": "1000"}
        call_site = {"space": "ram", "offset": "1008"}

        result = bridge.resolve_pseudocode_call(caller, call_site, "helper")

        self.assertEqual(client.calls[-1], ("program-1", "resolve_pseudocode_call", {
            "caller_address": caller, "call_site": call_site, "display_name": "helper",
        }))
        self.assertEqual(result["function_ref"]["namespace"], "Example")


if __name__ == "__main__":
    unittest.main()
