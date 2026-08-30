from __future__ import annotations

import json
import unittest

from aether_ghidra.tools.catalog import ChatbotToolbox, ToolNames
from aether_ghidra.integrations.ghidra.identity import normalize_bridge_arguments


class StructBridge:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def _invoke(self, capability: str, arguments: dict):
        self.calls.append((capability, arguments))
        return {"capability": capability, "arguments": arguments}


class ClassPathBridge(StructBridge):
    def _invoke(self, capability: str, arguments: dict):
        result = super()._invoke(capability, arguments)
        if capability == "get_struct":
            return {"class_name": "Widget", "path": arguments["path"]}
        return result


class FunctionListBridge(StructBridge):
    def list_functions(self, pattern: str, limit: int):
        return {"functions": [{
            "address": {"space": "ram", "offset": "1000"},
            "name": "entry", "qualified_name": "Main::entry", "namespace": "Main",
            "definition": "void Main::entry()",
            "called_functions": [{"address": {"space": "ram", "offset": "1100"}, "name": "helper"}],
            "caller_functions": [{"address": {"space": "ram", "offset": "0900"}, "name": "start"}],
        }]}


class StructToolTests(unittest.TestCase):
    def test_struct_tools_are_catalogued(self) -> None:
        names = {item["function"]["name"] for item in ChatbotToolbox(None, StructBridge()).get_tool_definitions()}
        self.assertIn(ToolNames.LIST_STRUCT.value, names)
        self.assertIn(ToolNames.CREATE_STRUCT.value, names)
        self.assertIn(ToolNames.CREATE_CLASS.value, names)

        specs = {item["function"]["name"]: item["function"]["parameters"] for item in ChatbotToolbox(None, StructBridge()).get_tool_definitions()}
        self.assertIn("structure_path", specs[ToolNames.ADD_FIELDS.value]["properties"])
        self.assertNotIn("structure", specs[ToolNames.ADD_FIELDS.value]["properties"])
        self.assertIn("data_type_path", specs[ToolNames.RETYPE_VARIABLE.value]["properties"])
        self.assertEqual(specs[ToolNames.GET_DATA_AT_ADDRESS.value]["properties"]["location"]["type"], "object")
        self.assertEqual(specs[ToolNames.SET_CODE_UNIT_COMMENT.value]["properties"]["location"]["type"], "object")
        resolver = specs[ToolNames.RESOLVE_PSEUDOCODE_CALL.value]
        self.assertEqual(resolver["required"], ["caller_address", "call_site"])

    def test_writes_are_immediate_bridge_calls(self) -> None:
        bridge = StructBridge()
        toolbox = ChatbotToolbox(None, bridge)

        result = json.loads(toolbox.create_struct("Widget_data", size=16))

        self.assertEqual(result["capability"], "create_struct")
        self.assertEqual(result["arguments"]["name"], "Widget_data")
        self.assertEqual(bridge.calls[0][0], "create_struct")

    def test_structure_path_and_data_type_path_are_mapped_to_bridge_protocol(self) -> None:
        bridge = StructBridge()
        toolbox = ChatbotToolbox(None, bridge)

        toolbox.add_fields("/Types/Widget", [{"offset": 0, "data_type_path": "/builtin/int"}])

        self.assertEqual(bridge.calls[0], ("add_fields", {
            "path": "/Types/Widget",
            "fields": [{"offset": 0, "data_type": "/builtin/int"}],
        }))

    def test_class_ref_is_mapped_without_a_bare_class_target(self) -> None:
        bridge = StructBridge()
        toolbox = ChatbotToolbox(None, bridge)

        toolbox.update_class(class_ref={"class_id": "class-widget", "structure_path": "/Types/Widget"})

        self.assertEqual(bridge.calls[0], ("update_class", {
            "class_id": "class-widget", "structure": "/Types/Widget",
        }))

    def test_structure_path_can_select_a_class(self) -> None:
        bridge = ClassPathBridge()
        toolbox = ChatbotToolbox(None, bridge)

        toolbox.delete_class(structure_path="/Types/Widget")

        self.assertEqual(bridge.calls, [("delete_class", {"structure": "/Types/Widget"})])

    def test_class_id_and_structure_path_are_preserved_for_base_refs(self) -> None:
        bridge = StructBridge()
        toolbox = ChatbotToolbox(None, bridge)

        toolbox.create_class("Derived", bases=[{
            "class_ref": {"class_id": "class-base", "structure_path": "/Types/Base"},
            "offset": 0,
        }])

        self.assertEqual(bridge.calls[0][1]["bases"], [{
            "class_id": "class-base", "structure": "/Types/Base", "offset": 0,
        }])

    def test_identity_normalizes_all_class_structure_paths_for_java(self) -> None:
        for capability, arguments in [
            ("create_class", {"name": "Widget", "structure_path": "/Types/Widget"}),
            ("update_class", {"class_ref": {"class_id": "class-widget", "structure_path": "/Types/Widget"}}),
            ("delete_class", {"class_ref": {"class_id": "class-widget", "structure_path": "/Types/Widget"}}),
        ]:
            normalized = normalize_bridge_arguments(capability, arguments)
            self.assertEqual(normalized["structure"], "/Types/Widget")
            if capability != "create_class":
                self.assertEqual(normalized["class_id"], "class-widget")

        bases = normalize_bridge_arguments("create_class", {"name": "Derived", "bases": [
            {"class_ref": {"class_id": "class-base", "structure_path": "/Types/Base"}},
        ]})["bases"]
        self.assertEqual(bases, [{"class_id": "class-base", "structure": "/Types/Base"}])

    def test_list_functions_returns_only_address_and_definition(self) -> None:
        rendered = ChatbotToolbox(None, FunctionListBridge()).list_functions()
        result = json.loads(rendered)

        self.assertEqual(set(result), {"address", "definition"})
        self.assertEqual(result["address"], {"space": "ram", "offset": "1000"})
        self.assertEqual(result["definition"], "void Main::entry()")

    def test_list_struct_combines_plain_structs_and_classes(self) -> None:
        bridge = StructBridge()
        toolbox = ChatbotToolbox(None, bridge)

        toolbox.list_struct(kind="class", limit="10")

        self.assertEqual(bridge.calls, [("list_struct", {"pattern": "", "kind": "class", "limit": 10})])


if __name__ == "__main__":
    unittest.main()
