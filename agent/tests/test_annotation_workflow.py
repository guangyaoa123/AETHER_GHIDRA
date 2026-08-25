from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aether_ghidra.features.annotation.workflow import AnnotationWorkflow
from aether_ghidra.features.annotation.staging import MutationStaging
from aether_ghidra.tools.catalog import ChatbotToolbox


ROOT = {"space": "ram", "offset": "1000"}
CALLEE = {"space": "ram", "offset": "1100"}


class FakeAnnotationBridge:
    def __init__(self):
        self.applied = []
        self.calls = []

    def invoke(self, program_id, capability, arguments):
        self.calls.append(capability)
        if capability == "get_function_call_tree":
            return {"functions": [
                {"name": "entry", "address": ROOT, "depth": 0},
                {"name": "decode", "address": CALLEE, "depth": 1},
            ]}
        if capability == "get_annotation_context":
            return {"functions": [
                {"name": "entry", "address": ROOT, "pseudocode": "void entry() {}", "variables": []},
                {"name": "decode", "address": CALLEE, "pseudocode": "void decode() {}", "variables": []},
            ]}
        if capability == "apply_annotation_batch":
            self.applied.append(arguments["operations"])
            return {"batch_id": "batch-1", "operations": [
                {**item, "before": "old", "after": item["value"]}
                for item in arguments["operations"]
            ]}
        raise AssertionError(capability)

    def list_programs(self):
        return [{"program_id": "program-1", "sha256": "abc123"}]


class FakeToolMessage:
    def __init__(self, content="", tool_calls=None):
        self.role = "assistant"
        self.content = content
        self.tool_calls = tool_calls


class FakeToolClient:
    def __init__(self):
        self.chat = self
        self.completions = self
        self.calls = []
        self.responses = [
            FakeToolMessage(tool_calls=[{
                "id": "rename-1",
                "type": "function",
                "function": {
                    "name": "rename_function",
                    "arguments": '{"function_name":"decode","name":"decode_payload"}',
                },
            }]),
            FakeToolMessage(tool_calls=[{
                "id": "comment-1",
                "type": "function",
                "function": {
                    "name": "set_function_comment",
                    "arguments": '{"function_name":"decode","comment":"Decodes the payload."}',
                },
            }]),
            FakeToolMessage("Annotation complete."),
        ]

    def create(self, **request):
        self.calls.append(request)
        return type("Response", (), {"choices": [type("Choice", (), {"message": self.responses.pop(0)})()]})()


class FakeGuidedBridge(FakeAnnotationBridge):
    def invoke(self, program_id, capability, arguments):
        self.calls.append(capability)
        if capability == "get_function_call_tree":
            return {"functions": [
                {"name": "entry", "address": ROOT, "depth": 0},
                {"name": "decode", "address": CALLEE, "depth": 1},
            ]}
        if capability == "get_annotation_context":
            return {"functions": [
                {
                    "name": "entry", "address": ROOT, "pseudocode": "void entry() {}",
                    "variables": [], "code_units": [],
                },
                {
                    "name": "decode", "address": CALLEE,
                    "pseudocode": "void decode() { decrypt(); }",
                    "variables": [{"name": "input", "storage": "r0"}],
                    "code_units": [{"address": {"space": "ram", "offset": "1100"}}],
                },
            ]}
        if capability == "apply_annotation_batch":
            self.applied.append(arguments["operations"])
            return {"batch_id": "batch-guided", "operations": [
                {**item, "before": "old", "after": item["value"]}
                for item in arguments["operations"]
            ]}
        if capability == "rename_function":
            return {"name": arguments["name"]}
        raise AssertionError(capability)


class AnnotationWorkflowTests(unittest.TestCase):
    def test_manual_gatherer_restricts_selection_to_candidates(self) -> None:
        bridge = FakeAnnotationBridge()
        workflow = AnnotationWorkflow(bridge, "program-1")
        selected = workflow._selected_functions(
            {"selected_functions": ["decode", "not-a-candidate"]},
            [{"name": "entry", "address": ROOT}, {"name": "decode", "address": CALLEE}],
            "manual",
        )
        self.assertEqual(selected, [
            {"address": ROOT, "name": "entry"},
            {"address": CALLEE, "name": "decode"},
        ])

    def test_external_candidates_are_not_decompilable(self) -> None:
        workflow = AnnotationWorkflow(FakeAnnotationBridge(), "program-1")
        self.assertFalse(workflow._is_decompilable_candidate({
            "name": "printf", "address": {"space": "EXTERNAL", "offset": "48"},
        }))
        self.assertFalse(workflow._is_decompilable_candidate({
            "name": "printf", "address": "EXTERNAL:00000048",
        }))
        self.assertFalse(workflow._is_decompilable_candidate({
            "name": "printf", "address": ROOT, "thunk": True,
        }))
        self.assertTrue(workflow._is_decompilable_candidate({
            "name": "decode", "address": ROOT,
        }))

    def test_manual_gatherer_accepts_default_name_preset_selection(self) -> None:
        workflow = AnnotationWorkflow(FakeAnnotationBridge(), "program-1")
        candidates = [
            {"name": "FUN_00401000", "address": ROOT, "default_name": True},
            {"name": "FUN_00401100", "address": CALLEE, "default_name": True},
            {"name": "NamedHelper", "address": {"space": "ram", "offset": "1200"}, "default_name": False},
        ]

        selected = workflow._selected_functions(
            {"selected_functions": [
                {"name": item["name"], "address": item["address"]}
                for item in candidates
                if item["default_name"]
            ]},
            candidates,
            "manual",
        )

        self.assertEqual(selected, [
            {"address": ROOT, "name": "FUN_00401000"},
            {"address": CALLEE, "name": "FUN_00401100"},
        ])

    def test_annotation_flow_logs_stages_and_bridge_capabilities(self) -> None:
        workflow = AnnotationWorkflow(FakeAnnotationBridge(), "program-1")

        with self.assertLogs("aether_ghidra.features.annotation.workflow", level="INFO") as captured:
            workflow._report_progress("Gathering candidate functions", 10)
            workflow._gather("get_function_call_tree", {"address": ROOT})
            workflow._annotate("apply_annotation_batch", {"operations": [{"kind": "set_function_comment", "value": "comment"}]})

        output = "\n".join(captured.output)
        self.assertIn("annotation stage program_id=program-1 progress=10%", output)
        self.assertIn("annotation bridge start phase=gathering", output)
        self.assertIn("capability=get_function_call_tree", output)
        self.assertIn("annotation bridge complete phase=annotation", output)

    def test_annotation_is_applied_and_journaled(self) -> None:
        bridge = FakeAnnotationBridge()
        workflow = AnnotationWorkflow(bridge, "program-1")
        operation = {
            "id": "op-1",
            "kind": "set_function_comment",
            "target": {"function_address": ROOT},
            "expected_before": "",
            "value": "Entry point decodes the input.",
            "reason": "The function is the root decoder.",
        }
        with tempfile.TemporaryDirectory() as directory:
            history_root = Path(directory) / "history"
            config_path = Path(directory) / "tools.json"
            config_path.write_text(
                '{"version": 2, "groups": {"annotation_read": true, "annotation_write": true}, "tools": {}}'
            )
            with patch("aether_ghidra.features.annotation.history.HISTORY_ROOT", history_root), \
                patch("aether_ghidra.config.tool_policy.TOOL_CONFIG_PATH", config_path), \
                patch.object(workflow, "_propose_operations", return_value=[operation]):
                result = workflow.run({"address": ROOT, "mode": "manual"})

            self.assertEqual(result["batch_id"], "batch-1")
            self.assertEqual(len(bridge.applied), 1)
            self.assertEqual(bridge.calls, [
                "get_function_call_tree", "get_annotation_context", "apply_annotation_batch",
            ])
            self.assertTrue(list(history_root.glob("*.json")))

    def test_undo_requests_empty_code_comment_clear(self) -> None:
        bridge = FakeAnnotationBridge()
        workflow = AnnotationWorkflow(bridge, "program-1")
        with tempfile.TemporaryDirectory() as directory:
            history_root = Path(directory) / "history"
            history_root.mkdir()
            (history_root / "abc123.json").write_text(json.dumps([{
                "batch_id": "batch-comments",
                "program_id": "program-1",
                "program_key": "abc123",
                "mode": "manual",
                "selected_functions": [],
                "operations": [{
                    "id": "op-1",
                    "kind": "set_code_unit_comment",
                    "target": {"address": ROOT},
                    "before": "",
                    "after": "Temporary comment",
                    "comment_kind": "eol",
                }],
            }]))
            config_path = Path(directory) / "tools.json"
            config_path.write_text(
                '{"version": 2, "groups": {"annotation_read": true, "annotation_write": true}, "tools": {}}'
            )
            with patch("aether_ghidra.features.annotation.history.HISTORY_ROOT", history_root), \
                 patch("aether_ghidra.config.tool_policy.TOOL_CONFIG_PATH", config_path):
                workflow.undo_last()

        inverse = bridge.applied[0][0]
        self.assertEqual(inverse["kind"], "set_code_unit_comment")
        self.assertEqual(inverse["value"], "")
        self.assertEqual(inverse["expected_before"], "Temporary comment")

    def test_undo_reconstructs_function_definition(self) -> None:
        bridge = FakeAnnotationBridge()
        before = {
            "return_type": "int",
            "calling_convention": "__stdcall",
            "custom_storage": False,
            "parameters": [{"name": "value", "data_type": "int"}],
            "varargs": False,
        }
        after = {
            "return_type": "uint32_t",
            "calling_convention": "__stdcall",
            "custom_storage": False,
            "parameters": [],
            "varargs": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            history_root = Path(directory) / "history"
            history_root.mkdir()
            (history_root / "abc123.json").write_text(json.dumps([{
                "batch_id": "batch-definition",
                "program_id": "program-1",
                "program_key": "abc123",
                "mode": "manual",
                "selected_functions": [],
                "operations": [{
                    "id": "definition-1",
                    "kind": "update_function_definition",
                    "target": {"function_address": ROOT},
                    "before": json.dumps(before, separators=(",", ":")),
                    "after": json.dumps(after, separators=(",", ":")),
                }],
            }]))
            config_path = Path(directory) / "tools.json"
            config_path.write_text(
                '{"version": 2, "groups": {"annotation_read": true, "annotation_write": true}, "tools": {}}'
            )
            with patch("aether_ghidra.features.annotation.history.HISTORY_ROOT", history_root), \
                 patch("aether_ghidra.config.tool_policy.TOOL_CONFIG_PATH", config_path):
                AnnotationWorkflow(bridge, "program-1").undo_last()

        inverse = bridge.applied[0][0]
        self.assertEqual(inverse["kind"], "update_function_definition")
        self.assertEqual(inverse["definition"]["parameters"][0]["name"], "value")
        self.assertEqual(inverse["value"], json.dumps(before, separators=(",", ":")))

    def test_auto_parameter_tool_error_is_returned_and_run_continues(self) -> None:
        workflow = AnnotationWorkflow(FakeAnnotationBridge(), "program-1")
        context = {
            "functions": [{
                "name": "entry",
                "address": ROOT,
                "variables": [{"name": "this", "parameter": True, "auto_parameter": True}],
            }],
        }
        staging = MutationStaging(context)
        toolbox = ChatbotToolbox(None, FakeAnnotationBridge(), staging)
        client = FakeToolClient()
        client.responses = [
            FakeToolMessage(tool_calls=[{
                "id": "auto-rename",
                "type": "function",
                "function": {
                    "name": "rename_variable",
                    "arguments": '{"function_name":"entry","variable_name":"this","name":"context"}',
                },
            }]),
            FakeToolMessage(tool_calls=[{
                "id": "valid-comment",
                "type": "function",
                "function": {
                    "name": "set_function_comment",
                    "arguments": '{"function_name":"entry","comment":"Valid comment."}',
                },
            }]),
            FakeToolMessage("Annotation complete."),
        ]

        with patch.object(workflow, "_llm_client", return_value=client):
            workflow._llm_with_tools("system", "prompt", toolbox, staging)

        exposed = {tool["function"]["name"] for tool in client.calls[0]["tools"]}
        self.assertIn("retype_variable", exposed)
        self.assertIn("update_function_definition", exposed)
        tool_messages = [
            message["content"]
            for request in client.calls
            for message in request["messages"]
            if message.get("role") == "tool"
        ]
        self.assertTrue(any("auto-parameter and cannot be renamed" in message for message in tool_messages))
        self.assertEqual([operation["kind"] for operation in staging.operations], ["set_function_comment"])

    def test_llm_guided_selection_prompt_includes_compact_function_sketch(self) -> None:
        workflow = AnnotationWorkflow(FakeAnnotationBridge(), "program-1")
        captured = {}

        def fake_llm(_system, prompt):
            captured["prompt"] = prompt
            return '{"selected_functions": [{"address": {"space": "ram", "offset": "1100"}}]}'

        with patch.object(workflow, "_llm_text", side_effect=fake_llm):
            selected = workflow._selected_functions(
                {},
                [{"name": "entry", "address": ROOT}, {"name": "decode", "address": CALLEE}],
                "llm_guided",
                {"functions": [
                {"name": "entry", "address": ROOT, "pseudocode": "void entry() {}"},
                    {
                        "name": "decode", "address": CALLEE, "signature": "void decode()",
                        "comment": "Existing decode comment", "pseudocode": "void decode() {\n  int local;\n  decrypt();\n  decrypt();\n}",
                    },
                ]},
            )

        self.assertIn('"function_sketches"', captured["prompt"])
        self.assertIn('"decrypt();"', captured["prompt"])
        self.assertNotIn('"pseudocode": "void decode()', captured["prompt"])
        self.assertNotIn("Existing decode comment", captured["prompt"])
        self.assertEqual([item["name"] for item in selected], ["entry", "decode"])

    def test_gatherer_sketch_removes_comments_declarations_and_duplicates(self) -> None:
        sketches = AnnotationWorkflow._gatherer_context({"functions": [{
            "name": "decode",
            "address": CALLEE,
            "comment": "Function metadata comment",
            "pseudocode": "/* existing comment */\nvoid decode()\n{\n  int local;\n0x1100: decrypt(); /* inline comment */\n0x1104: decrypt();\n  return;\n}",
        }]})

        self.assertEqual(sketches, [{
            "address": CALLEE,
            "pseudocode_sketch": ["decrypt();", "return;"],
        }])

    def test_llm_guided_workflow_runs_without_ui(self) -> None:
        bridge = FakeGuidedBridge()
        workflow = AnnotationWorkflow(bridge, "program-1")
        client = FakeToolClient()
        with tempfile.TemporaryDirectory() as directory:
            history_root = Path(directory) / "history"
            config_path = Path(directory) / "tools.json"
            config_path.write_text(
                '{"version": 2, "groups": {"annotation_read": true, "annotation_write": true}, "tools": {}}'
            )
            with patch("aether_ghidra.features.annotation.history.HISTORY_ROOT", history_root), \
                 patch("aether_ghidra.config.tool_policy.TOOL_CONFIG_PATH", config_path), \
                 patch.object(workflow, "_llm_text", return_value='{"selected_functions":[{"address":{"space":"ram","offset":"1100"}}]}'), \
                 patch.object(workflow, "_llm_client", return_value=client):
                result = workflow.run({"address": ROOT, "mode": "llm_guided", "instruction": "Annotate decoders."})

        self.assertEqual(result["batch_id"], "batch-guided")
        self.assertEqual([item["kind"] for item in bridge.applied[0]], ["set_function_comment"])
        self.assertEqual(bridge.calls, [
            "get_function_call_tree", "get_annotation_context", "rename_function", "apply_annotation_batch",
        ])
        self.assertEqual(len(client.calls), 3)

    def test_annotator_prompt_contains_only_guidance_and_pseudocode(self) -> None:
        workflow = AnnotationWorkflow(FakeAnnotationBridge(), "program-1")
        context = {"functions": [{
            "name": "decode",
            "address": CALLEE,
            "pseudocode": "0x1100: void decode() {}",
            "variables": [{"name": "input", "storage": "r0"}],
            "code_units": [{"address": CALLEE}],
        }]}
        with patch.object(workflow, "_llm_with_tools") as call:
            workflow._propose_operations(context, {"instruction": "Focus on decoding logic."}, "manual")

        prompt = call.call_args.args[1]
        self.assertIn("Focus on decoding logic.", prompt)
        self.assertIn("0x1100: void decode() {}", prompt)
        self.assertNotIn("Renameable variable targets:", prompt)
        self.assertNotIn('"mode"', prompt)
        self.assertNotIn('"instruction"', prompt)
        self.assertNotIn('"variables"', prompt)
        self.assertNotIn('"code_units"', prompt)

    def test_phase_allowlists_block_cross_phase_capabilities(self) -> None:
        workflow = AnnotationWorkflow(FakeAnnotationBridge(), "program-1")
        with self.assertRaisesRegex(RuntimeError, "gathering"):
            workflow._gather("apply_annotation_batch", {})
        with self.assertRaisesRegex(RuntimeError, "annotation"):
            workflow._annotate("get_function_call_tree", {})


if __name__ == "__main__":
    unittest.main()
