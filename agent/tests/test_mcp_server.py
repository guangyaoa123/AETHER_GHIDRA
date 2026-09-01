from __future__ import annotations

import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from aether_ghidra.api.mcp_server import (
    AnalysisSessionManager,
    BridgeError,
    MCPApplication,
    structured_progress,
    serve_stdio,
)


class FakeBridge:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self.analysis_status = {
            "program_id": "/fixture", "state": "completed", "is_analyzing": False,
            "analyzed": True, "rtti_recovery_state": "completed",
        }

    def health(self):
        return {"ok": True, "protocol_version": 2, "service": "ghidra-aether-bridge"}

    def list_programs(self):
        return [{"program_id": "/fixture", "project_path": "/fixture", "name": "fixture", "state": "open"}]

    def get_project(self):
        return {"gpr_path": "/tmp/fake.gpr", "name": "fake", "state": "open"}

    def open_program(self, program_id):
        return {"program_id": program_id, "name": Path(program_id).name, "state": "open"}

    def close_program(self, program_id):
        return {"program_id": program_id, "closed": True, "saved": True}

    def invoke(self, program_id, capability, arguments):
        self.calls.append((program_id, capability, arguments))
        if capability == "get_analysis_status":
            return {**self.analysis_status, "program_id": program_id}
        return {"capability": capability}

    def import_program(self, path):
        return {
            "primary_program_id": "/fixture",
            "programs": [{"program_id": "/fixture", "name": "imported", "state": "open"}],
        }


class FakeAgent:
    def request(self, method, path, payload=None):
        return {
            "job_id": "job-1",
            "program_id": "/fixture",
            "state": "running",
            "progress": {"progress": 25, "current_function_name": "entry"},
        }


class MCPServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.config_directory.cleanup)
        manifest = Path(self.config_directory.name) / "projects.json"
        manifest_patch = patch.dict(os.environ, {"AETHER_MCP_PROJECT_MANIFEST": str(manifest)})
        manifest_patch.start()
        self.addCleanup(manifest_patch.stop)
        self.bridge = FakeBridge()
        self.sessions = AnalysisSessionManager(
            bridge_factory=lambda _url: self.bridge,
            opener=lambda *_args, **_kwargs: None,
        )
        self.sessions.interactive().agent = FakeAgent()
        self.application = MCPApplication(self.sessions)
        self.application.handle({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
        })

    def test_program_read_and_write_tools_are_exposed(self) -> None:
        response = self.application.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        names = {tool["name"] for tool in response["result"]["tools"]}
        self.assertIn("get_analysis_status", names)
        self.assertIn("start_function_index", names)
        self.assertIn("import_binary", names)
        for name in {
            "rename_function", "rename_variable", "retype_variable", "update_function_definition",
            "set_function_comment", "set_code_unit_comment", "apply_annotation_batch",
            "create_struct", "add_fields", "update_fields", "remove_fields", "resize_struct",
            "create_class", "update_class", "delete_class",
        }:
            self.assertIn(name, names)
        self.assertNotIn("save_summary", names)
        self.assertNotIn("add_memory", names)
        self.assertNotIn("add_action_plan", names)
        self.assertNotIn("get_function_pseudocode", names)

    def test_function_targeting_tools_use_address_only(self) -> None:
        response = self.application.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/list", "params": {}})
        tools = {tool["name"]: tool for tool in response["result"]["tools"]}
        for name in {
            "get_function", "rename_function", "rename_variable", "retype_variable",
            "update_function_definition", "set_function_comment",
        }:
            schema = tools[name]["inputSchema"]
            self.assertIn("address", schema["properties"])
            self.assertNotIn("function_ref", schema["properties"])
            self.assertIn("address", schema["required"])
        self.assertNotIn("include_pseudocode", tools["get_function"]["inputSchema"]["properties"])

    def test_initialize_reports_existing_interactive_startup(self) -> None:
        response = self.application.handle({
            "jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {},
        })
        self.assertEqual(response["result"]["startup"]["state"], "connected")
        self.assertEqual(response["result"]["startup"]["session_id"], "interactive")
        self.assertTrue(response["result"]["startup"]["analyses"][0]["analysis_id"].startswith("analysis-"))

    def test_program_operations_route_through_opaque_analysis_id(self) -> None:
        listed = self.application.handle({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "list_programs", "arguments": {}},
        })
        programs = json.loads(listed["result"]["content"][0]["text"])["programs"]
        analysis_id = programs[0]["analysis_id"]
        response = self.application.handle({
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "get_analysis_status", "arguments": {"analysis_id": analysis_id}},
        })
        self.assertFalse(response["result"]["isError"])
        self.assertEqual(self.bridge.calls[-1][0], "/fixture")

    def test_initialize_reports_no_project_when_none_is_saved(self) -> None:
        manager = AnalysisSessionManager(
            bridge_factory=lambda _url: self.bridge,
            opener=lambda *_args, **_kwargs: None,
        )

        def unavailable():
            raise BridgeError("bridge unavailable", code="unreachable")

        manager.interactive().bridge.health = unavailable
        manager._saved_projects = []
        application = MCPApplication(manager)
        response = application.handle({
            "jsonrpc": "2.0", "id": 8, "method": "initialize", "params": {},
        })
        startup = response["result"]["startup"]
        self.assertEqual(startup["state"], "no_project_open")

    def test_list_programs_reports_startup_instead_of_raw_bridge_failure(self) -> None:
        manager = AnalysisSessionManager(
            bridge_factory=lambda _url: self.bridge,
            opener=lambda *_args, **_kwargs: None,
        )

        def unavailable():
            raise BridgeError("bridge unavailable", code="unreachable")

        manager.interactive().bridge.health = unavailable
        application = MCPApplication(manager)
        manager._saved_projects = []
        application.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        })
        sessions = application.handle({
            "jsonrpc": "2.0", "id": 11, "method": "tools/call",
            "params": {"name": "list_analysis_sessions", "arguments": {}},
        })
        response = application.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "list_programs", "arguments": {}},
        })

        session_payload = json.loads(sessions["result"]["content"][0]["text"])
        self.assertEqual(session_payload["sessions"][0]["state"], "unavailable")
        self.assertFalse("Connection refused" in json.dumps(session_payload))
        self.assertTrue(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["error"], "No Ghidra project is open")
        self.assertEqual(payload["code"], "no_project_open")

    def test_empty_headless_startup_reports_actionable_no_program_error(self) -> None:
        manager = AnalysisSessionManager(
            bridge_factory=lambda _url: self.bridge,
            opener=lambda *_args, **_kwargs: None,
        )
        manager._startup_state = {
            "state": "headless_ready", "mode": "headless", "empty": True,
        }
        application = MCPApplication(manager)
        application.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        })
        listed = application.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "list_programs", "arguments": {}},
        })
        self.assertTrue(listed["result"]["isError"])
        missing = application.handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "get_program_metadata", "arguments": {}},
        })
        self.assertTrue(missing["result"]["isError"])
        payload = json.loads(missing["result"]["content"][0]["text"])
        self.assertEqual(payload["code"], "no_program_loaded")

    def test_open_and_close_existing_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project_path = Path(directory)
            (project_path / "existing.gpr").write_text("", encoding="utf-8")
            (project_path / "existing.rep").mkdir()
            manager = AnalysisSessionManager(bridge_factory=lambda _url: self.bridge)
            manager._saved_projects = []
            opened = manager.open_project(directory, "existing")
            self.assertEqual(opened.name, "existing")
            self.assertEqual(opened.project_id, str(project_path / "existing.gpr"))

    def test_headless_import_gets_a_temporary_project_without_a_handle(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"AETHER_MCP_PROJECT_DIR": directory}):
            project = self.sessions._project_for_import({})
        self.assertTrue(project.project_id.endswith(".gpr"))
        self.assertTrue(project.name.startswith("import-"))
        self.assertEqual(project.path, Path(directory).resolve())

    def test_open_project_persists_only_the_gpr_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as config:
            project_path = Path(directory)
            (project_path / "game.gpr").write_text("", encoding="utf-8")
            (project_path / "game.rep").mkdir()
            manifest = Path(config) / "projects.json"
            with patch.dict(os.environ, {"AETHER_MCP_PROJECT_MANIFEST": str(manifest)}):
                sessions = AnalysisSessionManager(
                    bridge_factory=lambda _url: self.bridge,
                    opener=lambda *_args, **_kwargs: None,
                )
                sessions.open_project(directory, "game")
            saved = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(saved, {"projects": [{"gpr_path": str(project_path / "game.gpr")}]} )

    def test_save_session_invokes_save_for_each_program(self) -> None:
        self.sessions._save_session(self.sessions.interactive())
        self.assertEqual(self.bridge.calls[-1][1], "save_program")

    def test_project_tools_route_through_mcp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project_path = Path(directory)
            (project_path / "existing.gpr").write_text("", encoding="utf-8")
            (project_path / "existing.rep").mkdir()
            tools = self.application.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}})
            schemas = {tool["name"]: tool["inputSchema"] for tool in tools["result"]["tools"]}
            self.assertEqual(schemas["close_project"]["properties"], {})
            self.assertIn("list_open_project", schemas)
            self.assertIn("open_program", schemas)
            self.assertIn("close_program", schemas)

    def test_write_tools_route_to_the_program_bridge(self) -> None:
        common = {"program_id": "/fixture"}
        calls = [
            ("rename_function", {"address": {"space": "ram", "offset": "1000"}, "name": "renamed"}),
            ("rename_variable", {"address": {"space": "ram", "offset": "1000"}, "variable_name": "local_1", "name": "value"}),
            ("retype_variable", {"address": {"space": "ram", "offset": "1000"}, "variable_name": "value", "data_type_path": "/int"}),
            ("update_function_definition", {"address": {"space": "ram", "offset": "1000"}, "return_type": "int", "parameters": []}),
            ("set_function_comment", {"address": {"space": "ram", "offset": "1000"}, "comment": "note"}),
            ("set_code_unit_comment", {"location": {"space": "ram", "offset": "1000"}, "comment_kind": "eol", "comment": "note"}),
            ("apply_annotation_batch", {"operations": [{"kind": "rename_function", "target": {"function_address": {"space": "ram", "offset": "1000"}}, "value": "renamed"}]}),
            ("create_struct", {"name": "Record"}),
            ("add_fields", {"structure_path": "/Record", "fields": []}),
            ("update_fields", {"structure_path": "/Record", "fields": []}),
            ("remove_fields", {"structure_path": "/Record"}),
            ("resize_struct", {"structure_path": "/Record", "size": 8}),
            ("create_class", {"name": "RecordClass"}),
            ("update_class", {"structure_path": "/Record"}),
            ("delete_class", {"structure_path": "/Record"}),
        ]
        for index, (name, arguments) in enumerate(calls, 10):
            response = self.application.handle({
                "jsonrpc": "2.0", "id": index, "method": "tools/call",
                "params": {"name": name, "arguments": {**common, **arguments}},
            })
            self.assertFalse(response["result"]["isError"], name)
        self.assertEqual([call[1] for call in self.bridge.calls[-len(calls):]], [name for name, _ in calls])

    def test_pseudocode_is_always_read_only(self) -> None:
        response = self.application.handle({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "get_function",
                "arguments": {
                    "program_id": "/fixture",
                    "address": {"space": "ram", "offset": "1000"},
                },
            },
        })
        self.assertFalse(response["result"]["isError"])
        self.assertEqual(self.bridge.calls[-1][1], "get_function")
        self.assertTrue(self.bridge.calls[-1][2]["read_only"])

    def test_index_status_contains_structured_progress(self) -> None:
        response = self.application.handle({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "get_function_index_job",
                "arguments": {"program_id": "/fixture", "job_id": "job-1"},
            },
        })
        progress = response["result"]["structuredContent"] if "structuredContent" in response["result"] else None
        self.assertFalse(response["result"]["isError"])
        text = response["result"]["content"][0]["text"]
        self.assertIn('"progress"', text)
        self.assertIn('"percent":25', text)
        self.assertIsNone(progress)

    def test_progress_fills_current_and_message(self) -> None:
        progress = structured_progress({"progress": 50, "current_function_name": "worker", "last_error": "retry"}, "running")
        self.assertEqual(progress["percent"], 50)
        self.assertEqual(progress["current"], "worker")
        self.assertEqual(progress["message"], "retry")

    def test_import_automatically_uses_interactive_session(self) -> None:
        with tempfile.NamedTemporaryFile() as binary:
            job = self.sessions.import_binary({"binary_path": binary.name})
        for _ in range(20):
            result = self.sessions.import_job(job["job_id"])
            if result["state"] == "completed":
                break
            time.sleep(0.01)
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["result"]["session_id"], "interactive")
        self.assertEqual(result["result"]["program_id"], "/fixture")
        self.assertTrue(result["result"]["analysis_id"].startswith("analysis-"))
        self.assertEqual(result["result"]["analysis_status"]["state"], "completed")

    def test_rtti_failure_does_not_complete_import_barrier(self) -> None:
        self.bridge.analysis_status = {
            "state": "not_analyzed", "is_analyzing": False,
            "analyzed": False, "rtti_recovery_state": "failed",
        }
        with self.assertRaisesRegex(RuntimeError, "RTTI recovery failed"):
            self.sessions._wait_rtti_recovery(
                self.sessions.interactive(), "/fixture", 0.1,
            )

    def test_stdio_requires_json_rpc_and_returns_initialize(self) -> None:
        incoming = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
        outgoing = io.StringIO()
        serve_stdio(incoming, outgoing, application=MCPApplication(self.sessions))
        self.assertIn('"protocolVersion":"2024-11-05"', outgoing.getvalue())


if __name__ == "__main__":
    unittest.main()
