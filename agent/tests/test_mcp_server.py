from __future__ import annotations

import io
import json
import os
import signal
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from aether_ghidra.api import mcp_server
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
        gui_patch = patch.object(AnalysisSessionManager, "_gui_ghidra_running", return_value=False)
        gui_patch.start()
        self.addCleanup(gui_patch.stop)
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
        self.assertIn("get_function_index_job", names)
        self.assertIn("cancel_function_index", names)
        self.assertIn("get_function_index_stats", names)
        self.assertIn("list_function_index_entries", names)
        self.assertIn("search_function_index", names)
        self.assertIn("import_binary", names)
        self.assertIn("forget_project", names)
        for name in {
            "rename_function", "rename_variable", "retype_variable", "update_function_definition",
            "set_function_comment", "set_code_unit_comment",
            "create_struct", "add_fields", "update_fields", "remove_fields", "resize_struct",
            "create_class", "update_class", "delete_class",
        }:
            self.assertIn(name, names)
        self.assertNotIn("save_summary", names)
        self.assertNotIn("add_memory", names)
        self.assertNotIn("add_action_plan", names)
        self.assertNotIn("get_function_pseudocode", names)
        self.assertNotIn("apply_annotation_batch", names)
        schemas = {tool["name"]: tool["inputSchema"] for tool in response["result"]["tools"]}
        self.assertEqual(schemas["close_project"]["properties"], {})
        self.assertIn("list_open_project", schemas)
        self.assertIn("open_program", schemas)
        self.assertIn("close_program", schemas)
        self.assertEqual(schemas["forget_project"]["required"], ["gpr_path"])
        response = self.application.handle({
            "jsonrpc": "2.0", "id": 41, "method": "tools/call",
            "params": {"name": "apply_annotation_batch", "arguments": {"program_id": "/fixture"}},
        })
        self.assertEqual(response["error"]["data"]["code"], "unknown_tool")

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
        self.assertIn("vtable", tools["rename_function"]["description"])

    def test_initialize_reports_existing_interactive_startup(self) -> None:
        response = self.application.handle({
            "jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {},
        })
        self.assertEqual(response["result"]["startup"]["state"], "connected")
        self.assertEqual(response["result"]["startup"]["session_id"], "interactive")
        self.assertTrue(response["result"]["startup"]["analyses"][0]["analysis_id"].startswith("analysis-"))

    def test_orphan_lease_reaper_escalates_to_sigkill(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lease_dir = Path(directory) / "sessions"
            lease_dir.mkdir()
            with patch.dict(os.environ, {"AETHER_MCP_SESSION_DIR": str(lease_dir)}):
                manager = AnalysisSessionManager(
                    bridge_factory=lambda _url: self.bridge,
                    opener=lambda *_args, **_kwargs: None,
                )
            lease = lease_dir / "headless-test.json"
            lease.write_text(json.dumps({"owner_pid": 1234, "process_pid": 5678}), encoding="utf-8")
            with patch.object(os, "kill", side_effect=ProcessLookupError), \
                 patch.object(os, "killpg") as killpg, \
                 patch.object(time, "monotonic", side_effect=[0.0, 1.0, 3.0]), \
                 patch.object(manager, "sleep") as sleep, \
                 patch.object(manager, "_process_group_alive", return_value=True):
                manager._reap_orphan_leases()
            self.assertEqual(killpg.call_args_list, [
                call(5678, signal.SIGTERM),
                call(5678, signal.SIGKILL),
            ])
            sleep.assert_called_once_with(0.1)
            self.assertFalse(lease.exists())

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
        initialized = application.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        })
        self.assertEqual(initialized["result"]["startup"]["state"], "no_project_open")
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
                opened = sessions.open_project(directory, "game")
            self.assertEqual(opened.name, "game")
            self.assertEqual(opened.project_id, str(project_path / "game.gpr"))
            saved = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(saved, {"projects": [{"gpr_path": str(project_path / "game.gpr")}]} )

    def test_manifest_prunes_missing_projects_and_can_forget_existing(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as config:
            project_path = Path(directory)
            existing = project_path / "existing.gpr"
            existing.write_text("", encoding="utf-8")
            manifest = Path(config) / "projects.json"
            manifest.write_text(json.dumps({"projects": [
                {"gpr_path": str(project_path / "missing.gpr")},
                {"gpr_path": str(existing)},
            ]}), encoding="utf-8")
            with patch.dict(os.environ, {"AETHER_MCP_PROJECT_MANIFEST": str(manifest)}):
                manager = AnalysisSessionManager(
                    bridge_factory=lambda _url: self.bridge,
                    opener=lambda *_args, **_kwargs: None,
                )
                self.assertEqual(manager._saved_projects, [existing.resolve()])
                result = manager.forget_project(str(existing))
            self.assertTrue(result["forgotten"])
            self.assertEqual(json.loads(manifest.read_text(encoding="utf-8")), {"projects": []})

    def test_startup_reports_locked_saved_project_without_spawning_headless(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as config:
            project_path = Path(directory)
            gpr = project_path / "locked.gpr"
            gpr.write_text("", encoding="utf-8")
            manifest = Path(config) / "projects.json"
            manifest.write_text(json.dumps({"projects": [{"gpr_path": str(gpr)}]}), encoding="utf-8")
            with patch.dict(os.environ, {
                "AETHER_MCP_PROJECT_MANIFEST": str(manifest),
                "AETHER_MCP_BRIDGE_RETRIES": "0",
            }):
                popen = Mock()
                manager = AnalysisSessionManager(
                    bridge_factory=lambda _url: self.bridge,
                    opener=lambda *_args, **_kwargs: None,
                    popen_factory=popen,
                )

                def unavailable():
                    raise BridgeError("bridge unavailable", code="unreachable")

                manager.interactive().bridge.health = unavailable
                lock_path = gpr.with_suffix(".lock")
                lock_path.write_text("held", encoding="utf-8")
                with patch.object(mcp_server.fcntl, "lockf", side_effect=BlockingIOError):
                    startup = manager.startup()
            self.assertEqual(startup["state"], "project_locked")
            self.assertEqual(startup["lock_path"], str(lock_path))
            popen.assert_not_called()

    def test_startup_waits_for_gui_bridge_before_headless_fallback(self) -> None:
        manager = AnalysisSessionManager(
            bridge_factory=lambda _url: self.bridge,
            opener=lambda *_args, **_kwargs: None,
        )
        health = manager.interactive().bridge.health
        manager.interactive().bridge.health = Mock(side_effect=[
            BridgeError("bridge starting", code="unreachable"), health(),
        ])
        manager._saved_projects = []
        with patch.object(manager, "sleep") as sleep:
            startup = manager.startup()
        self.assertEqual(startup["state"], "connected")
        sleep.assert_called_once_with(0.5)

    def test_startup_pauses_restore_when_gui_ghidra_is_present(self) -> None:
        manager = AnalysisSessionManager(
            bridge_factory=lambda _url: self.bridge,
            opener=lambda *_args, **_kwargs: None,
            popen_factory=Mock(),
        )

        def unavailable():
            raise BridgeError("bridge unavailable", code="unreachable")

        manager.interactive().bridge.health = unavailable
        with patch.dict(os.environ, {"AETHER_MCP_BRIDGE_RETRIES": "0"}), \
             patch.object(manager, "_gui_ghidra_running", return_value=True):
            startup = manager.startup()
        self.assertEqual(startup["state"], "gui_bridge_unavailable")
        manager.popen_factory.assert_not_called()

    def test_save_session_invokes_save_for_each_program(self) -> None:
        self.sessions._save_session(self.sessions.interactive())
        self.assertEqual(self.bridge.calls[-1][1], "save_program")

    def test_write_tools_route_to_the_program_bridge(self) -> None:
        common = {"program_id": "/fixture"}
        calls = [
            ("rename_function", {"address": {"space": "ram", "offset": "1000"}, "name": "renamed"}),
            ("rename_variable", {"address": {"space": "ram", "offset": "1000"}, "variable_name": "local_1", "name": "value"}),
            ("retype_variable", {"address": {"space": "ram", "offset": "1000"}, "variable_name": "value", "data_type_path": "/int"}),
            ("update_function_definition", {"address": {"space": "ram", "offset": "1000"}, "return_type": "int", "parameters": []}),
            ("set_function_comment", {"address": {"space": "ram", "offset": "1000"}, "comment": "note"}),
            ("set_code_unit_comment", {"location": {"space": "ram", "offset": "1000"}, "comment_kind": "eol", "comment": "note"}),
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

    def test_indexing_tools_route_to_agent(self) -> None:
        agent = Mock()
        agent.request.side_effect = [
            {"job_id": "job/1", "program_id": "/fixture", "state": "queued", "progress": {"progress": 0}},
            {"job_id": "job/1", "program_id": "/fixture", "state": "running", "progress": {"progress": 25}},
            {"job_id": "job/1", "program_id": "/fixture", "state": "cancelled", "progress": {"progress": 25}},
            {"stable_id": "sha", "indexed": 1, "total": 2},
            {"offset": 2, "limit": 3, "entries": [{"name": "entry"}]},
            {"query": "network", "results": ["entry"]},
        ]
        self.sessions.interactive().agent = agent

        def invoke_tool(name, arguments):
            return self.application.handle({
                "jsonrpc": "2.0", "id": name, "method": "tools/call",
                "params": {"name": name, "arguments": {"program_id": "/fixture", **arguments}},
            })["result"]

        started = invoke_tool("start_function_index", {"resume": True, "reindex": True})
        status = invoke_tool("get_function_index_job", {"job_id": "job/1"})
        cancelled = invoke_tool("cancel_function_index", {"job_id": "job/1"})
        stats = invoke_tool("get_function_index_stats", {})
        entries = invoke_tool("list_function_index_entries", {"offset": 2, "limit": 3})
        search = invoke_tool("search_function_index", {"query": "network"})

        self.assertFalse(started["isError"])
        self.assertEqual(json.loads(started["content"][0]["text"])["progress"]["percent"], 0)
        self.assertFalse(status["isError"])
        self.assertEqual(json.loads(status["content"][0]["text"])["progress"]["percent"], 25)
        self.assertFalse(cancelled["isError"])
        self.assertEqual(json.loads(stats["content"][0]["text"])["stable_id"], "sha")
        self.assertEqual(json.loads(entries["content"][0]["text"])["entries"][0]["name"], "entry")
        self.assertEqual(json.loads(search["content"][0]["text"])["results"], ["entry"])
        agent.request.assert_has_calls([
            call("POST", "/v1/index-jobs", {"program_id": "/fixture", "resume": True, "reindex": True}),
            call("GET", "/v1/index-jobs/job%2F1"),
            call("POST", "/v1/index-jobs/job%2F1/cancel", {}),
            call("POST", "/v1/index-stats", {"program_id": "/fixture"}),
            call("POST", "/v1/index-entries", {"program_id": "/fixture", "offset": 2, "limit": 3}),
            call("POST", "/v1/index-search", {"program_id": "/fixture", "query": "network"}),
        ])

    def test_indexing_tools_enforce_analysis_and_program_guards(self) -> None:
        agent = Mock()
        self.sessions.interactive().agent = agent
        self.bridge.analysis_status["is_analyzing"] = True
        blocked = self.application.handle({
            "jsonrpc": "2.0", "id": 50, "method": "tools/call",
            "params": {"name": "start_function_index", "arguments": {"program_id": "/fixture"}},
        })
        blocked_payload = json.loads(blocked["result"]["content"][0]["text"])
        self.assertTrue(blocked["result"]["isError"])
        self.assertEqual(blocked_payload["code"], "analysis_in_progress")
        agent.request.assert_not_called()

        self.bridge.analysis_status["is_analyzing"] = False
        agent.request.return_value = {
            "job_id": "job-1", "program_id": "/other", "state": "running", "progress": {},
        }
        mismatch = self.application.handle({
            "jsonrpc": "2.0", "id": 51, "method": "tools/call",
            "params": {"name": "get_function_index_job", "arguments": {
                "program_id": "/fixture", "job_id": "job-1",
            }},
        })
        mismatch_payload = json.loads(mismatch["result"]["content"][0]["text"])
        self.assertTrue(mismatch["result"]["isError"])
        self.assertEqual(mismatch_payload["code"], "program_mismatch")

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

    def test_stdio_closes_managed_sessions_when_stdin_ends(self) -> None:
        sessions = Mock()
        application = MCPApplication(sessions)
        serve_stdio(io.StringIO(), io.StringIO(), application=application)
        sessions.close_all.assert_called_once()


if __name__ == "__main__":
    unittest.main()
