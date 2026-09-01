from __future__ import annotations

import unittest
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch

from aether_ghidra.integrations.ghidra.bridge_client import BridgeClient, BridgeError
from aether_ghidra.application.runtime import AgentRuntime, ToolPolicyError
from aether_ghidra.engine import AgentCancelled
from aether_ghidra.features.indexing.manager import FunctionIndexManager


class BridgeClientTests(unittest.TestCase):
    def test_invoke_request_shape(self) -> None:
        client = BridgeClient()
        def request(method, path, payload=None):
            if path == "/health":
                return {"ok": True, "protocol_version": 2}
            return {"result": {"name": "entry"}}

        with patch.object(client, "_request", side_effect=request) as request_mock:
            result = client.invoke("program-1", "get_function", {"address": {"space": "ram", "offset": "1000"}})

        self.assertEqual(result, {"name": "entry"})
        self.assertEqual(request_mock.call_args_list[0].args[:2], ("GET", "/health"))
        request_mock.assert_any_call(
            "POST",
            "/v1/invoke",
            {
                "protocol_version": 2,
                "program_id": "program-1",
                "capability": "get_function",
                "arguments": {"address": {"space": "ram", "offset": "1000"}},
            },
        )

    def test_health_rejects_protocol_mismatch(self) -> None:
        client = BridgeClient()
        with patch.object(client, "_request", return_value={"ok": True, "protocol_version": 99}):
            with self.assertRaisesRegex(BridgeError, "Unsupported Ghidra bridge protocol version"):
                client.health()

    def test_invoke_rejects_bare_function_name_before_http(self) -> None:
        client = BridgeClient()
        with patch.object(client, "_request") as request:
            with self.assertRaisesRegex(ValueError, "Bare function-name targets"):
                client.invoke("program-1", "get_function", {"function_name": "entry"})
        request.assert_not_called()

    def test_analyze_collects_selected_function(self) -> None:
        from unittest.mock import Mock

        agent = Mock()
        agent.run.return_value = {"final_analysis": "Explained"}
        bridge = Mock()
        runtime = AgentRuntime(bridge)
        with patch("aether_ghidra.application.runtime.ChatbotAgent", return_value=agent):
            result = runtime.analyze(
                {
                    "program_id": "program-1",
                    "address": {"space": "ram", "offset": "1000"},
                    "request": "Explain this function",
                }
            )

        self.assertEqual(result["final_analysis"], "Explained")
        agent.run.assert_called_once_with(
            "Explain this function",
            address={"space": "ram", "offset": "1000"},
        )

    def test_direct_write_capability_respects_tool_policy(self) -> None:
        bridge = Mock()
        runtime = AgentRuntime(bridge)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tools.json"
            path.write_text('{"version": 2, "groups": {"program_write": false}, "tools": {}}')
            with patch("aether_ghidra.config.tool_policy.TOOL_CONFIG_PATH", path):
                with self.assertRaises(ToolPolicyError):
                    runtime.run_capability("program-1", "rename_function", {"name": "renamed"})
        bridge.invoke.assert_not_called()

    def test_runtime_accepts_a_backend_neutral_gateway_factory(self) -> None:
        gateway = Mock()
        gateway.invoke.return_value = {"name": "renamed"}
        runtime = AgentRuntime(gateway_factory=lambda _program_id: gateway)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tools.json"
            path.write_text('{"version": 2, "groups": {"program_write": true}, "tools": {}}')
            with patch("aether_ghidra.config.tool_policy.TOOL_CONFIG_PATH", path):
                result = runtime.run_capability(
                    "program-1", "rename_function",
                    {"address": {"space": "ram", "offset": "1000"}, "name": "renamed"},
                )

        self.assertEqual(result, {"name": "renamed"})
        gateway.invoke.assert_called_once()

    def test_chat_job_cancellation_reaches_agent(self) -> None:
        started = threading.Event()

        class BlockingAgent:
            def run(self, message, address=None, cancel=None, progress=None):
                started.set()
                cancel.wait(2)
                raise AgentCancelled("Chat cancelled")

            def cancel_current(self):
                return None

        runtime = AgentRuntime(Mock())
        with patch("aether_ghidra.application.runtime.ChatbotAgent", return_value=BlockingAgent()):
            job = runtime.start_chat("program-1", "Inspect")
            self.assertTrue(started.wait(1))
            runtime.cancel_chat(job["job_id"])
            deadline = time.monotonic() + 1
            state = runtime.chat_job(job["job_id"])
            while state["state"] == "running" and time.monotonic() < deadline:
                time.sleep(0.01)
                state = runtime.chat_job(job["job_id"])

        self.assertEqual(state["state"], "cancelled")

    def test_chat_job_exposes_live_progress(self) -> None:
        progress_seen = threading.Event()
        release = threading.Event()

        class StreamingAgent:
            def run(self, message, address=None, cancel=None, progress=None):
                progress({
                    "conversation_history": [{"role": "user", "content": message}],
                    "tool_calls": [],
                    "final_analysis": "",
                    "iteration": 0,
                    "done": False,
                })
                progress_seen.set()
                release.wait(2)
                return {"final_analysis": "finished", "conversation_history": []}

        runtime = AgentRuntime(Mock())
        with patch("aether_ghidra.application.runtime.ChatbotAgent", return_value=StreamingAgent()):
            job = runtime.start_chat("program-1", "Inspect")
            self.assertTrue(progress_seen.wait(1))
            state = runtime.chat_job(job["job_id"])
            release.set()

        self.assertEqual(state["progress"]["conversation_history"][0]["content"], "Inspect")

    def test_missing_annotation_job_is_reported_as_lost(self) -> None:
        state = AgentRuntime(Mock()).annotation_job("missing-job")

        self.assertEqual(state["state"], "lost")
        self.assertIn("restarted", state["error"])

    def test_missing_index_job_recovers_persisted_checkpoint(self) -> None:
        runtime = AgentRuntime(Mock())
        with patch.object(FunctionIndexManager, "load_job", return_value={
            "job_id": "old-job", "program_id": "program-1", "state": "running",
            "progress": {"percent": 35, "indexed": 4, "total": 10},
        }):
            state = runtime.index_job("old-job")

        self.assertEqual(state["state"], "paused")
        self.assertTrue(state["resumable"])
        self.assertIn("resume=true", state["resume_hint"])


if __name__ == "__main__":
    unittest.main()
