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


class BridgeClientTests(unittest.TestCase):
    def test_invoke_request_shape(self) -> None:
        client = BridgeClient()
        with patch.object(client, "_request", return_value={"result": {"name": "entry"}}) as request:
            result = client.invoke("program-1", "get_function", {"address": {"space": "ram", "offset": "1000"}})

        self.assertEqual(result, {"name": "entry"})
        request.assert_called_once_with(
            "POST",
            "/v1/invoke",
            {
                "program_id": "program-1",
                "capability": "get_function",
                "arguments": {"address": {"space": "ram", "offset": "1000"}},
            },
        )

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


if __name__ == "__main__":
    unittest.main()
