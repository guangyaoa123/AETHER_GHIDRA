from __future__ import annotations

import json
import os
import signal
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aether_ghidra.api import server


class AgentLifecycleTests(unittest.TestCase):
    def test_pidfile_is_written_and_removed_for_current_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"AETHER_AGENT_RUN_DIR": directory}):
                path = server._write_pidfile(4321, "http://127.0.0.1:8765")
                self.assertIsNotNone(path)
                assert path is not None
                payload = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(payload["pid"], os.getpid())
                self.assertEqual(payload["agent_url"], "http://127.0.0.1:4321")
                server._remove_pidfile(path)
                self.assertFalse(path.exists())

    def test_sweep_stops_agent_with_dead_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "agent-4321.pid"
            pidfile.write_text(json.dumps({
                "pid": 1234,
                "agent_url": "http://127.0.0.1:4321",
                "bridge_url": "http://127.0.0.1:8765",
            }), encoding="utf-8")
            agent_health = {
                "ok": True, "service": "aether-ghidra-agent", "protocol_version": 2,
                "pid": 1234,
            }
            bridge_health = {
                "ok": False, "service": "ghidra-aether-bridge", "protocol_version": 2,
            }
            with patch.object(server, "_pid_exists", return_value=True), \
                 patch.object(server, "_is_agent_process", return_value=True), \
                 patch.object(server, "_probe_health", side_effect=[agent_health, bridge_health]), \
                 patch.object(server.os, "kill") as kill:
                stopped = server.sweep_stale_agents(Path(directory))
            self.assertEqual(stopped, [1234])
            kill.assert_called_once_with(1234, signal.SIGTERM)
            self.assertTrue(pidfile.exists())

    def test_sweep_removes_pidfile_for_dead_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "agent-4321.pid"
            pidfile.write_text(json.dumps({"pid": 1234}), encoding="utf-8")
            with patch.object(server, "_pid_exists", return_value=False):
                self.assertEqual(server.sweep_stale_agents(Path(directory)), [])
            self.assertFalse(pidfile.exists())
