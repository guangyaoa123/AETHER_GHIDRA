from __future__ import annotations

import json
import os
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

from aether_ghidra.api.server import AgentHandler


class FakeRuntime:
    def programs(self):
        return [{"program_id": "program-1"}]

    def session_state(self, program_id):
        return {"program_id": program_id, "conversation_history": []}

    def run_capability(self, program_id, capability, arguments):
        return {"program_id": program_id, "capability": capability, "arguments": arguments}

    def plan(self, request, program_id):
        return {"request": request, "program_id": program_id}

    def analyze(self, payload):
        return {"kind": "analyze", **payload}

    def chat(self, program_id, message, address=None):
        return {"program_id": program_id, "message": message, "address": address}

    def start_chat(self, program_id, message, address=None):
        return {"job_id": "chat-job-1", "program_id": program_id, "state": "queued", "message": message, "address": address}

    def chat_job(self, job_id):
        return {"job_id": job_id, "state": "completed", "result": {"final_analysis": "Answer"}}

    def cancel_chat(self, job_id):
        return {"job_id": job_id, "state": "cancelled"}

    def clear_session(self, program_id):
        self.cleared = program_id

    def start_annotation(self, payload):
        return {"job_id": "job-1", "state": "queued"}

    def annotation_job(self, job_id):
        if job_id == "missing-job":
            return {
                "job_id": job_id,
                "state": "lost",
                "message": "Annotation job is no longer available",
                "error": "Annotation job lost because the Python agent restarted.",
            }
        return {"job_id": job_id, "state": "completed", "progress": 100}

    def cancel_annotation(self, job_id):
        return {"job_id": job_id, "state": "cancelled"}

    def undo_annotation(self, program_id):
        return {"program_id": program_id, "undone": True}

    def index_entries(self, program_id, offset=0, limit=1000):
        return {"program_id": program_id, "offset": offset, "limit": limit, "functions": []}

    def pause_index(self, program_id):
        return {"program_id": program_id, "jobs": []}


class ServiceRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = FakeRuntime()
        handler = type("BoundAgentHandler", (AgentHandler,), {"runtime": cls.runtime})
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(self.base_url + path, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        with urlopen(request) as response:
            return response.status, json.loads(response.read())

    def test_health_and_program_routes(self):
        status, health = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["ok"])
        self.assertEqual(health["protocol_version"], 2)
        self.assertEqual(health["pid"], os.getpid())
        self.assertIsNone(health["bridge_url"])

        status, programs = self.request("GET", "/v1/programs")
        self.assertEqual(status, 200)
        self.assertEqual(programs["programs"][0]["program_id"], "program-1")

        status, session = self.request("GET", "/v1/session/program-1")
        self.assertEqual(status, 200)
        self.assertEqual(session["result"]["program_id"], "program-1")

    def test_post_routes(self):
        status, chat = self.request("POST", "/v1/chat", {"program_id": "program-1", "message": "Inspect"})
        self.assertEqual(status, 200)
        self.assertEqual(chat["result"]["message"], "Inspect")

        status, invoked = self.request(
            "POST",
            "/v1/invoke",
            {"program_id": "program-1", "capability": "list_functions", "arguments": {}},
        )
        self.assertEqual(status, 200)
        self.assertEqual(invoked["result"]["capability"], "list_functions")

        status, cleared = self.request("POST", "/v1/session/clear", {"program_id": "program-1"})
        self.assertEqual(status, 200)
        self.assertTrue(cleared["ok"])
        self.assertEqual(self.runtime.cleared, "program-1")

    def test_chat_job_routes(self):
        status, started = self.request(
            "POST", "/v1/chat-jobs",
            {"program_id": "program-1", "message": "Inspect", "address": {"space": "ram", "offset": "1000"}},
        )
        self.assertEqual(status, 202)
        self.assertEqual(started["result"]["job_id"], "chat-job-1")

        status, job = self.request("GET", "/v1/chat-jobs/chat-job-1")
        self.assertEqual(status, 200)
        self.assertEqual(job["result"]["state"], "completed")

        status, cancelled = self.request("POST", "/v1/chat-jobs/chat-job-1/cancel", {})
        self.assertEqual(status, 200)
        self.assertEqual(cancelled["result"]["state"], "cancelled")

    def test_annotation_job_routes(self):
        status, started = self.request("POST", "/v1/annotation-jobs", {"program_id": "program-1", "mode": "manual"})
        self.assertEqual(status, 202)
        self.assertEqual(started["result"]["job_id"], "job-1")

        status, job = self.request("GET", "/v1/annotation-jobs/job-1")
        self.assertEqual(status, 200)
        self.assertEqual(job["result"]["state"], "completed")

        status, cancelled = self.request("POST", "/v1/annotation-jobs/job-1/cancel", {})
        self.assertEqual(status, 200)
        self.assertEqual(cancelled["result"]["state"], "cancelled")

        status, missing = self.request("GET", "/v1/annotation-jobs/missing-job")
        self.assertEqual(status, 200)
        self.assertEqual(missing["result"]["state"], "lost")

        status, undone = self.request("POST", "/v1/annotations/undo", {"program_id": "program-1"})
        self.assertEqual(status, 200)
        self.assertTrue(undone["result"]["undone"])

    def test_index_entry_route(self):
        status, entries = self.request("POST", "/v1/index-entries", {"program_id": "program-1"})
        self.assertEqual(status, 200)
        self.assertEqual(entries["result"]["program_id"], "program-1")

    def test_index_pause_route(self):
        status, response = self.request("POST", "/v1/index-jobs/pause", {"program_id": "program-1"})
        self.assertEqual(status, 200)
        self.assertEqual(response["result"]["program_id"], "program-1")


if __name__ == "__main__":
    unittest.main()
