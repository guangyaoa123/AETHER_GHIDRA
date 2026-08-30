from __future__ import annotations

import json
import logging
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..integrations.ghidra.bridge_client import BridgeError
from ..config.settings import load_config
from ..observability.logging import configure_logging
from ..application.runtime import AgentRuntime, ToolPolicyError


logger = logging.getLogger(__name__)
PROTOCOL_VERSION = 2


class AgentHandler(BaseHTTPRequestHandler):
    runtime: AgentRuntime

    def do_GET(self) -> None:  # noqa: N802
        started = time.monotonic()
        logger.debug("GET %s", self.path)
        try:
            if self.path == "/health":
                self._send(200, {
                    "ok": True,
                    "service": "aether-ghidra-agent",
                    "protocol_version": PROTOCOL_VERSION,
                })
            elif self.path == "/v1/programs":
                self._send(200, {"programs": self.runtime.programs()})
            elif self.path.startswith("/v1/session/"):
                program_id = self.path.removeprefix("/v1/session/")
                self._send(200, {"ok": True, "result": self.runtime.session_state(program_id)})
            elif self.path.startswith("/v1/annotation-jobs/"):
                job_id = self.path.removeprefix("/v1/annotation-jobs/")
                self._send(200, {"ok": True, "result": self.runtime.annotation_job(job_id)})
            elif self.path.startswith("/v1/chat-jobs/"):
                job_id = self.path.removeprefix("/v1/chat-jobs/")
                self._send(200, {"ok": True, "result": self.runtime.chat_job(job_id)})
            elif self.path.startswith("/v1/index-jobs/"):
                job_id = self.path.removeprefix("/v1/index-jobs/")
                self._send(200, {"ok": True, "result": self.runtime.index_job(job_id)})
            else:
                self._send(404, {"ok": False, "error": "not_found"})
        except BridgeError as error:
            logger.warning("GET %s bridge error code=%s", self.path, error.code)
            self._send(502, {"ok": False, "code": error.code, "error": str(error)})
        except Exception:
            logger.exception("GET %s failed", self.path)
            self._send(500, {"ok": False, "error": "internal_error"})
        finally:
            logger.debug("GET %s completed in %.3fs", self.path, time.monotonic() - started)

    def do_POST(self) -> None:  # noqa: N802
        started = time.monotonic()
        logger.debug("POST %s", self.path)
        try:
            payload = self._read_json()
            if self.path == "/v1/invoke":
                result = self.runtime.run_capability(
                    payload["program_id"], payload["capability"], payload.get("arguments")
                )
                self._send(200, {"ok": True, "result": result})
            elif self.path == "/v1/annotation-jobs":
                self._send(202, {"ok": True, "result": self.runtime.start_annotation(payload)})
            elif self.path.startswith("/v1/annotation-jobs/") and self.path.endswith("/cancel"):
                job_id = self.path.removeprefix("/v1/annotation-jobs/").removesuffix("/cancel").rstrip("/")
                self._send(200, {"ok": True, "result": self.runtime.cancel_annotation(job_id)})
            elif self.path == "/v1/annotations/undo":
                self._send(200, {"ok": True, "result": self.runtime.undo_annotation(payload["program_id"])})
            elif self.path == "/v1/plan":
                self._send(200, {"ok": True, "result": self.runtime.plan(payload["request"], payload["program_id"])})
            elif self.path == "/v1/analyze":
                self._send(200, {"ok": True, "result": self.runtime.analyze(payload)})
            elif self.path == "/v1/chat":
                self._send(200, {"ok": True, "result": self.runtime.chat(payload["program_id"], payload["message"], payload.get("address"))})
            elif self.path == "/v1/chat-jobs":
                self._send(202, {"ok": True, "result": self.runtime.start_chat(payload["program_id"], payload["message"], payload.get("address"))})
            elif self.path.startswith("/v1/chat-jobs/") and self.path.endswith("/cancel"):
                job_id = self.path.removeprefix("/v1/chat-jobs/").removesuffix("/cancel").rstrip("/")
                self._send(200, {"ok": True, "result": self.runtime.cancel_chat(job_id)})
            elif self.path == "/v1/session/clear":
                self.runtime.clear_session(payload["program_id"])
                self._send(200, {"ok": True})
            elif self.path == "/v1/index-jobs":
                self._send(202, {"ok": True, "result": self.runtime.start_index(payload["program_id"], resume=bool(payload.get("resume")), reindex=bool(payload.get("reindex")))})
            elif self.path.startswith("/v1/index-jobs/") and self.path.endswith("/cancel"):
                job_id = self.path.removeprefix("/v1/index-jobs/").removesuffix("/cancel").rstrip("/")
                self._send(200, {"ok": True, "result": self.runtime.cancel_index(job_id)})
            elif self.path == "/v1/index-stats":
                self._send(200, {"ok": True, "result": self.runtime.index_stats(payload["program_id"])})
            elif self.path == "/v1/index-entries":
                self._send(200, {"ok": True, "result": self.runtime.index_entries(
                    payload["program_id"], int(payload.get("offset", 0)), int(payload.get("limit", 1000))
                )})
            elif self.path == "/v1/index-search":
                self._send(200, {"ok": True, "result": {"briefing": self.runtime.search_index(payload["program_id"], payload["query"])}})
            else:
                self._send(404, {"ok": False, "error": "not_found"})
        except ToolPolicyError as error:
            logger.warning("POST %s rejected by tool policy: %s", self.path, error)
            self._send(403, {"ok": False, "error": str(error)})
        except (BridgeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            logger.warning("POST %s rejected: %s", self.path, error)
            self._send(400, {"ok": False, "error": str(error)})
        except Exception as error:
            logger.exception("POST %s failed", self.path)
            self._send(502, {"ok": False, "error": "agent_error", "message": str(error)})
        finally:
            logger.debug("POST %s completed in %.3fs", self.path, time.monotonic() - started)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1024 * 1024:
            raise ValueError("request body is too large")
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("request body must be a JSON object")
        return payload

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        logger.log(logging.DEBUG if status < 400 else logging.WARNING, "%s %s -> %s", self.command, self.path, status)
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def serve(host: str | None = None, port: int | None = None) -> None:
    configure_logging(load_config())
    bind_host = host or os.getenv("AETHER_AGENT_HOST", "127.0.0.1")
    bind_port = port or int(os.getenv("AETHER_AGENT_PORT", "8780"))
    runtime = AgentRuntime()
    handler = type("BoundAgentHandler", (AgentHandler,), {"runtime": runtime})
    server = ThreadingHTTPServer((bind_host, bind_port), handler)
    logger.info("AETHER Python agent listening on http://%s:%s", bind_host, bind_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
