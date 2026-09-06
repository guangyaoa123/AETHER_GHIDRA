from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from ..integrations.ghidra.bridge_client import BridgeError
from ..config.settings import load_config
from ..observability.logging import configure_logging
from ..application.runtime import AgentRuntime, ToolPolicyError


logger = logging.getLogger(__name__)
PROTOCOL_VERSION = 2
DEFAULT_AGENT_RUN_DIR = Path("~/.config/aether-ghidra/run")


def agent_run_directory() -> Path:
    configured = os.getenv("AETHER_AGENT_RUN_DIR")
    return (Path(configured).expanduser() if configured else DEFAULT_AGENT_RUN_DIR.expanduser()).resolve()


def agent_pidfile_path(port: int, run_directory: Path | None = None) -> Path:
    return (run_directory or agent_run_directory()) / f"agent-{port}.pid"


def _read_pidfile(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _is_agent_process(pid: int) -> bool:
    if os.name == "nt":
        return True
    try:
        command_line = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace")
    except OSError:
        return False
    return "aether_ghidra.api.server" in command_line


def _probe_health(endpoint: str, opener=urlopen) -> dict[str, Any] | None:
    try:
        request = Request(endpoint.rstrip("/") + "/health", method="GET")
        with opener(request, timeout=0.5) as response:
            if response.status < 200 or response.status >= 300:
                return None
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, ValueError, TypeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _health_matches(payload: dict[str, Any] | None, service: str) -> bool:
    return bool(payload and payload.get("ok") is True and
                payload.get("service") == service and
                payload.get("protocol_version") == PROTOCOL_VERSION)


def sweep_stale_agents(run_directory: Path | None = None, *, opener=urlopen) -> list[int]:
    """Stop agents whose bridge is gone, while preserving live agent sessions."""
    directory = (run_directory or agent_run_directory()).expanduser()
    try:
        pidfiles = list(directory.glob("agent-*.pid"))
    except OSError:
        return []

    stopped: list[int] = []
    for pidfile in pidfiles:
        payload = _read_pidfile(pidfile)
        try:
            pid = int(payload["pid"]) if payload else 0
        except (KeyError, TypeError, ValueError):
            pid = 0
        if pid < 1:
            try:
                pidfile.unlink(missing_ok=True)
            except OSError:
                pass
            continue
        if not _pid_exists(pid):
            try:
                pidfile.unlink(missing_ok=True)
            except OSError:
                pass
            continue
        if not _is_agent_process(pid):
            continue

        agent_url = str(payload.get("agent_url", "")) if payload else ""
        bridge_url = str(payload.get("bridge_url", "")) if payload else ""
        agent_health = _probe_health(agent_url, opener=opener) if agent_url else None
        if not _health_matches(agent_health, "aether-ghidra-agent"):
            continue
        if agent_health.get("pid") != pid:
            continue
        if not bridge_url or _health_matches(_probe_health(bridge_url, opener=opener), "ghidra-aether-bridge"):
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            stopped.append(pid)
            for _ in range(20):
                if not _pid_exists(pid):
                    break
                time.sleep(0.05)
        except OSError:
            pass
    return stopped


def _write_pidfile(port: int, bridge_url: str | None) -> Path | None:
    path = agent_pidfile_path(port)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(json.dumps({
            "pid": os.getpid(),
            "agent_url": f"http://127.0.0.1:{port}",
            "bridge_url": bridge_url,
        }) + "\n", encoding="utf-8")
        temporary.replace(path)
        return path
    except OSError as error:
        logger.warning("Could not write AETHER agent pidfile: %s", error)
        return None


def _remove_pidfile(path: Path | None) -> None:
    if path is None:
        return
    payload = _read_pidfile(path)
    if payload and payload.get("pid") != os.getpid():
        return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


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
                    "pid": os.getpid(),
                    "bridge_url": os.getenv("AETHER_GHIDRA_URL"),
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
            elif self.path == "/v1/index-jobs/pause":
                self._send(200, {"ok": True, "result": self.runtime.pause_index(payload["program_id"])})
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
    sweep_stale_agents()
    runtime = AgentRuntime()
    handler = type("BoundAgentHandler", (AgentHandler,), {"runtime": runtime})
    server = ThreadingHTTPServer((bind_host, bind_port), handler)
    pidfile = _write_pidfile(bind_port, os.getenv("AETHER_GHIDRA_URL"))

    def request_shutdown(_signum: int, _frame: Any) -> None:
        # shutdown() must run outside the serve_forever thread.
        import threading
        threading.Thread(target=server.shutdown, name="aether-agent-shutdown", daemon=True).start()

    previous_handlers = {}
    for signal_name in ("SIGTERM", "SIGINT"):
        shutdown_signal = getattr(signal, signal_name, None)
        if shutdown_signal is not None:
            previous_handlers[shutdown_signal] = signal.getsignal(shutdown_signal)
            signal.signal(shutdown_signal, request_shutdown)
    logger.info("AETHER Python agent listening on http://%s:%s", bind_host, bind_port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        _remove_pidfile(pidfile)
        for shutdown_signal, previous_handler in previous_handlers.items():
            signal.signal(shutdown_signal, previous_handler)


if __name__ == "__main__":
    if "--sweep-stale" in sys.argv[1:]:
        sweep_stale_agents()
    else:
        serve()
