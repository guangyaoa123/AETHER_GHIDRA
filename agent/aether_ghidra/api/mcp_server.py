"""Standalone MCP server for external Ghidra clients.

The module intentionally has no MCP package dependency.  MCP stdio is a
newline-delimited JSON-RPC transport; all diagnostics are sent to stderr so
stdout remains safe to use as the protocol stream.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, TextIO
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from ..integrations.ghidra.bridge_client import BridgeClient, BridgeError


MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "aether-ghidra-analysis"
SERVER_VERSION = "0.1.0"
DEFAULT_BRIDGE_URL = "http://127.0.0.1:8765"
DEFAULT_AGENT_URL = "http://127.0.0.1:8780"
DEFAULT_PROJECT_MANIFEST = Path("~/.config/aether-ghidra/mcp-projects.json")


class MCPServerError(RuntimeError):
    """An actionable error suitable for returning from an MCP tool call."""

    def __init__(self, message: str, *, code: str = "mcp_error") -> None:
        super().__init__(message)
        self.code = code


class AgentAPIError(MCPServerError):
    pass


def _url(value: str | None, fallback: str) -> str:
    return (value or fallback).rstrip("/")


def _required_string(arguments: dict[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or not value.strip():
        raise MCPServerError(f"{name} is required and must be a non-empty string", code="invalid_argument")
    return value.strip()


def _optional_int(arguments: dict[str, Any], name: str, default: int) -> int:
    value = arguments.get(name, default)
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise MCPServerError(f"{name} must be an integer", code="invalid_argument") from error


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(("127.0.0.1", 0))
        return int(server_socket.getsockname()[1])


def _health_ok(value: Any, service: str | None = None) -> bool:
    return (
        isinstance(value, dict)
        and value.get("ok") is True
        and value.get("protocol_version") == 2
        and (service is None or value.get("service") == service)
    )


class AgentHTTPClient:
    """Small urllib-only client for the existing Python agent service."""

    def __init__(
        self,
        base_url: str,
        *,
        opener: Callable[..., Any] = urlopen,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = _url(base_url, DEFAULT_AGENT_URL)
        self.opener = opener
        self.timeout = timeout

    def health(self) -> dict[str, Any]:
        return self.request("GET", "/health", unwrap=False)

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        unwrap: bool = True,
    ) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            method=method,
            headers={
                "Accept": "application/json",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
        )
        try:
            response = self.opener(request, timeout=self.timeout)
            try:
                decoded = json.loads(response.read().decode("utf-8"))
            finally:
                close = getattr(response, "close", None)
                if close is not None:
                    close()
        except HTTPError as error:
            decoded = self._error_body(error)
            error_value = decoded.get("error", "") if isinstance(decoded, dict) else ""
            if isinstance(error_value, dict):
                message = error_value.get("message", str(error))
                code = error_value.get("code", "agent_http_error")
            else:
                message = decoded.get("message", error_value or str(error)) if isinstance(decoded, dict) else str(error)
                code = decoded.get("code", "agent_http_error") if isinstance(decoded, dict) else "agent_http_error"
            raise AgentAPIError(str(message), code=str(code)) from error
        except (OSError, URLError, json.JSONDecodeError) as error:
            raise AgentAPIError(f"Could not connect to AETHER agent at {self.base_url}: {error}", code="unreachable") from error

        if not isinstance(decoded, dict):
            raise AgentAPIError("AETHER agent returned a non-object JSON response", code="invalid_response")
        if decoded.get("ok") is False:
            error_value = decoded.get("error", {})
            if isinstance(error_value, dict):
                raise AgentAPIError(
                    str(error_value.get("message", "Agent request failed")),
                    code=str(error_value.get("code", "agent_error")),
                )
            raise AgentAPIError(str(decoded.get("message", error_value)), code=str(decoded.get("code", "agent_error")))
        if unwrap and "result" in decoded:
            result = decoded["result"]
            if not isinstance(result, dict):
                return {"value": result}
            return result
        return decoded

    @staticmethod
    def _error_body(error: HTTPError) -> dict[str, Any]:
        try:
            return json.loads(error.read().decode("utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}


@dataclass
class ProjectHandle:
    project_id: str
    path: Path
    name: str

    def as_dict(self) -> dict[str, str]:
        return {
            "project_id": self.project_id,
            "gpr_path": self.project_id,
            "path": str(self.path),
            "name": self.name,
        }


@dataclass
class ImportJob:
    job_id: str
    binary: Path
    arguments: dict[str, Any]
    state: str = "queued"
    progress: dict[str, Any] = field(default_factory=lambda: structured_progress(None, "queued"))
    result: dict[str, Any] | None = None
    error: str | None = None
    phase: str = "QUEUED"
    message: str = "Queued"
    last_update: float = field(default_factory=time.time)
    backend_alive: bool | None = None


@dataclass
class AnalysisSession:
    session_id: str
    mode: str
    bridge_url: str
    agent_url: str
    bridge: BridgeClient
    agent: AgentHTTPClient
    process: Any = None
    project: ProjectHandle | None = None
    bridge_port: int | None = None
    agent_port: int | None = None
    closed: bool = False
    bridge_status: str = "unknown"
    ready: bool = False
    output_tail: deque[str] = field(default_factory=lambda: deque(maxlen=200), repr=False)
    lease_path: Path | None = field(default=None, repr=False)
    created_at: float = field(default_factory=time.time)

    @property
    def managed(self) -> bool:
        return self.process is not None

    def as_dict(self) -> dict[str, Any]:
        process_alive = self.process is None or bool(self.process.poll() is None)
        alive = process_alive and (self.mode != "interactive" or self.bridge_status == "ready")
        if self.closed:
            state = "closed"
        elif self.mode == "interactive" and self.bridge_status == "unavailable":
            state = "unavailable"
        elif self.ready:
            state = "ready"
        elif process_alive:
            state = "starting"
        else:
            state = "exited"
        result: dict[str, Any] = {
            "session_id": self.session_id,
            "mode": self.mode,
            "bridge_url": self.bridge_url,
            "agent_url": self.agent_url,
            "managed": self.managed,
            "alive": alive,
            "state": state,
            "bridge_status": self.bridge_status,
        }
        if self.project is not None:
            result["project"] = self.project.as_dict()
        if self.bridge_port is not None:
            result["bridge_port"] = self.bridge_port
        if self.agent_port is not None:
            result["agent_port"] = self.agent_port
        if not alive and self.process is not None:
            result["exit_code"] = self.process.poll()
            result["output_tail"] = list(self.output_tail)
        return result


@dataclass
class AnalysisHandle:
    """Opaque broker handle for one session-scoped Program."""

    analysis_id: str
    session_id: str
    program_id: str
    created_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, str]:
        return {
            "analysis_id": self.analysis_id,
            "session_id": self.session_id,
            "program_id": self.program_id,
        }


class AnalysisBroker:
    """Own backend selection, Program handles, and session lifecycle."""

    def __init__(
        self,
        *,
        bridge_url: str | None = None,
        agent_url: str | None = None,
        bridge_factory: Callable[[str], BridgeClient] = BridgeClient,
        opener: Callable[..., Any] = urlopen,
        popen_factory: Callable[..., Any] = subprocess.Popen,
        sleep: Callable[[float], None] = time.sleep,
        port_factory: Callable[[], int] = _free_port,
        stderr: TextIO | None = None,
    ) -> None:
        self.bridge_url = _url(bridge_url or os.getenv("AETHER_GHIDRA_URL"), DEFAULT_BRIDGE_URL)
        self.agent_url = _url(agent_url or os.getenv("AETHER_AGENT_URL"), DEFAULT_AGENT_URL)
        self.bridge_factory = bridge_factory
        self.opener = opener
        self.popen_factory = popen_factory
        self.sleep = sleep
        self.port_factory = port_factory
        self.stderr = stderr or sys.stderr
        self._lock = threading.RLock()
        self._sessions: dict[str, AnalysisSession] = {}
        self._analyses: dict[str, AnalysisHandle] = {}
        self._analysis_keys: dict[tuple[str, str], str] = {}
        self._projects: dict[str, ProjectHandle] = {}
        self._import_jobs: dict[str, ImportJob] = {}
        self._startup_state: dict[str, Any] | None = None
        self._startup_lock = threading.Lock()
        self._session_lease_dir = Path(
            os.getenv("AETHER_MCP_SESSION_DIR", "/tmp/aether-ghidra-sessions")
        ).expanduser().resolve()
        self._reap_orphan_leases()
        self._manifest_path = Path(
            os.getenv("AETHER_MCP_PROJECT_MANIFEST", str(DEFAULT_PROJECT_MANIFEST))
        ).expanduser().resolve()
        self._saved_projects = self._load_project_manifest()
        # Construct the handle eagerly, but defer all network I/O until a tool uses it.
        self._sessions["interactive"] = self._new_session("interactive", self.bridge_url, self.agent_url)

    def interactive(self) -> AnalysisSession:
        with self._lock:
            current = self._sessions.get("interactive")
            if current is not None and not current.closed:
                return current
            current = self._new_session("interactive", self.bridge_url, self.agent_url)
            self._sessions[current.session_id] = current
            return current

    def _new_session(self, mode: str, bridge_url: str, agent_url: str) -> AnalysisSession:
        return AnalysisSession(
            session_id="interactive" if mode == "interactive" else f"headless-{uuid.uuid4()}",
            mode=mode,
            bridge_url=bridge_url,
            agent_url=agent_url,
            bridge=self.bridge_factory(bridge_url),
            agent=AgentHTTPClient(agent_url, opener=self.opener),
        )

    def _load_project_manifest(self) -> list[Path]:
        try:
            value = json.loads(self._manifest_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return []
        paths = value.get("projects", []) if isinstance(value, dict) else []
        result: list[Path] = []
        for item in paths:
            path = item if isinstance(item, str) else item.get("gpr_path") if isinstance(item, dict) else None
            if isinstance(path, str) and path.strip():
                candidate = Path(path).expanduser().resolve()
                if candidate not in result:
                    result.append(candidate)
        return result

    def _persist_project(self, project: ProjectHandle) -> None:
        gpr_path = (project.path / f"{project.name}.gpr").resolve()
        if not gpr_path.is_file():
            return
        if gpr_path not in self._saved_projects:
            self._saved_projects.append(gpr_path)
        payload = {"projects": [{"gpr_path": str(path)} for path in self._saved_projects]}
        self._manifest_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._manifest_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self._manifest_path)

    @staticmethod
    def _project_from_gpr(gpr_path: Path) -> ProjectHandle:
        gpr_path = gpr_path.expanduser().resolve()
        return ProjectHandle(
            str(gpr_path),
            gpr_path.parent,
            gpr_path.stem,
        )

    def get(self, session_id: str) -> AnalysisSession:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None or session.closed:
            raise MCPServerError(f"Unknown or closed analysis session: {session_id}", code="session_closed")
        if session.managed and session.process.poll() is not None:
            session.closed = True
            raise MCPServerError(self._session_exit_message(session), code="session_exited")
        return session

    def _reconcile_sessions(self) -> None:
        """Remove dead managed sessions before exposing broker state."""
        with self._lock:
            dead = [
                session for session in self._sessions.values()
                if session.managed and session.process.poll() is not None
            ]
            for session in dead:
                session.closed = True
                self._sessions.pop(session.session_id, None)
                self._remove_analysis_handles(session.session_id)
                self._remove_lease(session)
                if self._startup_state and self._startup_state.get("session_id") == session.session_id:
                    self._startup_state = None

    @staticmethod
    def _session_exit_message(session: AnalysisSession) -> str:
        exit_code = session.process.poll() if session.process is not None else None
        message = f"Analysis session has exited: {session.session_id} (exit_code={exit_code})"
        if session.output_tail:
            message += "\nHeadless output:\n" + "\n".join(session.output_tail)
        return message

    def analysis(self, analysis_id: str) -> tuple[AnalysisHandle, AnalysisSession]:
        with self._lock:
            handle = self._analyses.get(analysis_id)
        if handle is None:
            raise MCPServerError(f"Unknown analysis handle: {analysis_id}", code="analysis_not_found")
        return handle, self.get(handle.session_id)

    def _register_analysis(self, session: AnalysisSession, program_id: str) -> AnalysisHandle:
        key = (session.session_id, program_id)
        with self._lock:
            existing_id = self._analysis_keys.get(key)
            if existing_id is not None:
                return self._analyses[existing_id]
            handle = AnalysisHandle(f"analysis-{uuid.uuid4()}", session.session_id, program_id)
            self._analyses[handle.analysis_id] = handle
            self._analysis_keys[key] = handle.analysis_id
            return handle

    def _remove_program_handle(self, session_id: str, program_id: str) -> None:
        with self._lock:
            analysis_id = self._analysis_keys.pop((session_id, program_id), None)
            if analysis_id is not None:
                self._analyses.pop(analysis_id, None)

    def _active_project_session(self, *, required: bool = True) -> AnalysisSession | None:
        self._reconcile_sessions()
        with self._lock:
            sessions = [
                session for session in self._sessions.values()
                if not session.closed and session.project is not None
            ]
        if len(sessions) > 1:
            raise MCPServerError("More than one project session is open", code="project_conflict")
        if sessions:
            return self.get(sessions[0].session_id)
        if required:
            raise MCPServerError("No Ghidra project is open", code="no_project_open")
        return None

    def list_programs(self, analysis_id: str | None = None) -> list[dict[str, Any]]:
        if analysis_id:
            handle, session = self.analysis(analysis_id)
            return self._list_session_programs(session, handle)

        session = self._active_project_session()
        return self._list_session_programs(session)

    def _list_session_programs(
        self,
        session: AnalysisSession,
        selected: AnalysisHandle | None = None,
    ) -> list[dict[str, Any]]:
        programs = session.bridge.list_programs()
        result = []
        for program in programs:
            item = dict(program)
            program_id = item.get("program_id")
            if program_id and item.get("state", "open") == "open":
                handle = self._register_analysis(session, str(program_id))
                if selected is None or handle.program_id == selected.program_id:
                    item["analysis_id"] = handle.analysis_id
            result.append(item)
        return result

    def list_open_project(self) -> dict[str, Any]:
        session = self._active_project_session()
        project = dict(session.bridge.get_project())
        project["session_id"] = session.session_id
        return {"project": project, "programs": self._list_session_programs(session)}

    def open_program(self, program_id: str) -> dict[str, Any]:
        session = self._active_project_session()
        result = session.bridge.open_program(program_id)
        handle = self._register_analysis(session, str(result["program_id"]))
        return {**result, "analysis_id": handle.analysis_id}

    def close_program(self, program_id: str) -> dict[str, Any]:
        session = self._active_project_session()
        result = session.bridge.close_program(program_id)
        self._remove_program_handle(session.session_id, program_id)
        return result

    def list_sessions(self) -> list[dict[str, Any]]:
        self._reconcile_sessions()
        self.interactive()
        with self._lock:
            sessions = [session.as_dict() for session in self._sessions.values()]
            analyses = [handle.as_dict() for handle in self._analyses.values()]
        return [{**session, "analyses": [
            analysis for analysis in analyses if analysis["session_id"] == session["session_id"]
        ]} for session in sessions]

    def startup(self) -> dict[str, Any]:
        """Prefer an existing bridge, then restore a saved project or start empty."""
        with self._startup_lock:
            if self._startup_state is not None:
                return self._startup_snapshot()
            interactive = self.interactive()
            try:
                health = interactive.bridge.health()
            except BridgeError:
                interactive.bridge_status = "unavailable"
                interactive.ready = False
                try:
                    saved = next((path for path in reversed(self._saved_projects) if path.is_file()), None)
                    if saved is not None:
                        project = self._project_from_gpr(saved)
                        with self._lock:
                            self._projects[project.project_id] = project
                        job = self._start_saved_project(project)
                    else:
                        self._startup_state = {"state": "no_project_open", "mode": "headless"}
                        return self._startup_snapshot()
                except Exception as startup_error:
                    self._startup_state = {
                        "state": "failed",
                        "mode": "headless",
                        "error": str(startup_error),
                    }
                else:
                    self._startup_state = {
                        "state": "headless_starting",
                        "mode": "headless",
                        "empty": saved is None,
                        "import_job": job,
                    }
            else:
                interactive.bridge_status = "ready"
                interactive.ready = True
                try:
                    project_metadata = interactive.bridge.get_project()
                    gpr_value = project_metadata.get("gpr_path")
                    if isinstance(gpr_value, str) and gpr_value:
                        interactive.project = self._project_from_gpr(Path(gpr_value))
                except BridgeError:
                    pass
                programs = self._list_session_programs(interactive)
                self._startup_state = {
                    "state": "connected",
                    "mode": "interactive",
                    "session_id": interactive.session_id,
                    "bridge_health": health,
                    "analyses": [
                        {key: value for key, value in program.items() if key == "analysis_id"}
                        for program in programs if program.get("analysis_id")
                    ],
                }
            return self._startup_snapshot()

    def _start_saved_project(self, project: ProjectHandle) -> dict[str, Any]:
        job = ImportJob(str(uuid.uuid4()), Path("."), {"project_id": project.project_id, "resume": True})
        with self._lock:
            self._import_jobs[job.job_id] = job
        threading.Thread(target=self._run_import, args=(job,), daemon=True).start()
        return self.import_job(job.job_id)

    def _startup_snapshot(self) -> dict[str, Any]:
        state = dict(self._startup_state or {})
        import_job = state.get("import_job")
        if state.get("state") == "headless_starting" and isinstance(import_job, dict):
            job_id = import_job.get("job_id")
            if isinstance(job_id, str):
                try:
                    current = self.import_job(job_id)
                except MCPServerError:
                    current = None
                if current is not None:
                    state["import_job"] = current
                    if current.get("state") == "completed":
                        result = current.get("result") or {}
                        state["state"] = "headless_ready"
                        if result.get("session_id"):
                            state["session_id"] = result["session_id"]
                        if result.get("program_id"):
                            state["program_id"] = result["program_id"]
                        if result.get("analysis_id"):
                            state["analysis_id"] = result["analysis_id"]
                    elif current.get("state") == "failed":
                        state["state"] = "failed"
                        state["error"] = current.get("error")
        return state

    def create_project(self, path: str, name: str) -> ProjectHandle:
        if self._active_project_session(required=False) is not None:
            raise MCPServerError("A Ghidra project is already open", code="project_already_open")
        name = self._project_name(name)
        canonical = Path(path).expanduser().resolve(strict=False)
        if canonical.exists() and not canonical.is_dir():
            raise MCPServerError(f"project path is not a directory: {canonical}", code="invalid_argument")
        marker_paths = (canonical / f"{name}.gpr", canonical / f"{name}.rep")
        if any(marker.exists() for marker in marker_paths):
            raise MCPServerError(
                f"Ghidra project already exists at {canonical} with name {name}; refusing to overwrite it",
                code="project_exists",
            )
        try:
            canonical.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise MCPServerError(f"Could not create project directory {canonical}: {error}", code="project_error") from error
        project = ProjectHandle(str((canonical / f"{name}.gpr").resolve()), canonical, name)
        with self._lock:
            self._projects[project.project_id] = project
        return project

    def open_project(self, path: str, name: str) -> ProjectHandle:
        """Register an existing Ghidra project without modifying it."""
        name = self._project_name(name)
        canonical = Path(path).expanduser().resolve(strict=False)
        if not canonical.is_dir():
            raise MCPServerError(f"Project path is not a directory: {canonical}", code="project_not_found")
        gpr = canonical / f"{name}.gpr"
        rep = canonical / f"{name}.rep"
        if not gpr.is_file() or not rep.is_dir():
            raise MCPServerError(
                f"Existing Ghidra project markers were not found at {canonical} for {name}",
                code="project_not_found",
            )
        current = self._active_project_session(required=False)
        if current is not None:
            if current.project and current.project.project_id == str(gpr.resolve()):
                return current.project
            raise MCPServerError("A different Ghidra project is already open", code="project_already_open")
        with self._lock:
            existing = next(
                (project for project in self._projects.values()
                 if project.path == canonical and project.name == name),
                None,
            )
            if existing is not None:
                self._persist_project(existing)
                return existing
            project = ProjectHandle(str(gpr.resolve()), canonical, name)
            self._projects[project.project_id] = project
        self._persist_project(project)
        return project

    def open_project_backend(self, project: ProjectHandle) -> dict[str, Any]:
        current = self._active_project_session(required=False)
        if current is not None:
            if current.project and current.project.project_id == project.project_id:
                return self.list_open_project()
            raise MCPServerError("A different Ghidra project is already open", code="project_already_open")
        result = self._launch_headless({}, None, project)
        self._startup_state = {
            "state": "headless_ready",
            "mode": "headless",
            "empty": not bool(result.get("programs")),
            "session_id": result.get("session_id"),
        }
        return self.list_open_project()

    @staticmethod
    def _project_name(name: str) -> str:
        name = name.strip() if isinstance(name, str) else name
        if not isinstance(name, str) or not name or name in {".", ".."} or Path(name).name != name or "\\" in name:
            raise MCPServerError("project name must be a single non-empty path component", code="invalid_argument")
        return name

    def project(self, project_id: str) -> ProjectHandle:
        with self._lock:
            project = self._projects.get(project_id)
        if project is None:
            raise MCPServerError(f"Unknown project handle: {project_id}", code="project_not_found")
        return project

    def close_project(self) -> dict[str, Any]:
        session = self._active_project_session()
        project = session.project
        if project is None:
            raise MCPServerError("No Ghidra project is open", code="no_project_open")
        with self._lock:
            active_imports = [
                job for job in self._import_jobs.values()
                if job.state in {"queued", "running"}
                and job.arguments.get("closing") is not True
            ]
            sessions = [
                candidate for candidate in self._sessions.values()
                if candidate.session_id == session.session_id
            ]
        if active_imports:
            raise MCPServerError(
                f"Project has {len(active_imports)} active import job(s)",
                code="project_busy",
            )
        save_results = self._save_session(session)
        for candidate in sessions:
            candidate.closed = True
            self._terminate(candidate.process)
            self._remove_lease(candidate)
            with self._lock:
                self._sessions.pop(candidate.session_id, None)
                self._remove_analysis_handles(candidate.session_id)
                if self._startup_state and self._startup_state.get("session_id") == candidate.session_id:
                    self._startup_state = None
        with self._lock:
            self._projects.pop(project.project_id, None)
        return {
            "project_id": project.project_id,
            "gpr_path": project.project_id,
            "path": str(project.path),
            "name": project.name,
            "closed": True,
            "managed_sessions_stopped": len(sessions),
            "programs": save_results,
        }

    def import_binary(self, arguments: dict[str, Any]) -> dict[str, Any]:
        binary_value = arguments.get("binary_path", arguments.get("binary"))
        if not isinstance(binary_value, str) or not binary_value.strip():
            raise MCPServerError("binary_path is required", code="invalid_argument")
        binary = Path(binary_value).expanduser().resolve(strict=False)
        if not binary.is_file():
            raise MCPServerError(f"Binary does not exist or is not a file: {binary}", code="binary_not_found")
        session = self._active_project_session()
        if session.project is None:
            raise MCPServerError("No Ghidra project is open", code="no_project_open")
        requested_path = arguments.get("project_path")
        requested_name = arguments.get("project_name")
        if requested_path and Path(str(requested_path)).expanduser().resolve() != session.project.path:
            raise MCPServerError("Import target is not the open project", code="project_mismatch")
        if requested_name and str(requested_name) != session.project.name:
            raise MCPServerError("Import target is not the open project", code="project_mismatch")
        job = ImportJob(str(uuid.uuid4()), binary, dict(arguments))
        with self._lock:
            self._import_jobs[job.job_id] = job
        threading.Thread(target=self._run_import, args=(job,), daemon=True).start()
        return self.import_job(job.job_id)

    def start_empty(self) -> dict[str, Any]:
        """Start a managed backend with no loaded Program."""
        project = self._temporary_project()
        job = ImportJob(
            str(uuid.uuid4()), Path("."), {"empty": True, "project_id": project.project_id}
        )
        with self._lock:
            self._import_jobs[job.job_id] = job
        threading.Thread(target=self._run_import, args=(job,), daemon=True).start()
        return self.import_job(job.job_id)

    def _run_import(self, job: ImportJob) -> None:
        job.state = "running"
        self._update_import_job(job, "STARTING_GHIDRA", "Starting Ghidra import")
        progress = lambda phase, message, **kwargs: self._update_import_job(job, phase, message, **kwargs)
        try:
            arguments = job.arguments
            if arguments.get("empty"):
                job.result = self._start_empty_headless(arguments, progress=progress)
            elif arguments.get("resume"):
                project = self.project(_required_string(arguments, "project_id"))
                job.result = self._launch_headless(arguments, None, project, progress=progress)
            else:
                session = self._active_project_session()
                progress("IMPORTING", "Importing into the open Ghidra project", backend_alive=True)
                job.result = self._import_into_session(session, job.binary, arguments, progress)
            job.progress = structured_progress(
                {"phase": "COMPLETED", "progress": 100, "message": "Import complete"}, "completed"
            )
            job.phase = "COMPLETED"
            job.message = "Import complete"
            job.last_update = time.time()
            job.backend_alive = True
            job.state = "completed"
        except Exception as error:
            job.error = str(error)
            job.progress = structured_progress({"phase": "FAILED", "message": str(error)}, "failed")
            job.phase = "FAILED"
            job.message = str(error)
            job.last_update = time.time()
            job.backend_alive = False
            job.state = "failed"

    @staticmethod
    def _update_import_job(job: ImportJob, phase: str, message: str, *, backend_alive: bool | None = None) -> None:
        job.phase = phase
        job.message = message
        job.last_update = time.time()
        if backend_alive is not None:
            job.backend_alive = backend_alive
        job.progress = structured_progress(
            {"phase": phase, "message": message}, job.state
        )

    def import_job(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._import_jobs.get(job_id)
        if job is None:
            raise MCPServerError(f"Unknown import job: {job_id}", code="import_job_not_found")
        result: dict[str, Any] = {
            "job_id": job.job_id,
            "state": job.state,
            "progress": structured_progress(job.progress, job.state),
            "phase": job.phase,
            "message": job.message,
            "last_update": job.last_update,
            "heartbeat_age_seconds": max(0.0, time.time() - job.last_update),
            "backend_alive": job.backend_alive,
        }
        if job.result is not None:
            result["result"] = job.result
        if job.error is not None:
            result["error"] = job.error
        return result

    def _import_interactive(self, session: AnalysisSession, binary: Path) -> dict[str, Any]:
        result = session.bridge.import_program(str(binary))
        programs = result.get("programs", [])
        primary_id = result.get("primary_program_id")
        if not isinstance(primary_id, str) or not primary_id:
            raise MCPServerError("Interactive import returned no primary Program", code="interactive_import_failed")
        analysis = self._register_analysis(session, primary_id)
        return {
            "analysis_id": analysis.analysis_id,
            "session_id": session.session_id,
            "binary_path": str(binary),
            "programs": programs,
            "program_id": primary_id,
            "analysis_status": self._analysis_status(session, primary_id),
        }

    def _import_into_session(
        self,
        session: AnalysisSession,
        binary: Path,
        arguments: dict[str, Any],
        progress: Callable[..., None],
    ) -> dict[str, Any]:
        result = session.bridge.import_program(str(binary))
        primary_id = result.get("primary_program_id")
        if not isinstance(primary_id, str) or not primary_id:
            raise MCPServerError("Import returned no primary Program", code="import_failed")
        progress("RECOVERING_RTTI", "Waiting for Ghidra analysis and RTTI recovery", backend_alive=True)
        self._wait_rtti_recovery(session, primary_id, float(arguments.get(
            "startup_timeout_seconds", os.getenv("AETHER_MCP_STARTUP_TIMEOUT_SEC", "300")
        )), progress=progress)
        analysis = self._register_analysis(session, primary_id)
        programs = self._list_session_programs(session)
        selected = next((item for item in programs if item.get("program_id") == primary_id), {})
        return {
            "analysis_id": analysis.analysis_id,
            "session_id": session.session_id,
            "project": session.project.as_dict() if session.project else None,
            "binary_path": str(binary),
            "programs": programs,
            "program_id": primary_id,
            "program": selected,
            "analysis_status": self._analysis_status(session, primary_id),
        }

    def _project_for_import(self, arguments: dict[str, Any]) -> ProjectHandle:
        project_id = arguments.get("project_id")
        if project_id:
            return self.project(str(project_id))
        project_value = arguments.get("project")
        if isinstance(project_value, dict) and project_value.get("project_id"):
            return self.project(str(project_value["project_id"]))
        path = arguments.get("project_path", arguments.get("path"))
        name = arguments.get("project_name", arguments.get("name"))
        if not isinstance(path, str) or not path.strip() or not isinstance(name, str) or not name.strip():
            return self._temporary_project()
        canonical = Path(path).expanduser().resolve(strict=False)
        if not canonical.is_dir():
            raise MCPServerError(f"Project path is not a directory: {canonical}", code="project_not_found")
        project = ProjectHandle(
            str((canonical / f"{name.strip()}.gpr").resolve()), canonical, name.strip()
        )
        with self._lock:
            self._projects[project.project_id] = project
        return project

    def _temporary_project(self) -> ProjectHandle:
        root = Path(os.getenv("AETHER_MCP_PROJECT_DIR", "/tmp/aether-ghidra-projects")).expanduser().resolve()
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise MCPServerError(f"Could not create temporary project directory {root}: {error}", code="project_error") from error
        name = f"import-{uuid.uuid4().hex[:12]}"
        project = ProjectHandle(str((root / f"{name}.gpr").resolve()), root, name)
        with self._lock:
            self._projects[project.project_id] = project
        return project

    def _import_headless(self, arguments: dict[str, Any], binary: Path, *, progress: Callable[..., None] | None = None) -> dict[str, Any]:
        project = self._project_for_import(arguments)
        return self._launch_headless(arguments, binary, project, progress=progress)

    def _start_empty_headless(self, arguments: dict[str, Any], *, progress: Callable[..., None] | None = None) -> dict[str, Any]:
        project = self.project(_required_string(arguments, "project_id"))
        result = self._launch_headless(arguments, None, project, progress=progress)
        result["empty"] = True
        return result

    def _launch_headless(
        self,
        arguments: dict[str, Any],
        binary: Path | None,
        project: ProjectHandle,
        progress: Callable[..., None] | None = None,
    ) -> dict[str, Any]:
        if progress:
            progress("STARTING_GHIDRA", "Launching headless Ghidra")
        bridge_port = int(arguments.get("bridge_port") or self.port_factory())
        agent_port = int(arguments.get("agent_port") or self.port_factory())
        for _ in range(10):
            if bridge_port != agent_port:
                break
            agent_port = self.port_factory()
        if bridge_port == agent_port:
            raise MCPServerError("Could not allocate distinct bridge and agent ports", code="port_allocation_failed")
        bridge_url = f"http://127.0.0.1:{bridge_port}"
        agent_url = f"http://127.0.0.1:{agent_port}"
        session = self._new_session("headless", bridge_url, agent_url)
        session.project = project
        session.bridge_port = bridge_port
        session.agent_port = agent_port
        command = self._headless_command(project, binary)
        environment = os.environ.copy()
        environment.update({
            "AETHER_GHIDRA_PORT": str(bridge_port),
            "AETHER_AGENT_URL": agent_url,
            "AETHER_AGENT_HOST": "127.0.0.1",
            "AETHER_AGENT_PORT": str(agent_port),
            "AETHER_AGENT_DIR": os.getenv("AETHER_AGENT_DIR", str(self._repository_root() / "agent")),
            "AETHER_AGENT_PYTHON": os.getenv("AETHER_AGENT_PYTHON", sys.executable),
            "PYTHONUNBUFFERED": "1",
        })
        self._diagnostic(f"starting headless analysis: {' '.join(command)}")
        try:
            session.process = self.popen_factory(
                command,
                cwd=str(self._repository_root()),
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                **({"start_new_session": True} if os.name != "nt" else {
                    "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                }),
            )
            self._write_lease(session)
            self._drain_process_output(session)
            if progress:
                progress("WAITING_FOR_BRIDGE", "Waiting for Ghidra bridge and agent", backend_alive=True)
            self._wait_ready(session, float(arguments.get(
                "startup_timeout_seconds",
                os.getenv("AETHER_MCP_STARTUP_TIMEOUT_SEC", "300"),
            )), require_program=binary is not None, progress=progress)
            programs = session.bridge.list_programs()
            if binary is not None and not programs:
                raise MCPServerError("Headless Ghidra became ready but exposed no Programs", code="headless_no_program")
            if binary is None:
                with self._lock:
                    self._sessions[session.session_id] = session
                self._persist_project(project)
                return {
                    "session_id": session.session_id,
                    "project": project.as_dict(),
                    "programs": self._list_session_programs(session),
                    "program_id": None,
                    "analysis_status": {"state": "no_program_loaded", "is_analyzing": False},
                }
            program_id = arguments.get("program_id")
            if program_id is not None:
                selected = next((item for item in programs if str(item.get("program_id")) == str(program_id)), None)
                if selected is None:
                    raise MCPServerError(f"Program is not available in the headless session: {program_id}", code="program_not_found")
            else:
                selected = programs[0]
            if progress:
                progress("RECOVERING_RTTI", "Waiting for RTTI recovery", backend_alive=True)
            self._wait_rtti_recovery(session, str(selected["program_id"]), float(arguments.get(
                "startup_timeout_seconds",
                os.getenv("AETHER_MCP_STARTUP_TIMEOUT_SEC", "300"),
            )), progress=progress)
            status = self._analysis_status(session, str(selected["program_id"]))
            with self._lock:
                self._sessions[session.session_id] = session
            analysis = self._register_analysis(session, str(selected["program_id"]))
            self._persist_project(project)
            return {
                "analysis_id": analysis.analysis_id,
                "session_id": session.session_id,
                "project": project.as_dict(),
                "binary_path": str(binary),
                "programs": programs,
                "program_id": selected.get("program_id"),
                "analysis_status": status,
            }
        except Exception:
            self._terminate(session.process)
            self._remove_lease(session)
            raise

    def _wait_rtti_recovery(self, session: AnalysisSession, program_id: str, timeout: float, *, progress: Callable[..., None] | None = None) -> None:
        """Wait for import-time class recovery without blocking bridge startup."""
        deadline = time.monotonic() + max(0.1, timeout)
        compatibility_deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if progress:
                progress("RECOVERING_RTTI", "Waiting for RTTI recovery", backend_alive=True)
            if session.process is not None and session.process.poll() is not None:
                raise MCPServerError(self._session_exit_message(session), code="headless_exited")
            try:
                status = session.bridge.invoke(program_id, "get_analysis_status", {})
            except BridgeError as error:
                if error.code == "capability_unsupported":
                    return
                self.sleep(0.5)
                continue
            recovery_state = status.get("rtti_recovery_state")
            if status.get("is_analyzing"):
                self.sleep(0.5)
                continue
            if recovery_state == "failed":
                raise MCPServerError(
                    f"RTTI recovery failed for Program {program_id}",
                    code="rtti_recovery_failed",
                )
            if recovery_state == "completed":
                if status.get("analyzed") is False:
                    raise MCPServerError(
                        f"Ghidra auto-analysis did not complete for Program {program_id}",
                        code="analysis_incomplete",
                    )
                return
            if recovery_state is None and time.monotonic() >= compatibility_deadline:
                return
            self.sleep(0.5)
        raise MCPServerError(
            f"Timed out waiting for RTTI recovery for Program {program_id}",
            code="rtti_recovery_timeout",
        )

    @staticmethod
    def _analysis_status(session: AnalysisSession, program_id: str) -> dict[str, Any]:
        try:
            return session.bridge.invoke(program_id, "get_analysis_status", {})
        except BridgeError as error:
            # Older installed extension classes predate this read-only capability.
            # The headless script runs only after Auto Analyze, so readiness gives
            # us a safe compatibility status for those installations.
            if error.code == "capability_unsupported" and session.mode == "headless":
                return {
                    "program_id": program_id,
                    "state": "completed",
                    "is_analyzing": False,
                    "analysis_job_id": f"analysis-job-{program_id}",
                    "inferred": True,
                }
            raise

    def _headless_command(self, project: ProjectHandle, binary: Path | None) -> list[str]:
        install = Path(os.getenv("GHIDRA_INSTALL_DIR", "/opt/ghidra_12.1.2_PUBLIC")).expanduser().resolve()
        analyze_headless = install / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
        user_extension_paths = sorted(Path.home().glob(
            ".config/ghidra/ghidra_*/Extensions/AETHER_GHIDRA-main/ghidra_scripts"
        ))
        user_extension_paths += sorted(Path.home().glob(
            ".ghidra/.ghidra_*/Extensions/AETHER_GHIDRA-main/ghidra_scripts"
        ))
        system_extension_path = Path(os.getenv(
            "GHIDRA_INSTALL_DIR", "/opt/ghidra"
        )).expanduser() / "Extensions/AETHER_GHIDRA-main/ghidra_scripts"
        installed_script_path = user_extension_paths[0] if user_extension_paths else system_extension_path
        default_script_path = installed_script_path if installed_script_path.is_dir() else self._repository_root() / "ghidra_scripts"
        script_path = Path(os.getenv(
            "AETHER_HEADLESS_SCRIPT_DIR",
            str(default_script_path),
        )).expanduser().resolve()
        script = script_path / "AetherHeadlessScript.java"
        if not analyze_headless.is_file():
            raise MCPServerError(f"Ghidra analyzeHeadless was not found: {analyze_headless}", code="ghidra_not_found")
        if not script.is_file():
            raise MCPServerError(f"AetherHeadlessScript.java was not found: {script}", code="headless_script_not_found")
        try:
            script.touch()
            recovery_script = script_path / "AetherRecoverClassesAndAnalyze.java"
            if recovery_script.is_file():
                recovery_script.touch()
        except OSError as error:
            raise MCPServerError(f"Could not refresh installed headless scripts: {error}", code="headless_script_error") from error
        command = [
            str(analyze_headless),
            str(project.path),
            project.name,
            "-scriptPath",
            str(script_path),
            "-postScript",
            script.name,
        ]
        if binary is not None:
            command[3:3] = ["-import", str(binary), "-noanalysis"]
        return command

    def _wait_ready(self, session: AnalysisSession, timeout: float, *, require_program: bool = True, progress: Callable[..., None] | None = None) -> None:
        deadline = time.monotonic() + max(0.1, timeout)
        last_error = "services did not become ready"
        while time.monotonic() < deadline:
            if progress:
                progress("WAITING_FOR_BRIDGE", "Waiting for Ghidra bridge and agent", backend_alive=session.process is not None and session.process.poll() is None)
            if session.process is not None and session.process.poll() is not None:
                raise MCPServerError(self._session_exit_message(session), code="headless_exited")
            script_error = next(
                (line for line in session.output_tail
                 if "SCRIPT ERROR" in line or "GhidraScriptLoadException" in line),
                None,
            )
            if script_error is not None:
                raise MCPServerError(
                    f"Headless Ghidra could not load the AETHER script: {script_error}",
                    code="headless_script_failed",
                )
            try:
                bridge_health = session.bridge.health()
                agent_health = session.agent.health()
                if _health_ok(bridge_health) and _health_ok(agent_health, "aether-ghidra-agent"):
                    programs = session.bridge.list_programs()
                    if programs or not require_program:
                        session.bridge_status = "ready"
                        session.ready = True
                        return
                    last_error = "AETHER bridge is ready but no Program is registered yet"
                else:
                    last_error = "AETHER bridge or agent reported an incompatible protocol"
            except (BridgeError, AgentAPIError, OSError) as error:
                last_error = str(error)
            self.sleep(0.1)
        raise MCPServerError(f"Timed out waiting for headless AETHER services: {last_error}", code="headless_timeout")

    def close(self, session_id: str) -> dict[str, Any]:
        session = self.get(session_id)
        if session.mode != "headless":
            raise MCPServerError("The interactive session is owned by Ghidra and cannot be closed by MCP", code="interactive_session")
        session.closed = True
        self._pause_index_jobs(session)
        self._save_session(session)
        self._terminate(session.process)
        with self._lock:
            self._sessions.pop(session_id, None)
            self._remove_analysis_handles(session_id)
            if self._startup_state and self._startup_state.get("session_id") == session_id:
                self._startup_state = None
        self._remove_lease(session)
        return {"session_id": session_id, "closed": True, "managed_process_stopped": session.managed}

    def close_all(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
            self._analyses.clear()
            self._analysis_keys.clear()
        for session in sessions:
            session.closed = True
            self._pause_index_jobs(session)
            self._save_session(session)
            self._terminate(session.process)
            self._remove_lease(session)
        self._startup_state = None

    def _pause_index_jobs(self, session: AnalysisSession) -> None:
        """Checkpoint active headless indexes before stopping their agent."""
        if not session.managed:
            return
        try:
            programs = session.bridge.list_programs()
        except Exception as error:
            self._diagnostic(f"could not list programs before shutdown: {error}")
            return
        for program in programs:
            if program.get("state", "open") != "open":
                continue
            program_id = str(program.get("program_id", ""))
            if not program_id:
                continue
            try:
                session.agent.request("POST", "/v1/index-jobs/pause", {"program_id": program_id})
            except (AgentAPIError, OSError) as error:
                self._diagnostic(f"could not pause index for {program_id}: {error}")

    def _write_lease(self, session: AnalysisSession) -> None:
        if session.process is None:
            return
        try:
            self._session_lease_dir.mkdir(parents=True, exist_ok=True)
            lease = self._session_lease_dir / f"{session.session_id}.json"
            payload = {
                "owner_pid": os.getpid(),
                "process_pid": getattr(session.process, "pid", None),
                "project": str(session.project.path / f"{session.project.name}.gpr") if session.project else None,
            }
            lease.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            session.lease_path = lease
        except OSError as error:
            self._diagnostic(f"could not write session lease: {error}")

    @staticmethod
    def _remove_lease(session: AnalysisSession) -> None:
        if session.lease_path is not None:
            try:
                session.lease_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _reap_orphan_leases(self) -> None:
        try:
            leases = list(self._session_lease_dir.glob("*.json"))
        except OSError:
            return
        for lease in leases:
            try:
                payload = json.loads(lease.read_text(encoding="utf-8"))
                owner_pid = int(payload["owner_pid"])
                process_pid = int(payload["process_pid"])
                os.kill(owner_pid, 0)
            except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError):
                owner_alive = False
            else:
                owner_alive = True
            if owner_alive:
                continue
            try:
                if os.name != "nt":
                    os.killpg(process_pid, signal.SIGTERM)
                else:
                    os.kill(process_pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                lease.unlink(missing_ok=True)
            except OSError:
                pass

    def _save_session(self, session: AnalysisSession) -> list[dict[str, Any]]:
        """Flush every Program before a managed headless process is stopped."""
        results = []
        for program in session.bridge.list_programs():
            program_id = program.get("program_id")
            if program_id and program.get("state", "open") == "open":
                result = session.bridge.invoke(str(program_id), "save_program", {})
                results.append({"program_id": str(program_id), **result})
        return results

    def _remove_analysis_handles(self, session_id: str) -> None:
        for analysis_id, handle in list(self._analyses.items()):
            if handle.session_id == session_id:
                self._analyses.pop(analysis_id, None)
                self._analysis_keys.pop((handle.session_id, handle.program_id), None)

    def _terminate(self, process: Any) -> None:
        if process is None or process.poll() is not None:
            return
        try:
            pid = getattr(process, "pid", None)
            if os.name != "nt" and pid:
                os.killpg(pid, signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                if os.name != "nt" and pid:
                    os.killpg(pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass

    def _drain_process_output(self, session: AnalysisSession) -> None:
        process = session.process
        stream = getattr(process, "stdout", None)
        if stream is None:
            return

        def drain() -> None:
            try:
                for line in stream:
                    text = line.rstrip()
                    session.output_tail.append(text)
                    self._diagnostic(f"[ghidra-headless] {text}")
            except (OSError, ValueError):
                return

        threading.Thread(target=drain, name="aether-headless-output", daemon=True).start()

    def _diagnostic(self, message: str) -> None:
        print(message, file=self.stderr, flush=True)

    @staticmethod
    def _repository_root() -> Path:
        return Path(__file__).resolve().parents[3]


AnalysisSessionManager = AnalysisBroker


ADDRESS_SCHEMA = {
    "type": "object",
    "properties": {"space": {"type": "string"}, "offset": {"type": "string"}},
    "required": ["space", "offset"],
    "additionalProperties": False,
}
CLASS_REF_SCHEMA = {
    "type": "object",
    "properties": {"class_id": {"type": "string"}, "structure_path": {"type": "string"}},
    "additionalProperties": False,
}
TYPE_SYNTAX_DESCRIPTION = (
    "Ghidra type name ('int', 'double', 'undefined4'), pointer ('void *', 'int **', 'Board *'),"
    " or full datatype path ('/ClassDataTypes/Board/Board'). A leading slash before a bare"
    " name ('/undefined4') is also accepted."
)
FIELD_SCHEMA = {
    "type": "object",
    "properties": {
        "offset": {"type": "integer", "description": "Byte offset within the structure."},
        "name": {"type": "string"},
        "data_type_path": {"type": "string", "description": TYPE_SYNTAX_DESCRIPTION},
        "length": {"type": "integer"},
        "comment": {"type": "string"},
    },
    "required": ["offset", "data_type_path"],
    "additionalProperties": False,
}
UPDATE_FIELD_SCHEMA = {
    "type": "object",
    "properties": {
        "offset": {"type": "integer", "description": "Byte offset within the structure."},
        "name": {"type": "string"},
        "data_type_path": {"type": "string", "description": TYPE_SYNTAX_DESCRIPTION},
        "length": {"type": "integer"},
        "comment": {"type": "string"},
    },
    "required": ["offset"],
    "additionalProperties": False,
}
PARAMETER_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"}, "data_type_path": {"type": "string"},
        "storage": {"type": "object"},
    },
    "required": ["name", "data_type_path"],
    "additionalProperties": False,
}


def _program_schema(properties: dict[str, Any], required: Iterable[str] = ()) -> dict[str, Any]:
    all_properties = {
        "analysis_id": {"type": "string"},
        # Retained for clients migrating from the session/program API.
        "session_id": {"type": "string"},
        "program_id": {"type": "string"},
        **properties,
    }
    return {
        "type": "object",
        "properties": all_properties,
        "required": list(required),
        "anyOf": [
            {"required": ["program_id"]},
            {"required": ["analysis_id"]},
            {"required": ["session_id", "program_id"]},
        ],
        "additionalProperties": False,
    }


def _tool(name: str, description: str, schema: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "description": description, "inputSchema": schema}


TOOLS = [
    _tool("list_analysis_sessions", "List interactive and externally managed headless analysis sessions.", {"type": "object", "properties": {}, "additionalProperties": False}),
    _tool("list_open_project", "Return the one open Ghidra project and every Program stored in it.", {"type": "object", "properties": {}, "additionalProperties": False}),
    _tool("list_programs", "List every Program stored in the open project, including open and closed state.", {"type": "object", "properties": {}, "additionalProperties": False}),
    _tool("create_project", "Create a new, non-overwriting Ghidra project directory and return its handle.", {"type": "object", "properties": {"path": {"type": "string"}, "name": {"type": "string"}, "project_path": {"type": "string"}, "project_name": {"type": "string"}}, "anyOf": [{"required": ["path", "name"]}, {"required": ["project_path", "project_name"]}], "additionalProperties": False}),
    _tool("open_project", "Open an existing Ghidra project.", {"type": "object", "properties": {"gpr_path": {"type": "string"}, "path": {"type": "string"}, "name": {"type": "string"}, "project_path": {"type": "string"}, "project_name": {"type": "string"}}, "anyOf": [{"required": ["gpr_path"]}, {"required": ["path", "name"]}, {"required": ["project_path", "project_name"]}], "additionalProperties": False}),
    _tool("close_project", "Save all open Programs and close the one open Ghidra project.", {"type": "object", "properties": {}, "additionalProperties": False}),
    _tool("open_program", "Open one stored Program by its Ghidra project-domain path.", {"type": "object", "properties": {"program_id": {"type": "string"}}, "required": ["program_id"], "additionalProperties": False}),
    _tool("close_program", "Save and close one Program while keeping its project open.", {"type": "object", "properties": {"program_id": {"type": "string"}}, "required": ["program_id"], "additionalProperties": False}),
    _tool("import_binary", "Import a binary using the available AETHER analysis session. Interactive sessions use the active Ghidra project; otherwise a managed headless project is used.", {"type": "object", "properties": {
        "binary_path": {"type": "string"}, "project_id": {"type": "string"},
        "project_path": {"type": "string"}, "project_name": {"type": "string"}, "session_id": {"type": "string"},
        "startup_timeout_seconds": {"type": "number", "minimum": 1},
        "bridge_port": {"type": "integer", "minimum": 1}, "agent_port": {"type": "integer", "minimum": 1},
    }, "required": ["binary_path"], "additionalProperties": False}),
    _tool("get_import_job", "Get import state and progress, including the resulting analysis session and Program when complete.", {"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"], "additionalProperties": False}),
    _tool("close_analysis_session", "Close the managed backend for an opaque analysis handle.", {"type": "object", "properties": {"analysis_id": {"type": "string"}, "session_id": {"type": "string"}}, "anyOf": [{"required": ["analysis_id"]}, {"required": ["session_id"]}], "additionalProperties": False}),
    _tool("save_program", "Explicitly save one exact Program.", _program_schema({})),
    _tool("get_program_metadata", "Return metadata for an exact Program.", _program_schema({})),
    _tool("get_analysis_status", "Return Ghidra auto-analysis status for an exact Program.", _program_schema({})),
    _tool("list_functions", "List one compact page of functions in an exact Program (default limit 50). Each item contains only address and definition; use get_function for full metadata or set include_call_relationships to true for rich call-graph indexing data.", _program_schema({"pattern": {"type": "string"}, "name": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}, "include_call_relationships": {"type": "boolean"}})),
    _tool("get_function", "Retrieve one function by structured address, including address-aware pseudocode and resolved calls.", _program_schema({"address": ADDRESS_SCHEMA}, ["address"])),
    _tool("resolve_pseudocode_call", "Resolve a call at an exact caller and call-site address.", _program_schema({"caller_address": ADDRESS_SCHEMA, "call_site": ADDRESS_SCHEMA, "display_name": {"type": "string"}}, ["caller_address", "call_site"])),
    _tool("get_data_at_address", "Inspect bytes and disassembly at an exact address.", _program_schema({"location": ADDRESS_SCHEMA, "count": {"type": "integer"}}, ["location"])),
    _tool("get_xrefs_to", "List cross-references to an exact address.", _program_schema({"location": ADDRESS_SCHEMA}, ["location"])),
    _tool("list_struct", "List native and class-backed structures in an exact Program.", _program_schema({"pattern": {"type": "string"}, "kind": {"type": "string", "enum": ["struct", "class"]}, "grouped": {"type": "boolean"}, "limit": {"type": "integer"}})),
    _tool("get_struct", "Retrieve one structure by its exact full Ghidra datatype path.", _program_schema({"structure_path": {"type": "string"}}, ["structure_path"])),
    _tool("start_function_index", "Start a resumable whole-program function index after auto-analysis completes.", _program_schema({"resume": {"type": "boolean"}, "reindex": {"type": "boolean"}, "allow_partial_analysis": {"type": "boolean"}})),
    _tool("get_function_index_job", "Get state and structured progress for an indexing job.", _program_schema({"job_id": {"type": "string"}}, ["job_id"])),
    _tool("cancel_function_index", "Cancel an indexing job.", _program_schema({"job_id": {"type": "string"}}, ["job_id"])),
    _tool("get_function_index_stats", "Return persisted function index statistics.", _program_schema({})),
    _tool("list_function_index_entries", "List a page of persisted function index entries.", _program_schema({"offset": {"type": "integer"}, "limit": {"type": "integer"}})),
    _tool("search_function_index", "Search the persisted function index.", _program_schema({"query": {"type": "string"}}, ["query"])),
    _tool("rename_function", "Rename the exact function identified by address. A name containing '::' is split on the last '::': the prefix becomes a hierarchically resolved-or-created namespace path and the suffix becomes the function name (e.g. 'Sexy::Fish::update' places update in namespace Sexy::Fish). A plain name keeps the current namespace.", _program_schema({"address": ADDRESS_SCHEMA, "name": {"type": "string"}}, ["address", "name"])),
    _tool("rename_variable", "Rename a local or parameter variable in the exact function address.", _program_schema({"address": ADDRESS_SCHEMA, "variable_name": {"type": "string"}, "name": {"type": "string"}}, ["address", "variable_name", "name"])),
    _tool("retype_variable", "Change a local or parameter variable data type for the exact function address.", _program_schema({"address": ADDRESS_SCHEMA, "variable_name": {"type": "string"}, "data_type_path": {"type": "string"}}, ["address", "variable_name", "data_type_path"])),
    _tool("update_function_definition", "Replace the exact function return type, ordered parameters, and varargs setting by address.", _program_schema({"address": ADDRESS_SCHEMA, "return_type": {"type": "string"}, "parameters": {"type": "array", "items": PARAMETER_SCHEMA}, "varargs": {"type": "boolean"}}, ["address", "return_type", "parameters"])),
    _tool("set_function_comment", "Set or clear the exact function comment by address.", _program_schema({"address": ADDRESS_SCHEMA, "comment": {"type": "string"}}, ["address", "comment"])),
    _tool("set_code_unit_comment", "Set or clear a comment on the exact code unit at an address.", _program_schema({"location": ADDRESS_SCHEMA, "comment_kind": {"type": "string", "enum": ["eol", "pre", "post", "plate", "repeatable"]}, "comment": {"type": "string"}}, ["location", "comment_kind", "comment"])),
    _tool("apply_annotation_batch", "Apply multiple function, variable, definition, and comment edits atomically.", _program_schema({"operations": {"type": "array", "items": {"type": "object"}}}, ["operations"])),
    _tool("create_struct", "Create a native Ghidra structure.", _program_schema({"name": {"type": "string"}, "category": {"type": "string"}, "size": {"type": "integer"}, "fields": {"type": "array", "items": FIELD_SCHEMA}}, ["name"])),
    _tool("add_fields", "Insert fields at byte offsets; fields at or after each offset shift up and the structure grows by the inserted length. Batch entries are applied in descending offset order so all offsets refer to the original layout. Offsets must land on field boundaries, not inside an existing field.", _program_schema({"structure_path": {"type": "string"}, "fields": {"type": "array", "items": FIELD_SCHEMA}}, ["structure_path", "fields"])),
    _tool("update_fields", "Update fields in place without changing the structure size. An offset holding a defined field is replaced in place; an offset inside a field is rejected; an offset in a gap defines a new field there, replacing any field it overlaps (reported under 'replaced'). Never grows or shrinks the structure.", _program_schema({"structure_path": {"type": "string"}, "fields": {"type": "array", "items": UPDATE_FIELD_SCHEMA}}, ["structure_path", "fields"])),
    _tool("remove_fields", "Remove fields by byte offset (default) or by component ordinal with by_ordinal=true. Following fields shift down and the structure shrinks by each removed field's length.", _program_schema({"structure_path": {"type": "string"}, "offsets": {"type": "array", "items": {"type": "integer"}}, "by_ordinal": {"type": "boolean"}, "fields": {"type": "array", "items": UPDATE_FIELD_SCHEMA}}, ["structure_path"])),
    _tool("resize_struct", "Resize an exact native Ghidra structure. Shrinking is rejected if a defined field would be cut off.", _program_schema({"structure_path": {"type": "string"}, "size": {"type": "integer"}}, ["structure_path", "size"])),
    _tool("create_class", "Create a class model and optional backing native structure.", _program_schema({"name": {"type": "string"}, "structure_path": {"type": "string"}, "category": {"type": "string"}, "size": {"type": "integer"}, "fields": {"type": "array", "items": FIELD_SCHEMA}, "bases": {"type": "array", "items": {"type": "object"}}, "vtables": {"type": "array", "items": {"type": "object"}}, "methods": {"type": "array", "items": {"type": "object"}}, "rtti": {"type": "object"}}, ["name"])),
    _tool("update_class", "Update an existing class model selected by class_ref or structure_path.", _program_schema({"class_ref": CLASS_REF_SCHEMA, "structure_path": {"type": "string"}, "bases": {"type": "array", "items": {"type": "object"}}, "vtables": {"type": "array", "items": {"type": "object"}}, "methods": {"type": "array", "items": {"type": "object"}}, "rtti": {"type": "object"}, "confidence": {"type": "string"}})),
    _tool("delete_class", "Remove AETHER class metadata without deleting its backing structure.", _program_schema({"class_ref": CLASS_REF_SCHEMA, "structure_path": {"type": "string"}})),
]


DEFAULT_PROGRESS = {
    "phase": "PENDING",
    "state": "queued",
    "progress": 0,
    "percent": 0,
    "indexed": 0,
    "total": 0,
    "current": None,
    "message": "",
}


def structured_progress(value: Any, state: str | None = None) -> dict[str, Any]:
    """Make progress stable even before the worker has published its first update."""
    result = dict(DEFAULT_PROGRESS)
    if state:
        result["state"] = state
    if isinstance(value, dict):
        result.update(value)
        if isinstance(value.get("progress"), (int, float)):
            result["percent"] = value["progress"]
        if "indexing_progress" in value:
            result["percent"] = value["indexing_progress"]
        if "current" not in value and "current_function_name" in value:
            result["current"] = value.get("current_function_name")
        if "message" not in value and value.get("last_error"):
            result["message"] = value["last_error"]
    elif isinstance(value, (int, float)):
        result["progress"] = value
        result["percent"] = value
    return result


def validate_schema(schema: dict[str, Any], value: Any, path: str = "arguments") -> None:
    """Validate the small JSON Schema subset used by the MCP tool catalog."""
    alternatives = schema.get("anyOf")
    if alternatives:
        if schema.get("type") == "object" and not isinstance(value, dict):
            raise MCPServerError(f"{path} must be an object", code="invalid_argument")
        matched = False
        for alternative in alternatives:
            try:
                validate_schema(alternative, value, path)
                matched = True
                break
            except MCPServerError:
                continue
        if not matched:
            raise MCPServerError(f"{path} does not match the required shape", code="invalid_argument")

    expected = schema.get("type")
    if expected == "object":
        if not isinstance(value, dict):
            raise MCPServerError(f"{path} must be an object", code="invalid_argument")
        for name in schema.get("required", []):
            if name not in value:
                raise MCPServerError(f"{path}.{name} is required", code="invalid_argument")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unexpected = set(value) - set(properties)
            if unexpected:
                raise MCPServerError(f"{path} contains unsupported fields: {sorted(unexpected)}", code="invalid_argument")
        for name, item in value.items():
            if name in properties:
                validate_schema(properties[name], item, f"{path}.{name}")
    elif expected == "array":
        if not isinstance(value, list):
            raise MCPServerError(f"{path} must be an array", code="invalid_argument")
        if "items" in schema:
            for index, item in enumerate(value):
                validate_schema(schema["items"], item, f"{path}[{index}]")
    elif expected == "string":
        if not isinstance(value, str):
            raise MCPServerError(f"{path} must be a string", code="invalid_argument")
    elif expected == "boolean":
        if not isinstance(value, bool):
            raise MCPServerError(f"{path} must be a boolean", code="invalid_argument")
    elif expected == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise MCPServerError(f"{path} must be an integer", code="invalid_argument")
    elif expected == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise MCPServerError(f"{path} must be a number", code="invalid_argument")
    if "enum" in schema and value not in schema["enum"]:
        raise MCPServerError(f"{path} must be one of {schema['enum']}", code="invalid_argument")
    if "minimum" in schema and value < schema["minimum"]:
        raise MCPServerError(f"{path} must be at least {schema['minimum']}", code="invalid_argument")


class MCPApplication:
    """JSON-RPC method dispatcher, separated from stdio for unit testing."""

    def __init__(self, sessions: AnalysisBroker | None = None) -> None:
        self.sessions = sessions or AnalysisBroker()
        self.initialized = False

    def handle(self, request: Any) -> dict[str, Any] | None:
        if not isinstance(request, dict):
            return self.error(None, -32600, "Invalid Request")
        if request.get("jsonrpc") != "2.0":
            return self.error(request.get("id"), -32600, "Invalid Request")
        request_id = request.get("id")
        method = request.get("method")
        if not isinstance(method, str):
            return self.error(request_id, -32600, "Invalid Request")
        is_notification = "id" not in request
        params = request.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return None if is_notification else self.error(request_id, -32602, "params must be an object")
        try:
            if method == "notifications/initialized":
                self.initialized = True
                return None
            if method == "initialize":
                self.initialized = True
                return self.result(request_id, {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "instructions": "AETHER Ghidra tools. Open one project, list its stored Programs, then use the stable project-domain program_id for Program operations.",
                    "startup": self.sessions.startup(),
                })
            if method == "ping":
                return None if is_notification else self.result(request_id, {})
            if not self.initialized:
                return None if is_notification else self.error(request_id, -32002, "Server has not been initialized")
            if method == "tools/list":
                return None if is_notification else self.result(request_id, {"tools": TOOLS})
            if method == "tools/call":
                if is_notification:
                    return None
                return self.result(request_id, self.call_tool(params))
            return None if is_notification else self.error(request_id, -32601, f"Method not found: {method}")
        except MCPServerError as error:
            error_code = -32602 if error.code in {"invalid_argument", "unknown_tool"} else -32000
            return None if is_notification else self.error(request_id, error_code, str(error), {"code": error.code})
        except (BridgeError, AgentAPIError) as error:
            return None if is_notification else self.error(request_id, -32000, str(error), {"code": getattr(error, "code", "backend_error")})
        except (KeyError, TypeError, ValueError) as error:
            return None if is_notification else self.error(request_id, -32602, str(error))
        except Exception as error:  # pragma: no cover - defensive process boundary
            print(f"MCP request failed: {error}", file=sys.stderr, flush=True)
            return None if is_notification else self.error(request_id, -32603, "Internal error")

    @staticmethod
    def result(request_id: Any, value: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": value}

    @staticmethod
    def error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": "2.0", "id": request_id, "error": error}

    def call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        name = _required_string(params, "name")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            raise MCPServerError("tools/call arguments must be an object", code="invalid_argument")
        tool = next((tool for tool in TOOLS if tool["name"] == name), None)
        if tool is None:
            raise MCPServerError(f"Unknown tool: {name}", code="unknown_tool")
        validate_schema(tool["inputSchema"], arguments)
        try:
            value = self._dispatch(name, arguments)
        except MCPServerError as error:
            if error.code == "invalid_argument":
                raise
            return self.tool_error(str(error), error.code)
        except (BridgeError, AgentAPIError, KeyError, TypeError, ValueError) as error:
            return self.tool_error(str(error), getattr(error, "code", "backend_error"))
        return {
            "content": [{"type": "text", "text": _json_text(value)}],
            "isError": False,
        }

    @staticmethod
    def tool_error(message: str, code: str) -> dict[str, Any]:
        return {
            "content": [{"type": "text", "text": _json_text({"error": message, "code": code})}],
            "isError": True,
        }

    def _program(self, arguments: dict[str, Any]) -> tuple[AnalysisSession, str, dict[str, Any]]:
        analysis_id = arguments.get("analysis_id")
        if isinstance(analysis_id, str) and analysis_id.strip():
            handle, session = self.sessions.analysis(analysis_id.strip())
            return session, handle.program_id, {
                key: value for key, value in arguments.items() if key != "analysis_id"
            }

        program_value = arguments.get("program_id")
        if isinstance(program_value, str) and program_value.strip() and not arguments.get("session_id"):
            session = self.sessions._active_project_session()
            program_id = program_value.strip()
            available = session.bridge.list_programs()
            selected = next((item for item in available if str(item.get("program_id")) == program_id), None)
            if selected is None:
                raise MCPServerError(f"Program is not in the open project: {program_id}", code="program_not_found")
            if selected.get("state", "open") != "open":
                raise MCPServerError(f"Program is not open: {program_id}. Call open_program first", code="program_not_open")
            return session, program_id, {
                key: value for key, value in arguments.items() if key != "program_id"
            }

        # Accept the legacy pair while clients migrate to opaque analysis IDs.
        if not arguments.get("session_id") and not arguments.get("program_id"):
            raise MCPServerError(
                "No Program is loaded. Call create_project, then import_binary, before using Program tools",
                code="no_program_loaded",
            )
        session_id = _required_string(arguments, "session_id")
        program_id = _required_string(arguments, "program_id")
        session = self.sessions.get(session_id)
        return session, program_id, {
            key: value for key, value in arguments.items()
            if key not in {"session_id", "program_id"}
        }

    def _invoke(self, arguments: dict[str, Any], capability: str) -> dict[str, Any]:
        session, program_id, capability_arguments = self._program(arguments)
        return session.bridge.invoke(program_id, capability, capability_arguments)

    def _dispatch(self, name: str, arguments: dict[str, Any]) -> Any:
        if name == "list_analysis_sessions":
            startup = self.sessions.startup()
            return {"sessions": self.sessions.list_sessions(), "startup": startup}
        if name == "list_open_project":
            return self.sessions.list_open_project()
        if name == "list_programs":
            return {"programs": self.sessions.list_programs()}
        if name == "create_project":
            path = arguments.get("path", arguments.get("project_path"))
            project_name = arguments.get("name", arguments.get("project_name"))
            if not isinstance(path, str) or not path.strip():
                raise MCPServerError("path or project_path is required", code="invalid_argument")
            if not isinstance(project_name, str) or not project_name.strip():
                raise MCPServerError("name or project_name is required", code="invalid_argument")
            project = self.sessions.create_project(path, project_name)
            return self.sessions.open_project_backend(project)
        if name == "open_project":
            gpr_value = arguments.get("gpr_path")
            if isinstance(gpr_value, str) and gpr_value.strip():
                gpr = Path(gpr_value).expanduser().resolve()
                path = str(gpr.parent)
                project_name = gpr.stem
            else:
                path = arguments.get("path", arguments.get("project_path"))
                project_name = arguments.get("name", arguments.get("project_name"))
            if not isinstance(path, str) or not path.strip():
                raise MCPServerError("path or project_path is required", code="invalid_argument")
            if not isinstance(project_name, str) or not project_name.strip():
                raise MCPServerError("name or project_name is required", code="invalid_argument")
            project = self.sessions.open_project(path, project_name)
            return self.sessions.open_project_backend(project)
        if name == "close_project":
            return self.sessions.close_project()
        if name == "open_program":
            return self.sessions.open_program(_required_string(arguments, "program_id"))
        if name == "close_program":
            return self.sessions.close_program(_required_string(arguments, "program_id"))
        if name == "import_binary":
            return self.sessions.import_binary(arguments)
        if name == "get_import_job":
            return self.sessions.import_job(_required_string(arguments, "job_id"))
        if name == "close_analysis_session":
            analysis_id = arguments.get("analysis_id")
            if isinstance(analysis_id, str) and analysis_id.strip():
                handle, _ = self.sessions.analysis(analysis_id.strip())
                return self.sessions.close(handle.session_id)
            return self.sessions.close(_required_string(arguments, "session_id"))
        if name == "get_analysis_status":
            session, program_id, _ = self._program(arguments)
            return self.sessions._analysis_status(session, program_id)
        if name == "save_program":
            return self._invoke(arguments, name)
        if name == "get_function":
            arguments = dict(arguments)
            arguments["read_only"] = True
            return self._invoke(arguments, name)
        if name in {
            "get_program_metadata", "list_functions", "get_function", "resolve_pseudocode_call",
            "get_data_at_address", "get_xrefs_to", "list_struct", "get_struct",
            "save_program",
            "rename_function", "rename_variable", "retype_variable", "update_function_definition",
            "set_function_comment", "set_code_unit_comment", "apply_annotation_batch",
            "create_struct", "add_fields", "update_fields", "remove_fields", "resize_struct",
            "create_class", "update_class", "delete_class",
        }:
            return self._invoke(arguments, name)
        if name == "start_function_index":
            session, program_id, _ = self._program(arguments)
            analysis_status = self.sessions._analysis_status(session, program_id)
            if analysis_status.get("is_analyzing") and not arguments.get("allow_partial_analysis", False):
                raise MCPServerError(
                    "Function indexing is blocked until Ghidra auto-analysis completes",
                    code="analysis_in_progress",
                )
            payload = {"program_id": program_id, "resume": bool(arguments.get("resume")), "reindex": bool(arguments.get("reindex"))}
            result = session.agent.request("POST", "/v1/index-jobs", payload)
            result["progress"] = structured_progress(result.get("progress"), str(result.get("state", "queued")))
            return result
        if name == "get_function_index_job":
            session, program_id, _ = self._program(arguments)
            job_id = _required_string(arguments, "job_id")
            result = session.agent.request("GET", f"/v1/index-jobs/{quote(job_id, safe='')}")
            if str(result.get("program_id", program_id)) != program_id:
                raise MCPServerError("Index job belongs to a different Program", code="program_mismatch")
            result["progress"] = structured_progress(result.get("progress"), str(result.get("state", "queued")))
            return result
        if name == "cancel_function_index":
            session, program_id, _ = self._program(arguments)
            job_id = _required_string(arguments, "job_id")
            result = session.agent.request("POST", f"/v1/index-jobs/{quote(job_id, safe='')}/cancel", {})
            if result.get("program_id") is not None and str(result["program_id"]) != program_id:
                raise MCPServerError("Index job belongs to a different Program", code="program_mismatch")
            result["progress"] = structured_progress(result.get("progress"), str(result.get("state", "queued")))
            return result
        if name == "get_function_index_stats":
            session, program_id, _ = self._program(arguments)
            return session.agent.request("POST", "/v1/index-stats", {"program_id": program_id})
        if name == "list_function_index_entries":
            session, program_id, _ = self._program(arguments)
            return session.agent.request("POST", "/v1/index-entries", {
                "program_id": program_id,
                "offset": _optional_int(arguments, "offset", 0),
                "limit": _optional_int(arguments, "limit", 1000),
            })
        if name == "search_function_index":
            session, program_id, _ = self._program(arguments)
            return session.agent.request("POST", "/v1/index-search", {"program_id": program_id, "query": _required_string(arguments, "query")})
        raise MCPServerError(f"Unknown tool: {name}", code="unknown_tool")


def serve_stdio(
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
    *,
    application: MCPApplication | None = None,
) -> None:
    """Serve newline-delimited MCP JSON-RPC until stdin closes."""
    input_stream = input_stream or sys.stdin
    output_stream = output_stream or sys.stdout
    application = application or MCPApplication()
    try:
        for line in input_stream:
            if not line.strip():
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                response = application.error(None, -32700, "Parse error")
            else:
                response = application.handle(request)
            if response is not None:
                output_stream.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
                output_stream.flush()
    finally:
        application.sessions.close_all()


def main() -> None:
    serve_stdio()


if __name__ == "__main__":
    main()
