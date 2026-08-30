from __future__ import annotations

import threading
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from ..integrations.ghidra.bridge_client import BridgeClient
from ..integrations.ghidra.gateway import AnalysisBackend, GhidraAnalysisBackend, ProgramGateway
from ..integrations.ghidra.identity import normalize_bridge_arguments
from ..features.chat.agent import ChatbotAgent
from ..engine import AgentCancelled
from ..features.annotation.workflow import AnnotationCancelled, AnnotationWorkflow
from ..config.tool_policy import capability_enabled
from ..tools.catalog import CAPABILITY_TO_TOOL, TOOL_GROUP_BY_NAME
from ..features.indexing.indexer import FunctionIndexer, IndexCancelled
from ..features.indexing.manager import FunctionIndexManager
from ..features.indexing.search import search_index


logger = logging.getLogger(__name__)


class ToolPolicyError(PermissionError):
    """Raised when a capability is disabled by the persisted tool policy."""


@dataclass
class ProgramSession:
    program_id: str
    agent: ChatbotAgent
    lock: threading.RLock = field(default_factory=threading.RLock)


@dataclass
class AnnotationJob:
    job_id: str
    program_id: str
    state: str = "queued"
    progress: int = 0
    message: str = "Queued"
    result: dict[str, Any] | None = None
    error: str | None = None
    cancel: threading.Event = field(default_factory=threading.Event)


@dataclass
class ChatJob:
    job_id: str
    program_id: str
    agent: ChatbotAgent
    message: str
    address: dict[str, Any] | None = None
    state: str = "queued"
    progress: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    cancel: threading.Event = field(default_factory=threading.Event)


@dataclass
class IndexJob:
    job_id: str
    program_id: str
    state: str = "queued"
    progress: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None
    cancel: threading.Event = field(default_factory=threading.Event)


class AgentRuntime:
    """Own one persistent chatbot session per Program gateway."""

    def __init__(
        self,
        bridge: BridgeClient | None = None,
        *,
        backend: AnalysisBackend | None = None,
        gateway_factory: Callable[[str], ProgramGateway] | None = None,
    ) -> None:
        self.backend = backend or GhidraAnalysisBackend(bridge)
        self._gateway_factory = gateway_factory or self.backend.gateway_for
        self._sessions: dict[str, ProgramSession] = {}
        self._lock = threading.RLock()
        self._annotation_jobs: dict[str, AnnotationJob] = {}
        self._chat_jobs: dict[str, ChatJob] = {}
        self._index_jobs: dict[str, IndexJob] = {}

    def programs(self) -> list[dict[str, Any]]:
        programs = self.backend.list_programs()
        live_ids = {str(program["program_id"]) for program in programs}
        with self._lock:
            for program_id in set(self._sessions) - live_ids:
                self._sessions.pop(program_id, None)
        return programs

    def session(self, program_id: str) -> ProgramSession:
        with self._lock:
            existing = self._sessions.get(program_id)
            if existing is not None:
                return existing
            logger.info("creating chatbot session program_id=%s", program_id)
            session = ProgramSession(program_id, ChatbotAgent(program_id, self.gateway_for(program_id)))
            self._sessions[program_id] = session
            return session

    def gateway_for(self, program_id: str) -> ProgramGateway:
        return self._gateway_factory(program_id)

    def bridge_for(self, program_id: str) -> ProgramGateway:
        """Compatibility alias for integrations that still use the old name."""
        return self.gateway_for(program_id)

    def run_capability(
        self,
        program_id: str,
        capability: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        logger.debug("capability start program_id=%s capability=%s", program_id, capability)
        if not capability_enabled(capability, CAPABILITY_TO_TOOL, TOOL_GROUP_BY_NAME):
            raise ToolPolicyError(f"Capability disabled by tool policy: {capability}")
        result = self.gateway_for(program_id).invoke(
            program_id, capability, normalize_bridge_arguments(capability, arguments)
        )
        logger.debug("capability complete program_id=%s capability=%s", program_id, capability)
        return result

    def plan(self, request: str, program_id: str) -> dict[str, Any]:
        """Compatibility response for callers that only request planning metadata."""
        return {
            "status": "available",
            "message": "Use /v1/chat or /v1/analyze to run the persistent chatbot agent.",
            "request": request,
            "program_id": program_id,
        }

    def analyze(self, request: dict[str, Any]) -> dict[str, Any]:
        program_id = str(request["program_id"])
        started = time.monotonic()
        logger.info("analysis start program_id=%s address=%s", program_id, request.get("address"))
        session = self.session(program_id)
        with session.lock:
            result = session.agent.run(
                str(request.get("request") or "Analyse the selected location and its containing function."),
                address=request.get("address"),
            )
        logger.info("analysis complete program_id=%s duration=%.3fs", program_id, time.monotonic() - started)
        return result

    def chat(self, program_id: str, message: str, address: dict[str, Any] | None = None) -> dict[str, Any]:
        started = time.monotonic()
        logger.info("chat start program_id=%s message_chars=%s address=%s", program_id, len(message), address)
        session = self.session(program_id)
        with session.lock:
            result = session.agent.run(message, address=address)
        logger.info("chat complete program_id=%s duration=%.3fs", program_id, time.monotonic() - started)
        return result

    def session_state(self, program_id: str) -> dict[str, Any]:
        session = self.session(program_id)
        with session.lock:
            return {
                "program_id": program_id,
                "conversation_history": session.agent.state.conversation_history,
                "state": str(session.agent.state),
                "tool_names": sorted(session.agent.exposed_tools),
            }

    def clear_session(self, program_id: str) -> None:
        logger.info("clearing chatbot session program_id=%s", program_id)
        with self._lock:
            active_jobs = [
                job for job in self._chat_jobs.values()
                if job.program_id == program_id and job.state in {"queued", "running"}
            ]
        for job in active_jobs:
            job.cancel.set()
            job.agent.cancel_current()
        with self._lock:
            session = self._sessions.get(program_id)
        if session is not None:
            with session.lock:
                session.agent.state.clear()

    def start_index(self, program_id: str, *, resume: bool = False, reindex: bool = False) -> dict[str, Any]:
        with self._lock:
            if any(job.program_id == program_id and job.state in {"queued", "running"} for job in self._index_jobs.values()):
                raise ValueError("An indexing request is already running for this program")
            job = IndexJob(str(uuid.uuid4()), program_id)
            self._index_jobs[job.job_id] = job
        threading.Thread(target=self._run_index, args=(job, resume, reindex), daemon=True).start()
        return self.index_job(job.job_id)

    def _run_index(self, job: IndexJob, resume: bool, reindex: bool) -> None:
        job.state = "running"
        try:
            bridge = self.gateway_for(job.program_id)
            index = FunctionIndexer(
                job.program_id,
                bridge,
                cancel=job.cancel,
                progress=lambda update: self._update_index_progress(job, update),
            ).run(resume=resume, reindex=reindex)
            job.result = index.to_dict()
            job.progress = {
                "phase": index.batch_metadata.phase,
                "state": index.indexing_state,
                "progress": index.indexing_progress,
                "percent": index.indexing_progress,
                "indexed": index.size(),
                "total": index.total_function_count,
                "current": index.batch_metadata.current_function_name,
                "message": index.batch_metadata.last_error or "",
            }
            job.state = "completed"
        except IndexCancelled as error:
            job.state = "cancelled"
            job.error = str(error)
            job.progress = {
                **job.progress,
                "state": "cancelled",
                "phase": "CANCELLED",
                "message": str(error),
            }
        except Exception as error:
            logger.exception("index job failed job_id=%s", job.job_id)
            job.state = "failed"
            job.error = str(error)
            job.progress = {
                **job.progress,
                "state": "failed",
                "phase": "FAILED",
                "message": str(error),
            }

    @staticmethod
    def _update_index_progress(job: IndexJob, update: dict[str, Any]) -> None:
        job.progress = dict(update)

    def index_job(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._index_jobs.get(job_id)
        if job is None:
            raise KeyError(f"Unknown indexing job: {job_id}")
        result: dict[str, Any] = {"job_id": job.job_id, "program_id": job.program_id, "state": job.state, "progress": job.progress}
        if job.result is not None:
            result["result"] = job.result
        if job.error is not None:
            result["error"] = job.error
        return result

    def cancel_index(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._index_jobs.get(job_id)
        if job is None:
            raise KeyError(f"Unknown indexing job: {job_id}")
        if job.state in {"queued", "running"}:
            job.cancel.set()
        return self.index_job(job_id)

    def index_stats(self, program_id: str) -> dict[str, Any]:
        metadata = self.gateway_for(program_id).get_program_metadata()
        index = FunctionIndexManager.get(metadata)
        importance: dict[str, int] = {}
        categories: dict[str, int] = {}
        for entry in index.entries_by_address.values():
            if entry.importance():
                importance[entry.importance()] = importance.get(entry.importance(), 0) + 1
            for tag in entry.tags:
                if tag not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"}:
                    categories[tag] = categories.get(tag, 0) + 1
        return {"stable_id": index.stable_id, "program_name": index.program_name, "state": index.indexing_state, "progress": index.indexing_progress, "indexed": index.size(), "total": index.total_function_count, "tokens": index.total_tokens_used, "importance": importance, "categories": dict(sorted(categories.items(), key=lambda item: -item[1])[:15])}

    def index_entries(self, program_id: str, offset: int = 0, limit: int = 1000) -> dict[str, Any]:
        if offset < 0 or limit < 1 or limit > 5000:
            raise ValueError("index entries offset must be non-negative and limit must be between 1 and 5000")
        metadata = self.gateway_for(program_id).get_program_metadata()
        index = FunctionIndexManager.get(metadata)
        entries = list(index.entries_by_address.values())
        page = entries[offset:offset + limit]
        return {
            "stable_id": index.stable_id,
            "program_name": index.program_name,
            "state": index.indexing_state,
            "progress": index.indexing_progress,
            "indexed": index.size(),
            "total": len(entries),
            "offset": offset,
            "returned": len(page),
            "functions": [entry.to_dict() for entry in page],
        }

    def search_index(self, program_id: str, query: str) -> str:
        metadata = self.gateway_for(program_id).get_program_metadata()
        return search_index(FunctionIndexManager.get(metadata), query)

    def start_chat(self, program_id: str, message: str, address: dict[str, Any] | None = None) -> dict[str, Any]:
        session = self.session(program_id)
        with self._lock:
            if any(
                job.program_id == program_id and job.state in {"queued", "running"}
                for job in self._chat_jobs.values()
            ):
                raise ValueError("A chat request is already running for this program")
            job = ChatJob(str(uuid.uuid4()), program_id, session.agent, message, address)
            self._chat_jobs[job.job_id] = job
        thread = threading.Thread(target=self._run_chat, args=(job,), daemon=True)
        thread.start()
        return self.chat_job(job.job_id)

    def _run_chat(self, job: ChatJob) -> None:
        started = time.monotonic()
        job.state = "running"
        logger.info("chat job start job_id=%s program_id=%s", job.job_id, job.program_id)
        try:
            session = self.session(job.program_id)
            with session.lock:
                job.result = job.agent.run(
                    job.message,
                    address=job.address,
                    cancel=job.cancel,
                    progress=lambda update: self._update_chat_progress(job, update),
                )
            job.state = "completed"
        except AgentCancelled as error:
            job.state = "cancelled"
            job.error = str(error)
        except Exception as error:
            logger.exception("chat job failed job_id=%s", job.job_id)
            job.state = "failed"
            job.error = str(error)
        finally:
            logger.info("chat job finish job_id=%s program_id=%s state=%s duration=%.3fs", job.job_id, job.program_id, job.state, time.monotonic() - started)

    @staticmethod
    def _update_chat_progress(job: ChatJob, update: dict[str, Any]) -> None:
        job.progress = update

    def chat_job(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._chat_jobs.get(job_id)
        if job is None:
            raise KeyError(f"Unknown chat job: {job_id}")
        result: dict[str, Any] = {
            "job_id": job.job_id,
            "program_id": job.program_id,
            "state": job.state,
        }
        if job.progress is not None:
            result["progress"] = job.progress
        if job.result is not None:
            result["result"] = job.result
        if job.error is not None:
            result["error"] = job.error
        return result

    def cancel_chat(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._chat_jobs.get(job_id)
        if job is None:
            raise KeyError(f"Unknown chat job: {job_id}")
        if job.state in {"queued", "running"}:
            job.cancel.set()
            job.agent.cancel_current()
        return self.chat_job(job_id)

    def start_annotation(self, request: dict[str, Any]) -> dict[str, Any]:
        program_id = str(request["program_id"])
        job = AnnotationJob(str(uuid.uuid4()), program_id)
        with self._lock:
            self._annotation_jobs[job.job_id] = job
        thread = threading.Thread(target=self._run_annotation, args=(job, request), daemon=True)
        thread.start()
        return self.annotation_job(job.job_id)

    def _run_annotation(self, job: AnnotationJob, request: dict[str, Any]) -> None:
        started = time.monotonic()
        job.state = "running"
        job.message = "Starting annotation"
        logger.info("annotation job start job_id=%s program_id=%s mode=%s", job.job_id, job.program_id, request.get("mode", "manual"))
        try:
            workflow = AnnotationWorkflow(
                self.gateway_for(job.program_id), job.program_id, job.cancel,
                lambda message, progress: self._update_annotation(job, message, progress),
            )
            job.result = workflow.run(request)
            job.state = "completed"
            job.message = "Annotation complete"
            job.progress = 100
        except AnnotationCancelled as error:
            job.state = "cancelled"
            job.message = str(error)
            job.error = str(error)
        except Exception as error:
            logger.exception("annotation job failed job_id=%s", job.job_id)
            job.state = "failed"
            job.message = str(error)
            job.error = str(error)
        finally:
            logger.info("annotation job finish job_id=%s program_id=%s state=%s duration=%.3fs", job.job_id, job.program_id, job.state, time.monotonic() - started)

    @staticmethod
    def _update_annotation(job: AnnotationJob, message: str, progress: int) -> None:
        if not job.cancel.is_set():
            job.message = message
            job.progress = progress

    def annotation_job(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._annotation_jobs.get(job_id)
        if job is None:
            logger.warning("annotation job missing job_id=%s; treating it as lost after an agent restart", job_id)
            return {
                "job_id": job_id,
                "state": "lost",
                "progress": 0,
                "message": "Annotation job is no longer available; the Python agent was restarted.",
                "error": "Annotation job lost because the Python agent restarted.",
            }
        result: dict[str, Any] = {
            "job_id": job.job_id, "program_id": job.program_id, "state": job.state,
            "progress": job.progress, "message": job.message,
        }
        if job.result is not None:
            result["result"] = job.result
        if job.error is not None:
            result["error"] = job.error
        return result

    def cancel_annotation(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._annotation_jobs.get(job_id)
        if job is None:
            return self.annotation_job(job_id)
        job.cancel.set()
        return self.annotation_job(job_id)

    def undo_annotation(self, program_id: str) -> dict[str, Any]:
        return AnnotationWorkflow(self.gateway_for(program_id), program_id).undo_last()
