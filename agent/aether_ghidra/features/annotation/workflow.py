from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Callable

from ...config.settings import load_config
from .history import AnnotationHistory
from ...config.tool_policy import capability_enabled
from ...observability.conversation_logging import ConversationLogger
from ...integrations.ghidra.identity import function_address, function_ref as normalize_function_ref, structured_address
from ...tools.catalog import CAPABILITY_TO_TOOL, TOOL_GROUP_BY_NAME, ChatbotToolbox, ToolNames
from .staging import MutationStaging


logger = logging.getLogger(__name__)
Progress = Callable[[str, int], None]
GATHERER_SKETCH_MAX_LINES = 40
GATHERER_SKETCH_MAX_CHARS = 2000
ADDRESS_PREFIX = re.compile(r"^\s*(?:0x[0-9a-fA-F]+(?:\s*,\s*0x[0-9a-fA-F]+)*)\s*:\s*")
DECLARATION_LINE = re.compile(
    r"^(?:[A-Za-z_]\w*|undefined\d+)(?:\s+|\s*\*\s*)+"
    r"[A-Za-z_]\w*(?:\s*\[[^\]]+\])?\s*;+$"
)
GATHERING_CAPABILITIES = frozenset({"get_function_call_tree", "get_annotation_context"})
ANNOTATION_CAPABILITIES = frozenset({
    "rename_function", "rename_variable", "retype_variable", "update_function_definition",
    "set_function_comment", "set_code_unit_comment",
    "resolve_pseudocode_call",
    "apply_annotation_batch",
})


class AnnotationCancelled(RuntimeError):
    pass


class AnnotationWorkflow:
    def __init__(self, bridge: Any, program_id: str, cancel: Any = None, progress: Progress | None = None) -> None:
        self.bridge = bridge
        self.program_id = program_id
        self.cancel = cancel
        self._progress_callback = progress or (lambda _message, _percent: None)
        self.conversation_logger = ConversationLogger()
        self._last_staging: MutationStaging | None = None

    def run(self, request: dict[str, Any]) -> dict[str, Any]:
        self._check_cancel()
        mode = str(request.get("mode") or "manual").lower()
        if mode not in {"manual", "llm_guided"}:
            raise ValueError("mode must be manual or llm_guided")
        if not capability_enabled("get_function_call_tree", CAPABILITY_TO_TOOL, TOOL_GROUP_BY_NAME):
            raise PermissionError("Annotation read tools are disabled")
        if not capability_enabled("apply_annotation_batch", CAPABILITY_TO_TOOL, TOOL_GROUP_BY_NAME):
            raise PermissionError("Enable the annotation write tool group before annotating")

        logger.info("annotation flow start program_id=%s mode=%s address=%s", self.program_id, mode, request.get("address"))
        root_ref = request.get("function_ref") or {"address": request.get("address")}
        root_address = function_address(root_ref)
        self._report_progress("Gathering candidate functions", 10)
        tree = self._gather("get_function_call_tree", {
            "address": root_address,
            "direction": "callees",
            "max_depth": int(request.get("max_depth", 5)),
            "max_functions": int(request.get("max_functions", 30)),
            "max_edges": int(request.get("max_edges", 48)),
        })
        self._check_cancel()
        candidates = [item for item in tree.get("functions", []) if self._is_decompilable_candidate(item)]
        logger.info("annotation flow candidates program_id=%s count=%s truncated=%s", self.program_id, len(candidates), tree.get("truncated", False))
        candidate_context = None
        if mode == "llm_guided":
            self._report_progress("Collecting candidate pseudocode", 25)
            candidate_context = self._gather("get_annotation_context", {
                "functions": [self._function_ref(item) for item in candidates],
            })
        selected = self._selected_functions(request, candidates, mode, candidate_context)
        if not selected:
            raise ValueError("No functions selected for annotation")

        logger.info("annotation flow selected program_id=%s count=%s functions=%s", self.program_id, len(selected), [item.get("name") for item in selected])
        self._report_progress("Collecting annotation context", 35)
        context = self._selected_context(candidate_context, selected) if candidate_context is not None else self._gather(
            "get_annotation_context", {"functions": selected}
        )
        self._check_cancel()
        self._report_progress("Requesting annotation proposals", 55)
        applied = None
        try:
            operations = self._propose_operations(context, request, mode)
            operations = self._validate_operations(operations, context)
            logger.info("annotation flow proposals program_id=%s count=%s", self.program_id, len(operations))
            self._check_cancel()
            if not operations:
                return {"mode": mode, "selected_functions": selected, "operations": [], "message": "No annotation operations proposed."}

            self._report_progress("Applying annotation batch", 80)
            if self._last_staging is not None:
                self._last_staging.operations = operations
                applied = self._last_staging.commit(self._annotate)
            else:
                applied = self._annotate("apply_annotation_batch", {"operations": operations})
            metadata = next((item for item in self.bridge.list_programs() if item.get("program_id") == self.program_id), {})
            program_key = str(metadata.get("sha256") or metadata.get("md5") or self.program_id)
            AnnotationHistory(program_key).append({
                "batch_id": applied.get("batch_id"),
                "program_id": self.program_id,
                "program_key": program_key,
                "mode": mode,
                "selected_functions": selected,
                "operations": applied.get("operations", []),
            })
            logger.info("annotation flow applied program_id=%s batch_id=%s operations=%s", self.program_id, applied.get("batch_id"), len(applied.get("operations", [])))
            self._report_progress("Annotation complete", 100)
            return {"mode": mode, "selected_functions": selected, **applied}
        except Exception:
            if applied is None and self._last_staging is not None:
                immediate = self._last_staging.immediate_result()
                if immediate is not None:
                    metadata = next((item for item in self.bridge.list_programs() if item.get("program_id") == self.program_id), {})
                    program_key = str(metadata.get("sha256") or metadata.get("md5") or self.program_id)
                    AnnotationHistory(program_key).append({
                        "batch_id": immediate.get("batch_id"),
                        "program_id": self.program_id,
                        "program_key": program_key,
                        "mode": mode,
                        "selected_functions": selected,
                        "operations": immediate.get("operations", []),
                    })
            if self._last_staging is not None:
                self._last_staging.discard()
            raise

    def undo_last(self) -> dict[str, Any]:
        if not capability_enabled("apply_annotation_batch", CAPABILITY_TO_TOOL, TOOL_GROUP_BY_NAME):
            raise PermissionError("Enable the annotation writes tool group before undoing annotations")
        metadata = next((item for item in self.bridge.list_programs() if item.get("program_id") == self.program_id), {})
        program_key = str(metadata.get("sha256") or metadata.get("md5") or self.program_id)
        history = AnnotationHistory(program_key)
        entry = history.latest_active()
        if entry is None:
            raise ValueError("No active AETHER annotation batch exists for this program")
        inverse = []
        for index, operation in enumerate(reversed(entry.get("operations", []))):
            target = dict(operation.get("target") or {})
            if operation.get("kind") == "rename_variable":
                target["variable_name"] = operation.get("after", target.get("variable_name", ""))
            inverse_operation = {
                "id": f"undo-{index}",
                "kind": operation["kind"],
                "target": target,
                "expected_before": operation.get("after", ""),
                "value": operation.get("before", ""),
                "comment_kind": operation.get("comment_kind", "eol"),
            }
            if operation.get("kind") == "update_function_definition":
                try:
                    inverse_operation["definition"] = json.loads(operation.get("before", "{}"))
                except (TypeError, json.JSONDecodeError) as error:
                    raise ValueError("Cannot undo malformed function-definition history") from error
            inverse.append(inverse_operation)
            if operation.get("created_decompiler_variable"):
                inverse[-1]["remove_decompiler_variable"] = True
        result = self._annotate("apply_annotation_batch", {"operations": inverse})
        history.mark_undone(str(entry.get("batch_id")))
        return {"undone_batch_id": entry.get("batch_id"), "result": result}

    def _selected_functions(
        self,
        request: dict[str, Any],
        candidates: list[dict[str, Any]],
        mode: str,
        candidate_context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        if mode == "manual":
            requested = request.get("selected_functions") or []
            if not requested:
                return [self._function_ref(candidates[0])] if candidates else []
            allowed = {self._address_key(item.get("address")): item for item in candidates}
            selected = []
            for item in requested:
                candidate_ref = item.get("function_ref", item) if isinstance(item, dict) else None
                candidate = allowed.get(self._address_key(candidate_ref.get("address"))) if isinstance(candidate_ref, dict) else None
                if candidate is not None:
                    selected.append(self._function_ref(candidate))
            root = self._function_ref(candidates[0]) if candidates else None
            if root is not None and not any(self._address_key(item.get("address")) == self._address_key(root["address"]) for item in selected):
                selected.insert(0, root)
            return selected

        prompt = self._prompt("gatherer.txt") + "\n\n" + json.dumps(
            {
                "candidates": [{**item, "function_ref": self._function_ref(item)} for item in candidates],
                "function_sketches": self._gatherer_context(candidate_context),
            },
            indent=2,
            default=str,
        )
        raw = self._llm_text("You select relevant reverse-engineering context.", prompt)
        decoded = self._json_object(raw)
        allowed = {self._address_key(item.get("address")): item for item in candidates}
        selected = []
        selected_keys: set[str] = set()
        for item in decoded.get("selected_functions", []):
            if not isinstance(item, dict):
                continue
            selected_ref = item.get("function_ref", item)
            key = self._address_key(selected_ref.get("address")) if isinstance(selected_ref, dict) else ""
            if key in allowed and key not in selected_keys:
                selected.append(self._function_ref(allowed[key]))
                selected_keys.add(key)
        if not selected and candidates:
            selected = [self._function_ref(candidates[0])]
            selected_keys.add(self._address_key(candidates[0].get("address")))
        elif candidates and self._address_key(candidates[0].get("address")) not in selected_keys:
            selected.insert(0, self._function_ref(candidates[0]))
            selected_keys.add(self._address_key(candidates[0].get("address")))
        return selected

    @staticmethod
    def _gatherer_context(context: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Give the gatherer compact pseudocode keyed by candidate address."""
        if not context:
            return []
        return [
            {
                "function_ref": {"address": item.get("address"), "name": item.get("name", "")},
                "pseudocode_sketch": AnnotationWorkflow._compact_pseudocode(item.get("pseudocode", "")),
            }
            for item in context.get("functions", [])
        ]

    @staticmethod
    def _compact_pseudocode(pseudocode: Any) -> list[str]:
        """Keep structural pseudocode signals without repeating candidate metadata or comments."""
        text = str(pseudocode or "")
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        text = re.sub(r"//[^\r\n]*", "", text)
        lines: list[str] = []
        seen: set[str] = set()
        body_started = False
        for raw_line in text.splitlines():
            line = ADDRESS_PREFIX.sub("", raw_line)
            line = re.sub(r"\s+", " ", line).strip()
            if not line:
                continue
            if not body_started:
                if "{" not in line:
                    continue
                body_started = True
                line = line.split("{", 1)[1].strip()
                if not line:
                    continue
            if line in {"{", "}", "};"} or DECLARATION_LINE.fullmatch(line):
                continue
            if line in seen:
                continue
            seen.add(line)
            lines.append(line)

        if not lines:
            return []
        if len(lines) > GATHERER_SKETCH_MAX_LINES:
            omitted = len(lines) - GATHERER_SKETCH_MAX_LINES + 1
            head = GATHERER_SKETCH_MAX_LINES // 2
            tail = GATHERER_SKETCH_MAX_LINES - head - 1
            lines = lines[:head] + [f"[{omitted} structural lines omitted]"] + lines[-tail:]
        if sum(len(line) + 1 for line in lines) > GATHERER_SKETCH_MAX_CHARS:
            kept: list[str] = []
            used = 0
            for line in lines:
                if used + len(line) + 1 > GATHERER_SKETCH_MAX_CHARS:
                    kept.append("[remaining structural lines omitted]")
                    break
                kept.append(line)
                used += len(line) + 1
            lines = kept
        return lines

    @staticmethod
    def _selected_context(context: dict[str, Any], selected: list[dict[str, Any]]) -> dict[str, Any]:
        selected_keys = {AnnotationWorkflow._address_key(item.get("address")) for item in selected}
        result = dict(context)
        result["functions"] = [
            item for item in context.get("functions", [])
            if AnnotationWorkflow._address_key(item.get("address")) in selected_keys
        ]
        return result

    def _propose_operations(self, context: dict[str, Any], request: dict[str, Any], mode: str) -> list[dict[str, Any]]:
        guidance = request.get("instruction", "").strip()
        prompt = self._prompt("annotator.txt")
        if guidance:
            prompt += "\n\nAnalysis guidance from the user:\n" + guidance
        prompt += "\n\nPseudocode mapped to exact function_ref:\n" + json.dumps(
            [{"function_ref": self._function_ref(item), "pseudocode": item.get("pseudocode", "")} for item in context.get("functions", [])],
            indent=2,
            ensure_ascii=True,
        )
        staging = MutationStaging(context, immediate_rename=self._immediate_rename)
        self._last_staging = staging
        toolbox = ChatbotToolbox(None, self.bridge, staging)
        self._llm_with_tools(
            "You are a careful Ghidra reverse-engineering annotator. Use the provided mutation tools for every proposed change. Do not emit annotation JSON.",
            prompt,
            toolbox,
            staging,
        )
        return staging.operations

    def _immediate_rename(self, operation: dict[str, Any]) -> dict[str, Any]:
        result = self._annotate("rename_function", {
            "address": operation["target"]["function_address"],
            "name": operation["value"],
        })
        return {
            "batch_id": "immediate-" + str(operation["id"]),
            "operations": [{
                "id": operation["id"],
                "kind": operation["kind"],
                "target": operation["target"],
                "before": operation.get("_before", ""),
                "after": result.get("name", operation["value"]),
            }],
        }

    def _validate_operations(self, operations: list[Any], context: dict[str, Any]) -> list[dict[str, Any]]:
        allowed_functions = {self._address_key(item.get("address")): item for item in context.get("functions", [])}
        valid = []
        for index, raw in enumerate(operations):
            if not isinstance(raw, dict) or raw.get("kind") not in {
                "set_function_comment", "set_code_unit_comment", "rename_function", "rename_variable",
                "retype_variable", "update_function_definition",
            }:
                continue
            operation = dict(raw)
            operation.setdefault("id", f"annotation-{index}")
            operation["value"] = str(operation.get("value", "")).strip()
            target = operation.get("target")
            if not isinstance(target, dict):
                continue
            function_address_value = target.get("function_address")
            if operation["kind"] != "set_code_unit_comment" and function_address_value is None:
                continue
            if operation["kind"] != "set_code_unit_comment" and not isinstance(function_address_value, dict):
                continue
            if function_address_value is not None and self._address_key(function_address_value) not in allowed_functions:
                continue
            if operation["kind"] == "set_code_unit_comment":
                try:
                    target["address"] = structured_address(target.get("address"), "location")
                except ValueError:
                    continue
                if operation.get("comment_kind", "eol") not in {"eol", "pre", "post", "plate", "repeatable"}:
                    continue
                operation["comment_kind"] = operation.get("comment_kind", "eol")
            if operation["kind"] == "rename_variable" and not target.get("variable_name"):
                continue
            if operation["kind"] == "retype_variable":
                if not target.get("variable_name") or not operation["value"]:
                    continue
            if operation["kind"] == "update_function_definition":
                definition = operation.get("definition")
                if not isinstance(definition, dict) or not definition.get("return_type"):
                    continue
                if not isinstance(definition.get("parameters"), list):
                    continue
            if not operation["value"] and operation["kind"].startswith("rename"):
                continue
            valid.append(operation)
        return valid

    def _llm_text(self, system: str, prompt: str) -> str:
        started = time.monotonic()
        logger.info("annotation llm start phase=gatherer program_id=%s prompt_chars=%s", self.program_id, len(prompt))
        client = self._llm_client()
        request: dict[str, Any] = {
            "model": load_config().get("OPENAI_MODEL", "gpt-4o-mini"),
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            "max_tokens": 8192,
            "temperature": 0.1,
        }
        config = load_config()
        if config.get("OPENAI_EXTRA_BODY"):
            request["extra_body"] = config["OPENAI_EXTRA_BODY"]
        response = client.chat.completions.create(**request)
        self.conversation_logger.record_completion("annotation_gatherer", request, response)
        logger.info("annotation llm complete phase=gatherer program_id=%s duration=%.3fs response_chars=%s", self.program_id, time.monotonic() - started, len(str(response.choices[0].message.content or "")))
        return str(response.choices[0].message.content or "")

    def _llm_with_tools(self, system: str, prompt: str, toolbox: ChatbotToolbox, staging: MutationStaging) -> str:
        config = load_config()
        client = self._llm_client()
        allowed = {
            ToolNames.RENAME_FUNCTION.value,
            ToolNames.RENAME_VARIABLE.value,
            ToolNames.RETYPE_VARIABLE.value,
            ToolNames.UPDATE_FUNCTION_DEFINITION.value,
            ToolNames.SET_FUNCTION_COMMENT.value,
            ToolNames.SET_CODE_UNIT_COMMENT.value,
            ToolNames.RESOLVE_PSEUDOCODE_CALL.value,
        }
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]
        for _ in range(12):
            iteration = _ + 1
            logger.info("annotation llm start phase=annotator program_id=%s iteration=%s", self.program_id, iteration)
            request: dict[str, Any] = {
                "model": config.get("OPENAI_MODEL", "gpt-4o-mini"),
                "messages": messages,
                "tools": toolbox.get_tool_definitions(allowed),
                "tool_choice": "auto",
                "max_tokens": 8192,
                "temperature": 0.1,
            }
            if config.get("OPENAI_EXTRA_BODY"):
                request["extra_body"] = config["OPENAI_EXTRA_BODY"]
            response = client.chat.completions.create(**request)
            self.conversation_logger.record_completion("annotation", request, response)
            message = response.choices[0].message
            raw_calls = getattr(message, "tool_calls", None) or []
            logger.info("annotation llm complete phase=annotator program_id=%s iteration=%s tool_calls=%s", self.program_id, iteration, len(raw_calls))
            if hasattr(message, "model_dump"):
                assistant = message.model_dump(exclude_none=True)
            else:
                assistant = {"role": "assistant", "content": getattr(message, "content", None)}
            messages.append(assistant)
            if not raw_calls:
                return str(getattr(message, "content", "") or "")
            for call in raw_calls:
                if isinstance(call, dict):
                    function = call.get("function", {})
                    name = function.get("name", "")
                    arguments = function.get("arguments", {})
                    call_id = call.get("id", "")
                else:
                    function = call.function
                    name = function.name
                    arguments = function.arguments
                    call_id = call.id
                try:
                    parsed = json.loads(arguments) if isinstance(arguments, str) else arguments
                    logger.info("annotation model tool_call program_id=%s iteration=%s tool=%s target=%s", self.program_id, iteration, name, self._tool_target(parsed))
                    result = toolbox.execute_named(name, parsed)
                    logger.info("annotation model tool_result program_id=%s iteration=%s tool=%s result_chars=%s", self.program_id, iteration, name, len(result))
                except Exception as exc:
                    result = f"Error executing {name}: {exc}"
                    logger.warning("annotation model tool_failed program_id=%s iteration=%s tool=%s error=%s", self.program_id, iteration, name, exc)
                messages.append({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": result,
                })
        return "Annotation tool-call limit reached."

    @staticmethod
    def _llm_client() -> Any:
        try:
            import httpx
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError("The annotation workflow requires the 'openai' and 'httpx' packages.") from exc
        config = load_config()
        api_key = config.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not configured.")
        return OpenAI(
            api_key=api_key,
            base_url=config.get("OPENAI_BASE_URL") or None,
            http_client=httpx.Client(verify=False, timeout=600.0),
        )

    def _gather(self, capability: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if capability not in GATHERING_CAPABILITIES:
            raise RuntimeError(f"Capability is not allowed during annotation gathering: {capability}")
        started = time.monotonic()
        logger.info("annotation bridge start phase=gathering program_id=%s capability=%s", self.program_id, capability)
        try:
            result = self.bridge.invoke(self.program_id, capability, arguments)
            logger.info("annotation bridge complete phase=gathering program_id=%s capability=%s duration=%.3fs", self.program_id, capability, time.monotonic() - started)
            return result
        except Exception:
            logger.exception("annotation bridge failed phase=gathering program_id=%s capability=%s", self.program_id, capability)
            raise

    def _annotate(self, capability: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if capability not in ANNOTATION_CAPABILITIES:
            raise RuntimeError(f"Capability is not allowed during annotation: {capability}")
        started = time.monotonic()
        logger.info("annotation bridge start phase=annotation program_id=%s capability=%s", self.program_id, capability)
        try:
            result = self.bridge.invoke(self.program_id, capability, arguments)
            logger.info("annotation bridge complete phase=annotation program_id=%s capability=%s duration=%.3fs", self.program_id, capability, time.monotonic() - started)
            return result
        except Exception:
            logger.exception("annotation bridge failed phase=annotation program_id=%s capability=%s", self.program_id, capability)
            raise

    def _report_progress(self, message: str, percent: int) -> None:
        logger.info("annotation stage program_id=%s progress=%s%% message=%s", self.program_id, percent, message)
        self._progress_callback(message, percent)

    @staticmethod
    def _tool_target(arguments: Any) -> Any:
        if not isinstance(arguments, dict):
            return "json"
        return (
            arguments.get("function_ref")
            or arguments.get("variable_name")
            or arguments.get("structure_path")
            or arguments.get("class_ref")
            or arguments.get("location")
            or arguments.get("address")
            or "-"
        )

    @staticmethod
    def _json_object(value: str) -> dict[str, Any]:
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", value, re.DOTALL)
        candidate = fenced.group(1) if fenced else value[value.find("{"):value.rfind("}") + 1]
        decoded = json.loads(candidate)
        if not isinstance(decoded, dict):
            raise ValueError("LLM annotation response must be a JSON object")
        return decoded

    def _check_cancel(self) -> None:
        if self.cancel is not None and self.cancel.is_set():
            raise AnnotationCancelled("Annotation cancelled")

    @staticmethod
    def _prompt(name: str) -> str:
        path = Path(__file__).parent / "prompts" / name
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return "Return the requested annotation data as strict JSON."

    @staticmethod
    def _function_ref(item: dict[str, Any]) -> dict[str, Any]:
        return normalize_function_ref({"address": item.get("address"), "name": item.get("name", "")})

    @staticmethod
    def _is_decompilable_candidate(item: Any) -> bool:
        if not isinstance(item, dict) or item.get("external") or item.get("thunk"):
            return False
        address = item.get("address")
        try:
            function_address({"address": address})
        except ValueError:
            return False
        if isinstance(address, dict):
            return str(address.get("space", "")).upper() != "EXTERNAL"
        return not str(address or "").upper().startswith("EXTERNAL:")

    @staticmethod
    def _address_key(address: Any) -> str:
        return json.dumps(address, sort_keys=True, default=str)
