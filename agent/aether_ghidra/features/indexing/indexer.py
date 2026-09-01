from __future__ import annotations

import json
import logging
import queue
import threading
from typing import Any, Callable

from ...config.settings import load_config
from ...integrations.ghidra.chatbot_backend import GhidraChatbotBackendBridge
from ...integrations.ghidra.identity import function_ref
from .manager import FunctionIndexManager
from .model import BatchMetadata, FunctionEntry, FunctionIndex
from .taxonomy import DEFAULT_FUNCTION_TAGS, DynamicTagManager, IMPORTANCE_LEVELS, normalize_tag

Progress = Callable[[dict[str, Any]], None]
logger = logging.getLogger(__name__)


class IndexCancelled(Exception):
    pass


def address_key(value: Any) -> str:
    if isinstance(value, dict):
        return f"{value.get('space', 'ram')}:{value.get('offset', '')}"
    return str(value)


def address_aliases(value: Any) -> set[str]:
    """Return equivalent spellings used by Ghidra and LLM responses."""
    raw = address_key(value).strip().lower()
    aliases = {raw}
    if ":" in raw:
        space, offset = raw.split(":", 1)
    else:
        space, offset = "ram", raw
    offset = offset.strip()
    normalized = offset[2:] if offset.startswith("0x") else offset
    aliases.update({normalized, f"{space}:{normalized}", f"0x{normalized}"})
    try:
        compact = format(int(normalized, 16), "x")
    except ValueError:
        return aliases
    aliases.update({compact, f"{space}:{compact}", f"0x{compact}"})
    return aliases


class FunctionIndexer:
    """Port of the source plugin's resumable classify-and-persist pipeline."""

    def __init__(self, program_id: str, bridge: GhidraChatbotBackendBridge, *, cancel: threading.Event, progress: Progress | None = None) -> None:
        self.program_id = program_id
        self.bridge = bridge
        self.cancel = cancel
        self.progress = progress
        self.config = load_config()
        self.batch_size = max(1, int(self.config.get("INDEXING_BATCH_SIZE", 50)))
        self.max_function_size = int(self.config.get("INDEXING_MAX_FUNC_SIZE_BYTES", 24_576))
        self.max_decompile_size = int(self.config.get("INDEXING_DECOMP_MAX_FUNC_SIZE_BYTES", 12_288))
        self.max_retries = max(0, int(self.config.get("INDEXING_FAILED_RETRY_MAX", 5)))

    def _check(self) -> None:
        if self.cancel.is_set():
            raise IndexCancelled("Indexing paused by user")

    def _update(self, index: FunctionIndex, phase: str, **extra: Any) -> None:
        index.batch_metadata.phase = phase
        index.batch_metadata.last_update_time = int(__import__("time").time() * 1000)
        payload = {"phase": phase, "state": index.indexing_state, "progress": index.indexing_progress, "indexed": index.size(), "total": index.total_function_count, **extra}
        if self.progress:
            self.progress(payload)

    def _functions(self) -> list[dict[str, Any]]:
        functions: list[dict[str, Any]] = []
        offset = 0
        while True:
            self._check()
            page = self.bridge.list_functions(limit=1000, offset=offset, include_call_relationships=True)
            items = list(page.get("functions", []))
            functions.extend(items)
            if len(items) < 1000:
                break
            offset += len(items)
        result = []
        for item in functions:
            name = str(item.get("name", ""))
            if item.get("external") or item.get("thunk") or item.get("library"):
                continue
            if name.startswith(("j_", "nullsub_")):
                continue
            size = int(item.get("size", 0) or 0)
            if self.max_function_size > 0 and size > self.max_function_size:
                continue
            result.append(item)
        return result

    def _decompile(self, item: dict[str, Any]) -> str | None:
        size = int(item.get("size", 0) or 0)
        if size <= 0 or (self.max_decompile_size > 0 and size > self.max_decompile_size):
            return None
        result = self.bridge.get_function(function_ref({
            "address": item["address"], "name": item.get("name", ""),
        }), read_only=True)
        return str(result.get("code", "")) or None

    @staticmethod
    def _tools() -> list[dict[str, Any]]:
        address_schema = {
            "type": "object",
            "properties": {"space": {"type": "string"}, "offset": {"type": "string"}},
            "required": ["space", "offset"],
            "additionalProperties": False,
        }
        function_ref_schema = {
            "type": "object",
            "properties": {
                "address": address_schema, "name": {"type": "string"}, "signature": {"type": "string"},
                "namespace": {"type": "string"}, "comment": {"type": "string"},
                "external": {"type": "boolean"}, "thunk": {"type": "boolean"},
                "default_name": {"type": "boolean"}, "return_type": {"type": "string"},
                "calling_convention": {"type": "string"}, "varargs": {"type": "boolean"},
                "custom_storage": {"type": "boolean"}, "parameters": {"type": "array"},
            },
            "required": ["address"],
            "additionalProperties": True,
        }
        return [{
            "type": "function",
            "function": {
                "name": "index_function_entry",
                "description": "Classify one function for the persistent reverse engineering index.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "function_ref": function_ref_schema,
                        "importance": {"type": "string", "enum": list(IMPORTANCE_LEVELS)},
                        "categories": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        "summary": {"type": "string"},
                        "key_operations": {"type": "array", "items": {"type": "string"}},
                        "key_constants": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["function_ref", "importance", "categories", "summary"],
                },
            },
        }]

    def _client(self) -> Any:
        try:
            import httpx
            from openai import OpenAI
        except ImportError as error:
            raise RuntimeError("Indexing requires the openai and httpx packages") from error
        return OpenAI(
            api_key=self.config.get("OPENAI_API_KEY"),
            base_url=self.config.get("OPENAI_BASE_URL"),
            http_client=httpx.Client(verify=False, timeout=600.0),
        )

    def _cancellable_request(self, request: Callable[[], Any]) -> Any:
        """Keep cancellation responsive while a provider request is blocked."""
        result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

        def invoke() -> None:
            try:
                result.put((True, request()))
            except BaseException as error:  # Re-raise provider failures in the worker.
                result.put((False, error))

        threading.Thread(target=invoke, name="aether-index-provider", daemon=True).start()
        while True:
            try:
                succeeded, value = result.get(timeout=0.1)
            except queue.Empty:
                self._check()
                continue
            if succeeded:
                return value
            raise value

    def _classify(self, batch: list[dict[str, Any]], pseudocode: dict[str, str], index: FunctionIndex, tags: DynamicTagManager) -> list[FunctionEntry]:
        tag_lines = "\n".join(f"- {key}: {value}" for key, value in DEFAULT_FUNCTION_TAGS.items())
        sections = []
        for item in batch:
            address = address_key(item["address"])
            reference = function_ref(item)
            sections.append(f"## function_ref={json.dumps(reference, default=str)}\n```c\n{pseudocode.get(address, '')}\n```")
        prompt = f"""You are an expert reverse engineer classifying functions in batch indexing.
Assign exactly one importance level and one or more functional categories.
Importance: CRITICAL, HIGH, MEDIUM, LOW, MINIMAL.
Categories:\n{tag_lines}
Return only one index_function_entry tool call per function shown. Copy the exact structured function_ref for that function; never identify a function by name alone. Summaries must be searchable and explain what, how, and context.
Functions:\n{chr(10).join(sections)}"""
        client = self._client()
        response = self._cancellable_request(lambda: client.chat.completions.create(
            model=self.config.get("INDEXING_MODEL") or self.config.get("OPENAI_MODEL", "qwen/qwen3-coder"),
            messages=[{"role": "user", "content": prompt}],
            tools=self._tools(),
            tool_choice="required",
            temperature=0.7,
            max_tokens=int(self.config.get("INDEXING_MAX_TOKENS", 65_536)),
        ))
        message = response.choices[0].message
        entries: list[FunctionEntry] = []
        valid_addresses = {address_key(item["address"]): item for item in batch}
        aliases_to_address = {
            alias: canonical
            for canonical, item in valid_addresses.items()
            for alias in address_aliases(canonical)
        }
        tool_calls = getattr(message, "tool_calls", None) or []
        logger.info("index classification response tool_calls=%d batch=%d", len(tool_calls), len(batch))
        if not tool_calls:
            for canonical, item in valid_addresses.items():
                index.llm_failed_entries[canonical] = {
                    "name": str(item.get("name", "")),
                    "reason": "empty_tool_response",
                }
        for call in getattr(message, "tool_calls", None) or []:
            function = getattr(call, "function", None)
            if function is None:
                continue
            try:
                args = function.arguments if isinstance(function.arguments, dict) else json.loads(function.arguments)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(args, dict):
                continue
            raw_ref = args.get("function_ref")
            if not isinstance(raw_ref, dict):
                logger.warning("index classification returned no structured function_ref")
                continue
            address_value = raw_ref.get("address")
            if not isinstance(address_value, dict):
                logger.warning("index classification returned a non-structured function address")
                continue
            address = next((aliases_to_address[alias] for alias in address_aliases(address_value) if alias in aliases_to_address), None)
            name = str(raw_ref.get("name") or "").strip()
            if address is None:
                logger.warning("index classification returned unknown function_ref=%r", raw_ref)
                continue
            name = name or str(valid_addresses[address].get("name", ""))
            importance = str(args.get("importance", "")).upper()
            summary = str(args.get("summary", "")).strip()
            if importance not in IMPORTANCE_LEVELS or not summary:
                index.llm_failed_entries[address] = {"name": name, "reason": "invalid_entry"}
                continue
            categories_value = args.get("categories", [])
            if isinstance(categories_value, str):
                categories_value = [categories_value]
            categories = {tags.resolve(value, name) for value in categories_value if str(value).strip()}
            categories.discard("unknown") if len(categories) > 1 else None
            entries.append(FunctionEntry(
                name=name,
                address=address,
                tags=categories | {importance},
                summary=summary,
                called_functions=list(valid_addresses[address].get("called_functions", [])),
                caller_functions=list(valid_addresses[address].get("caller_functions", [])),
                key_operations=[str(value) for value in args.get("key_operations", [])],
                key_constants=[str(value) for value in args.get("key_constants", [])],
            ))
        classified_addresses = {entry.address for entry in entries}
        for canonical, item in valid_addresses.items():
            if canonical not in classified_addresses and canonical not in index.llm_failed_entries:
                index.llm_failed_entries[canonical] = {
                    "name": str(item.get("name", "")),
                    "reason": "missing_from_response",
                }
        return entries

    def _resolve_unknowns(self, entries: list[FunctionEntry], tags: DynamicTagManager) -> int:
        if not entries:
            return 0
        prompt = "Classify the following reverse engineering index entries. Replace unknown with one to three specific functional categories. Copy the exact structured function_ref; never resolve an entry by name. Return only resolve_unknown_entry tool calls.\n"
        for entry in entries:
            prompt += f"- {json.dumps({'address': {'space': entry.address.split(':', 1)[0], 'offset': entry.address.split(':', 1)[-1]}, 'name': entry.name})} tags={sorted(entry.tags)} summary={entry.summary}\n"
        tool = {"type": "function", "function": {"name": "resolve_unknown_entry", "description": "Resolve unknown categories.", "parameters": {"type": "object", "properties": {"function_ref": {"type": "object", "properties": {"address": {"type": "object", "properties": {"space": {"type": "string"}, "offset": {"type": "string"}}, "required": ["space", "offset"]}, "name": {"type": "string"}}, "required": ["address"]}, "categories": {"type": "array", "items": {"type": "string"}}}, "required": ["function_ref", "categories"]}}}
        client = self._client()
        response = self._cancellable_request(lambda: client.chat.completions.create(
            model=self.config.get("INDEXING_MODEL") or self.config.get("OPENAI_MODEL", "qwen/qwen3-coder"),
            messages=[{"role": "user", "content": prompt}],
            tools=[tool], tool_choice="required", temperature=0.3,
            max_tokens=int(self.config.get("INDEXING_MAX_TOKENS", 65_536)),
        ))
        by_address = {entry.address: entry for entry in entries}
        updated = 0
        for call in getattr(response.choices[0].message, "tool_calls", None) or []:
            function = getattr(call, "function", None)
            if function is None:
                continue
            try:
                args = function.arguments if isinstance(function.arguments, dict) else json.loads(function.arguments)
            except (TypeError, json.JSONDecodeError):
                continue
            raw_ref = args.get("function_ref")
            if not isinstance(raw_ref, dict):
                continue
            address = address_key(raw_ref.get("address"))
            entry = by_address.get(address)
            categories = {tags.resolve(value, entry.name) for value in args.get("categories", [])} if entry else set()
            if entry and categories:
                entry.tags = {tag for tag in entry.tags if tag != "unknown"} | categories
                updated += 1
        return updated

    def run(self, *, resume: bool = False, reindex: bool = False) -> FunctionIndex:
        try:
            return self._run(resume=resume, reindex=reindex)
        except IndexCancelled:
            self._save_paused_index()
            raise

    def _save_paused_index(self) -> None:
        try:
            metadata = self.bridge.get_program_metadata()
            index = FunctionIndexManager.get(metadata)
            index.indexing_state = "PAUSED"
            index.indexed = False
            index.batch_metadata.last_error = "Indexing paused; resume with resume=true"
            FunctionIndexManager.save(index)
        except Exception:
            logger.exception("could not persist paused index")

    def _run(self, *, resume: bool = False, reindex: bool = False) -> FunctionIndex:
        metadata = self.bridge.get_program_metadata()
        if reindex:
            FunctionIndexManager.clear(metadata)
        index = FunctionIndexManager.get(metadata)
        index.indexing_state = "IN_PROGRESS"
        index.indexed = False
        index.total_function_count = max(index.total_function_count, int(metadata.get("function_count", 0)))
        index.batch_metadata.last_error = None
        index.batch_metadata.indexed_functions = index.size()
        index.batch_metadata.start_time = index.batch_metadata.start_time or int(__import__("time").time() * 1000)
        FunctionIndexManager.save(index)
        self._update(index, "COLLECTING_FUNCTIONS")

        functions = self._functions()
        index.total_function_count = len(functions)
        # Call relationships are deterministic bridge data, so refresh them
        # even when resuming an existing index without another LLM pass.
        for item in functions:
            entry = index.entries_by_address.get(address_key(item["address"]))
            if entry is not None:
                entry.called_functions = list(item.get("called_functions", []))
                entry.caller_functions = list(item.get("caller_functions", []))
        pending = [item for item in functions if address_key(item["address"]) not in index.entries_by_address]
        if resume and not pending:
            index.indexed = True
            index.indexing_state = "COMPLETED"
            index.indexing_progress = 100
            index.batch_metadata.indexed_functions = index.size()
            index.batch_metadata.phase = "COMPLETED"
            index.batch_metadata.last_error = None
            FunctionIndexManager.save(index)
            self._update(index, "COMPLETED")
            return index

        pseudocode: dict[str, str] = {}
        self._update(index, "DECOMPILING", total=len(pending))
        for position, item in enumerate(pending, 1):
            self._check()
            address = address_key(item["address"])
            try:
                code = index.cached_pseudocode(address) if resume else None
                code = code or self._decompile(item)
                if code:
                    pseudocode[address] = code
                    if self.config.get("INDEXING_PSEUDOCODE_CACHE_ENABLED", True):
                        index.cache_pseudocode(address, code)
                else:
                    index.decompile_blacklist[address] = {"name": str(item.get("name", "")), "reason": "decompile_failed_or_size"}
            except Exception as error:
                index.batch_metadata.decompile_fail_count += 1
                index.batch_metadata.last_error = str(error)
            index.batch_metadata.decompiled_count = position
            index.batch_metadata.current_function_address = address
            index.batch_metadata.current_function_name = str(item.get("name", ""))
            index.indexing_progress = max(1, int(position / max(len(pending), 1) * 35))
            self._update(index, "DECOMPILING", current=item.get("name", ""), position=position, total=len(pending))
            if position % 10 == 0:
                FunctionIndexManager.save(index)
        FunctionIndexManager.save(index)

        candidates = [item for item in pending if address_key(item["address"]) in pseudocode]
        batches = [candidates[start:start + self.batch_size] for start in range(0, len(candidates), self.batch_size)]
        index.batch_metadata.total_batches = len(batches)
        tags = DynamicTagManager(index.dynamic_tags)
        for batch_number, batch in enumerate(batches, 1):
            self._check()
            index.batch_metadata.current_batch = batch_number
            self._update(index, "CLASSIFYING", batch=batch_number, batches=len(batches))
            try:
                entries = self._classify(batch, pseudocode, index, tags)
                for entry in entries:
                    index.add_entry(entry)
                if not entries:
                    index.indexing_state = "PARTIAL"
                    index.batch_metadata.last_error = f"No valid classifier entries returned for batch {batch_number}"
                    FunctionIndexManager.save(index)
                    raise RuntimeError(index.batch_metadata.last_error)
                index.batch_metadata.completed_batches = batch_number
                index.batch_metadata.indexed_functions = index.size()
                index.indexing_progress = 35 + int(batch_number / max(len(batches), 1) * 60)
                index.last_indexed_address = entries[-1].address if entries else index.last_indexed_address
            except Exception as error:
                index.indexing_state = "PARTIAL"
                index.batch_metadata.last_error = str(error)
                FunctionIndexManager.save(index)
                raise
            index.dynamic_tags = tags.to_dict()
            FunctionIndexManager.save(index)

        unknown_entries = [
            entry for entry in index.entries_by_address.values()
            if "unknown" in {tag.lower() for tag in entry.tags}
        ]
        for start in range(0, len(unknown_entries), 40):
            self._check()
            self._update(index, "RESOLVING_UNKNOWNS", batch=start // 40 + 1)
            self._resolve_unknowns(unknown_entries[start:start + 40], tags)
        index.dynamic_tags = tags.to_dict()

        for attempt in range(self.max_retries):
            failed = [item for item in functions if address_key(item["address"]) in index.llm_failed_entries and address_key(item["address"]) in pseudocode]
            if not failed:
                break
            before = len(failed)
            self._update(index, "RETRYING_FAILED_ENTRIES", attempt=attempt + 1, failed=before)
            for start in range(0, len(failed), self.batch_size):
                self._check()
                for entry in self._classify(failed[start:start + self.batch_size], pseudocode, index, tags):
                    index.add_entry(entry)
                index.dynamic_tags = tags.to_dict()
                FunctionIndexManager.save(index)
            if len([item for item in functions if address_key(item["address"]) in index.llm_failed_entries]) >= before:
                break

        remaining_failures = [
            item for item in functions
            if address_key(item["address"]) in index.llm_failed_entries
        ]
        index.indexed = bool(index.entries_by_address) and not remaining_failures
        index.indexing_state = "COMPLETED" if index.indexed else "PARTIAL"
        index.indexing_progress = 100
        index.batch_metadata.indexed_functions = index.size()
        index.batch_metadata.phase = index.indexing_state
        if remaining_failures:
            index.batch_metadata.last_error = f"{len(remaining_failures)} functions were not classified"
        else:
            index.batch_metadata.last_error = None
        FunctionIndexManager.save(index)
        self._update(index, index.batch_metadata.phase)
        return index
