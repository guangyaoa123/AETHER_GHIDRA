from __future__ import annotations

import json
import tempfile
import threading
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from aether_ghidra.features.indexing.indexer import FunctionIndexer, IndexCancelled, address_aliases
from aether_ghidra.features.indexing.manager import FunctionIndexManager
from aether_ghidra.features.indexing.model import FunctionEntry, FunctionIndex
from aether_ghidra.features.indexing.search import search_index
from aether_ghidra.features.indexing.taxonomy import DynamicTagManager


class IndexingTests(unittest.TestCase):
    def test_job_checkpoint_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "job.json"
            with patch.object(FunctionIndexManager, "job_path", return_value=path):
                FunctionIndexManager.save_job("sha", {"job_id": "job-1", "state": "paused"})
                with patch.object(Path, "glob", return_value=iter([path])):
                    loaded = FunctionIndexManager.load_job("job-1")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["state"], "paused")

    def test_cancellation_persists_paused_index(self) -> None:
        class CancelledBridge:
            def get_program_metadata(self):
                return {"sha256": "paused-test", "name": "fixture", "function_count": 1}

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            with patch.object(FunctionIndexManager, "path", return_value=path):
                FunctionIndexManager._cache.clear()
                indexer = FunctionIndexer("program", CancelledBridge(), cancel=threading.Event())
                indexer.cancel.set()
                with self.assertRaises(IndexCancelled):
                    indexer.run()
                saved = FunctionIndex.load(path)

        self.assertIsNotNone(saved)
        self.assertEqual(saved.indexing_state, "PAUSED")
        self.assertTrue(saved.is_resumable())

    def test_provider_request_honors_cancellation(self) -> None:
        started = threading.Event()
        release = threading.Event()
        outcome: list[BaseException] = []
        indexer = FunctionIndexer("program", object(), cancel=threading.Event())

        def request() -> object:
            started.set()
            release.wait(2)
            return object()

        def run() -> None:
            try:
                indexer._cancellable_request(request)
            except BaseException as error:
                outcome.append(error)

        worker = threading.Thread(target=run)
        worker.start()
        self.assertTrue(started.wait(1))
        indexer.cancel.set()
        worker.join(1)
        release.set()
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], IndexCancelled)

    def test_address_aliases_normalize_common_llm_forms(self) -> None:
        aliases = address_aliases({"space": "ram", "offset": "00101230"})
        self.assertIn("ram:00101230", aliases)
        self.assertIn("ram:101230", aliases)
        self.assertIn("0x101230", aliases)

    def test_classifier_matches_hex_address_alias(self) -> None:
        response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(tool_calls=[
            SimpleNamespace(function=SimpleNamespace(arguments=json.dumps({
                "function_ref": {"name": "entry", "address": {"space": "ram", "offset": "101230"}},
                "importance": "HIGH",
                "categories": "network",
                "summary": "Sends network traffic",
            })))
        ]))])
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **_: response)))
        indexer = FunctionIndexer("program", object(), cancel=threading.Event())
        batch = [{"name": "entry", "address": {"space": "ram", "offset": "00101230"}, "called_functions": ["send"], "caller_functions": ["main"]}]
        with patch.object(indexer, "_client", return_value=client):
            entries = indexer._classify(batch, {"ram:00101230": "void entry() {}"}, FunctionIndex(), DynamicTagManager())
        self.assertEqual([entry.address for entry in entries], ["ram:00101230"])
        self.assertEqual(entries[0].called_functions, ["send"])
        self.assertEqual(entries[0].caller_functions, ["main"])

    def test_empty_classifier_response_is_recorded(self) -> None:
        response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(tool_calls=[]))])
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **_: response)))
        indexer = FunctionIndexer("program", object(), cancel=threading.Event())
        index = FunctionIndex()
        batch = [{"name": "entry", "address": {"space": "ram", "offset": "101230"}, "called_functions": [], "caller_functions": []}]
        with patch.object(indexer, "_client", return_value=client):
            self.assertEqual(indexer._classify(batch, {"ram:101230": "void entry() {}"}, index, DynamicTagManager()), [])
        self.assertEqual(index.llm_failed_entries["ram:101230"]["reason"], "empty_tool_response")

    def test_classifier_does_not_fall_back_to_function_name(self) -> None:
        response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(tool_calls=[
            SimpleNamespace(function=SimpleNamespace(arguments=json.dumps({
                "name": "entry", "address": "0x101230", "importance": "HIGH",
                "categories": ["network"], "summary": "Sends network traffic",
            })))
        ]))])
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **_: response)))
        indexer = FunctionIndexer("program", object(), cancel=threading.Event())
        batch = [{"name": "entry", "address": {"space": "ram", "offset": "101230"}}]
        with patch.object(indexer, "_client", return_value=client):
            self.assertEqual(indexer._classify(batch, {"ram:101230": "void entry() {}"}, FunctionIndex(), DynamicTagManager()), [])

    def test_index_round_trips_entries_and_cache(self) -> None:
        index = FunctionIndex(stable_id="sha", program_name="sample")
        index.add_entry(FunctionEntry(
            "entry", "ram:1000", {"HIGH", "network:http"}, "Sends an HTTP request",
            ["send"], ["main"],
        ))
        index.cache_pseudocode("ram:1000", "void entry() {}")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            index.save(path)
            loaded = FunctionIndex.load(path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.entries_by_address["ram:1000"].summary, "Sends an HTTP request")
        self.assertEqual(loaded.entries_by_address["ram:1000"].called_functions, ["send"])
        self.assertEqual(loaded.entries_by_address["ram:1000"].caller_functions, ["main"])
        self.assertEqual(loaded.cached_pseudocode("ram:1000"), "void entry() {}")

    def test_resume_completion_clears_stale_cancellation_metadata(self) -> None:
        class ExistingIndexBridge:
            def get_program_metadata(self):
                return {"sha256": "resume-stale", "name": "fixture", "function_count": 1}

            def list_functions(self, **_kwargs):
                return {
                    "functions": [{
                        "name": "entry", "address": {"space": "ram", "offset": "1000"},
                        "size": 8, "library": False, "thunk": False,
                    }],
                }

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            progress: list[dict] = []
            index = FunctionIndex(
                stable_id="resume-stale", program_name="fixture", indexed=False,
                indexing_state="PARTIAL", indexing_progress=35,
            )
            index.add_entry(FunctionEntry("entry", "ram:1000"))
            index.batch_metadata.indexed_functions = 0
            index.batch_metadata.last_error = "Indexing paused by user"
            with patch.object(FunctionIndexManager, "path", return_value=path):
                FunctionIndexManager._cache.clear()
                FunctionIndexManager.save(index)
                result = FunctionIndexer(
                    "program", ExistingIndexBridge(), cancel=threading.Event(),
                    progress=progress.append,
                ).run(resume=True)

        self.assertEqual(result.indexing_state, "COMPLETED")
        self.assertEqual(result.batch_metadata.indexed_functions, 1)
        self.assertIsNone(result.batch_metadata.last_error)
        self.assertEqual(progress[-1]["state"], "COMPLETED")
        self.assertEqual(progress[-1]["progress"], 100)

    def test_legacy_index_migrates_outgoing_calls_and_drops_llm_apis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            path.write_text(json.dumps({
                "index_version": 1,
                "functions": [{
                    "name": "entry",
                    "address": "ram:1000",
                    "tags": ["HIGH"],
                    "summary": "entry",
                    "callee_functions": ["send"],
                    "called_apis": ["socket"],
                }],
            }), encoding="utf-8")
            loaded = FunctionIndex.load(path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.index_version, 2)
        self.assertEqual(loaded.entries_by_address["ram:1000"].called_functions, ["send"])
        self.assertEqual(loaded.entries_by_address["ram:1000"].caller_functions, [])
        self.assertNotIn("called_apis", loaded.to_dict()["functions"][0])

    def test_dynamic_tags_and_search(self) -> None:
        tags = DynamicTagManager()
        self.assertEqual(tags.resolve("HTTP", "entry"), "http")
        self.assertEqual(tags.resolve("network:dns", "resolver"), "network:dns")
        index = FunctionIndex(stable_id="sha", indexing_state="COMPLETED")
        index.add_entry(FunctionEntry(
            "resolver", "ram:2000", {"MEDIUM", "network:dns"}, "Resolves DNS names",
            [{"address": {"space": "ram", "offset": "3000"}, "name": "send"}],
            [{"address": {"space": "ram", "offset": "1000"}, "name": "entry"}],
        ))
        result = search_index(index, "dns")
        self.assertIn("resolver", result)
        self.assertIn('"name": "send"', result)


if __name__ == "__main__":
    unittest.main()
