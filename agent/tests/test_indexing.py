from __future__ import annotations

import json
import tempfile
import threading
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from aether_ghidra.features.indexing.indexer import FunctionIndexer, address_aliases
from aether_ghidra.features.indexing.model import FunctionEntry, FunctionIndex
from aether_ghidra.features.indexing.search import search_index
from aether_ghidra.features.indexing.taxonomy import DynamicTagManager


class IndexingTests(unittest.TestCase):
    def test_address_aliases_normalize_common_llm_forms(self) -> None:
        aliases = address_aliases({"space": "ram", "offset": "00101230"})
        self.assertIn("ram:00101230", aliases)
        self.assertIn("ram:101230", aliases)
        self.assertIn("0x101230", aliases)

    def test_classifier_matches_hex_address_alias(self) -> None:
        response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(tool_calls=[
            SimpleNamespace(function=SimpleNamespace(arguments=json.dumps({
                "name": "entry",
                "address": "0x101230",
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
        index.add_entry(FunctionEntry("resolver", "ram:2000", {"MEDIUM", "network:dns"}, "Resolves DNS names"))
        result = search_index(index, "dns")
        self.assertIn("resolver", result)


if __name__ == "__main__":
    unittest.main()
