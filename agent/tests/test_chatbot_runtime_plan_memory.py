from __future__ import annotations

import unittest

from aether_ghidra.engine import ActionStatus, MemoryPriority, MemoryStore, PlanManager


class ChatbotRuntimePlanMemoryTests(unittest.TestCase):
    def test_plan_updates_and_serialization_preserve_progress(self) -> None:
        manager = PlanManager()
        plan = manager.create_plan("Inspect program", [{"description": "Collect facts"}, {"description": "Summarize facts"}])
        first = plan.actions[0]
        manager.start_action(first)
        manager.complete_action(first, "facts collected", ["memory-1"])

        restored = plan.from_dict(plan.to_dict())
        self.assertEqual(restored.get_action(first.id).status, ActionStatus.COMPLETED)
        self.assertEqual(restored.get_action(first.id).memory_refs, ["memory-1"])
        self.assertEqual(restored.progress(), (1, 2))
        self.assertEqual(manager.get_all_memory_refs(plan), ["memory-1"])

    def test_keyword_retrieval_and_hierarchy_round_trip(self) -> None:
        store = MemoryStore(auto_reorganize=False)
        crypto = store.create_node("crypto", "key and decryption findings")
        item = store.add_memory("aes_key", "AES key schedule", "finding", MemoryPriority.HIGH, ["crypto"], node_id=crypto.id)

        matches = store.search_memories("AES crypto")
        restored = MemoryStore.from_dict(store.export_to_dict())

        self.assertEqual(matches[0].memory.id, item.id)
        self.assertEqual(restored.get_memories_by_node(crypto.id, include_children=False)[0].key, "aes_key")
        self.assertEqual(restored.get_statistics()["total_memories"], 1)


if __name__ == "__main__":
    unittest.main()
