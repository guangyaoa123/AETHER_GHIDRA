from __future__ import annotations

import unittest
from unittest.mock import patch

from aether_ghidra.features.chat.agent import ChatbotAgentState
from aether_ghidra.engine import (
    BlockBuffer,
    HierarchicalRetrievalAgent,
    MemoryStore,
    OpenAILLMClient,
)
from aether_ghidra.engine.context.summarizer_agent import SummarizerAgent


class FakeCompletions:
    def __init__(self, response: str) -> None:
        self.response = response
        self.requests: list[dict[str, object]] = []

    def create(self, **request):
        self.requests.append(request)
        message = type("Message", (), {"content": self.response})()
        choice = type("Choice", (), {"message": message})()
        return type("Response", (), {"choices": [choice]})()


class FakeClient:
    def __init__(self, response: str) -> None:
        self.chat = type("Chat", (), {"completions": FakeCompletions(response)})()


class ChatbotContextFeatureTests(unittest.TestCase):
    def test_block_summary_keeps_recent_tool_exchange_intact(self) -> None:
        buffer = BlockBuffer(max_raw_blocks=3, max_tokens=10_000)
        for index in range(4):
            buffer.add_message({"role": "user", "content": f"Investigate function {index}"})
        buffer.add_message({
            "role": "assistant",
            "content": "",
            "tool_calls": [{"id": "call-1", "function": {"name": "list_functions", "arguments": "{}"}}],
        })
        buffer.add_message({"role": "tool", "tool_call_id": "call-1", "content": "Found 1 function"})

        summarized = buffer.summarize_oldest_blocks()

        self.assertEqual(summarized, 1)
        history = buffer.get_summarized_conversation_history()
        self.assertEqual(history[-2]["role"], "assistant")
        self.assertEqual(history[-1]["tool_call_id"], "call-1")
        self.assertIn("Variable Summary", history[0]["content"])

    def test_llm_retrieval_parses_scores_and_applies_threshold(self) -> None:
        client = OpenAILLMClient(
            client=FakeClient('[{"score": 0.9, "reason": "direct"}, {"score": 0.1, "reason": "weak"}]'),
            relevance_threshold=0.3,
        )

        self.assertEqual(
            client.evaluate_relevance_batch("crypto", ["AES key", "HTTP beacon"]),
            [(0.9, "direct"), (0.0, "weak")],
        )

    def test_hierarchical_retrieval_uses_llm_branch_and_memory_scores(self) -> None:
        class RetrievalModel:
            def decide_branch_priority_batch(self, query, branches):
                return [(1.0, "crypto branch")]

            def evaluate_relevance_batch(self, query, contents):
                return [(0.8, "matching memory")]

        store = MemoryStore(auto_reorganize=False)
        node = store.create_node("crypto", "decryption findings")
        item = store.add_memory("key", "AES key schedule", "finding", node_id=node.id)
        store.set_retrieval_agent(HierarchicalRetrievalAgent(store, RetrievalModel()))

        matches = store.search_memories("decrypt")

        self.assertEqual(matches[0].memory.id, item.id)
        self.assertEqual(matches[0].reason, "matching memory")

    def test_program_state_selects_llm_guided_retrieval_when_configured(self) -> None:
        with patch("aether_ghidra.features.chat.agent.load_config", return_value={
            "OPENAI_API_KEY": "secret",
            "OPENAI_MODEL": "model",
            "OPENAI_MEMORY_MODEL": "memory-model",
            "OPENAI_BASE_URL": "https://example.invalid/v1",
        }), patch("aether_ghidra.features.chat.agent.OpenAILLMClient") as llm:
            state = ChatbotAgentState("program-1", object())

        self.assertIsInstance(state.memory_store.retrieval_agent, HierarchicalRetrievalAgent)
        llm.assert_called_once_with(
            api_key="secret",
            model="memory-model",
            base_url="https://example.invalid/v1",
        )

    def test_summarizer_agent_parses_chronological_summary(self) -> None:
        fake = FakeClient('{"chronological_summary": ["Reviewed entrypoint"], "key_findings": [], "files_examined": []}')
        agent = SummarizerAgent("secret", client=fake)
        block = BlockBuffer()
        block.add_message({"role": "user", "content": "Inspect entrypoint"})

        result = agent.summarize_blocks([block.blocks[0]])

        self.assertEqual(result.chronological_summary, "Reviewed entrypoint")

    def test_manual_summary_preserves_latest_two_blocks(self) -> None:
        state = ChatbotAgentState("program-1", object())
        state.conversation_history = [
            {"role": "user", "content": "first prompt"},
            {"role": "assistant", "content": "intermediate"},
            {"role": "user", "content": "latest question"},
            {"role": "assistant", "content": "latest answer"},
        ]

        state.save_summary("fallback summary")

        self.assertIn("Analyzed 2 conversation turns", state.conversation_history[0]["content"])
        self.assertEqual(state.conversation_history[-2]["content"], "latest question")
        self.assertEqual(state.conversation_history[-1]["content"], "latest answer")


if __name__ == "__main__":
    unittest.main()
