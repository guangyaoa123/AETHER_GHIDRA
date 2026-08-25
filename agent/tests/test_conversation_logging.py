from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aether_ghidra.observability.conversation_logging import ConversationLogger


class Message:
    def __init__(self) -> None:
        self.role = "assistant"
        self.content = "Use the rename tool."


class Response:
    choices = [type("Choice", (), {"message": Message()})()]


class ConversationLoggingTests(unittest.TestCase):
    def test_writes_separate_jsonl_transcript_without_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "conversations.jsonl"
            logger = ConversationLogger(path=path)
            logger.record_completion(
                "chat",
                {
                    "model": "test-model",
                    "messages": [{"role": "user", "content": "Rename the function."}],
                    "tools": [{"type": "function", "function": {"name": "rename_function"}}],
                },
                Response(),
            )
            record = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(record["source"], "chat")
        self.assertEqual(record["messages"][0]["content"], "Rename the function.")
        self.assertEqual(record["response"]["content"], "Use the rename tool.")
        self.assertNotIn("api_key", record)

    def test_disabled_logger_does_not_create_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "conversations.jsonl"
            logger = ConversationLogger(config={})
            logger.record_completion("chat", {"messages": []})
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
