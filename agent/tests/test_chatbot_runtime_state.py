from __future__ import annotations

import unittest

from aether_ghidra.engine import FunctionTool, MultiAgentRuntime


class ChatbotRuntimeStateTests(unittest.TestCase):
    def test_agents_exchange_messages_and_keep_isolated_state(self) -> None:
        runtime = MultiAgentRuntime()
        seen: list[tuple[str, str]] = []

        def sender(agent, message, ctx):
            if message.topic != "start":
                return
            ctx.tools["context"].set(ctx, "phase", "sent")
            ctx.send("receiver", "ping", topic="ping")

        def receiver(agent, message, ctx):
            if message.topic != "ping":
                return
            seen.append((message.content, ctx.tools["context"].get(ctx, "phase", "unset")))
            ctx.reply(message, "pong", topic="pong")

        runtime.create_agent("sender", sender)
        runtime.create_agent("receiver", receiver)
        runtime.send("system", "sender", "start", topic="start")

        self.assertEqual(runtime.run(), 3)
        self.assertEqual(seen, [("ping", "unset")])
        self.assertEqual(runtime.get_agent_context("sender"), {"phase": "sent"})
        self.assertEqual([item.topic for item in runtime.history], ["start", "ping", "pong"])

    def test_mandatory_tools_and_custom_tool_are_available(self) -> None:
        runtime = MultiAgentRuntime()
        result: dict[str, object] = {}

        def uppercase(ctx, value: str) -> str:
            return value.upper()

        def handler(agent, message, ctx):
            result["names"] = ctx.tools.names()
            result["value"] = ctx.tools["uppercase"].invoke(ctx, message.content)
            ctx.tools["memory"].remember(ctx, {"type": "finding", "result": "parser found"})

        runtime.create_agent("worker", handler, tools=[FunctionTool("uppercase", uppercase)])
        runtime.send("system", "worker", "hello")
        runtime.run()

        self.assertEqual(result["names"], ["context", "memory", "planning", "uppercase"])
        self.assertEqual(result["value"], "HELLO")
        memories = runtime.get_agent_memory_store("worker").search_memories("finding")
        self.assertEqual(len(memories), 1)


if __name__ == "__main__":
    unittest.main()
