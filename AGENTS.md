# AETHER Ghidra Plugin

## Structure

- `src/main/java/aether/ghidra/` is the Ghidra extension. `plugin/` owns lifecycle and UI, `bridge/` exposes the loopback API, and `program/` is the only package that reads or mutates live Ghidra `Program` state.
- `agent/aether_ghidra/` is bundled with the extension. `api/server.py` serves the Python API; `application/runtime.py` keeps one locked chatbot session per `program_id`; `integrations/ghidra/` calls the Java bridge; `features/` contains chat and annotation workflows; `engine/` contains the domain-neutral agent runtime.
- Keep Java and Python protocol changes synchronized. Agent workflows use a backend-neutral Program gateway. The external MCP keeps at most one Project open, identifies Programs by stable Ghidra project-domain `program_id` paths, and may also expose opaque `analysis_id` handles for open Programs. Analysis handles are invalid once Ghidra closes that Program. Ghidra writes belong in `ProgramRegistry` transactions. The external MCP exposes program read and write capabilities, but not chat, memory, planning, or conversation tools.

## Commands

- The project has no Gradle wrapper. Build against the installed Ghidra distribution (Ghidra 12.1.2 and Java 21):
  ```sh
  export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC
  "$GHIDRA_INSTALL_DIR/support/gradle/gradlew" -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" buildExtension
  ```
  The installable ZIP is written to `dist/`.
- From `agent/`, create/update the locked environment and run the standard-library tests:
  ```sh
  uv sync
  uv run python -m unittest discover -s tests
  ```

## Runtime Constraints

- Enabling the plugin starts the bundled Python service automatically. Agent instances record PID metadata under `~/.config/aether-ghidra/run/` and clean it up on shutdown; stale instances whose bridge is unavailable are swept before a new agent starts. For source-checkout debugging, run `python -m aether_ghidra.api.server` from `agent/`; set `AETHER_AGENT_PYTHON`, `AETHER_AGENT_DIR`, or `AETHER_AGENT_RUN_DIR` when the automatic launcher cannot locate the intended interpreter, package, or runtime directory.
- The Java bridge is loopback-only at `127.0.0.1:8765` and intentionally has no authentication layer. Use `AETHER_GHIDRA_URL` or `AETHER_GHIDRA_PORT` only before the plugin starts for local routing. The agent defaults to `127.0.0.1:8780` and accepts `AETHER_AGENT_URL`, `AETHER_AGENT_HOST`, `AETHER_AGENT_PORT`, and `AETHER_AGENT_RUN_DIR`. The external MCP waits briefly for a GUI bridge, pauses headless auto-restore while a GUI Ghidra JVM is present, gates explicit/headless restore on the Ghidra project lock, and closes managed headless Ghidra/agent process groups when its stdin closes or it receives SIGTERM/SIGINT; `forget_project` removes a saved auto-restore entry without deleting the project.
- Agent credentials and model settings load from `~/.config/aether-ghidra/config.json` (or `AETHER_GHIDRA_CONFIG`); `OPENAI_API_KEY`, `OPENAI_MODEL`, and `OPENAI_BASE_URL` environment variables fill only settings absent from that file. Enabled chatbot tools persist separately in `~/.config/aether-ghidra/chatbot-tool-config.json`.
- The Ghidra `AETHER > Configuration` dialog writes the agent config and grouped chatbot tool policy; valid persisted GUI values take priority over environment values and restart the plugin-managed Python agent.
- Binary imports run Ghidra RTTI recovery before completing the import job; `get_analysis_status` exposes `rtti_recovery_state` while that work is active. Unified annotation runs use `Manual` or `LLM-guided` gathering, freeze gathered context before annotation, apply one atomic batch through `ProgramRegistry`, and persist inverse journals under `~/.config/aether-ghidra/annotation-history/` for conflict-safe undo. Gathering and annotation have separate capability allowlists; memory, planning, and general retrieval tools are unavailable to the workflow.
- Debug logging is opt-in: set `AETHER_GHIDRA_DEBUG=1` before launching Ghidra for Java and Python diagnostics, or set `DEBUG: true` in the agent config; Python logs can also be written with `AETHER_GHIDRA_LOG_FILE` or `LOG_FILE`. Conversation transcripts are separate JSONL output configured with `AETHER_GHIDRA_CONVERSATION_LOG_FILE` or `CONVERSATION_LOG_FILE`.
- Gradle intentionally excludes `agent/tests/`, `agent/.venv/`, and Python cache files from the extension ZIP; do not rely on those files at runtime.
