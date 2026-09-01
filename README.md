# AETHER Ghidra Plugin

This directory is a new, independent Ghidra integration. The Java extension owns live Ghidra state; the Python process owns the legacy-compatible chatbot orchestration, memory, plans, and tool loop.

The Java source is organized into `plugin/` (lifecycle and UI), `bridge/` (authenticated transport), `program/` (live Program capabilities), and `observability/`. The Python agent is organized into `api/`, `application/`, `integrations/ghidra/`, `features/`, `tools/`, `config/`, `observability/`, and the domain-neutral `engine/`.

```text
Ghidra Java plugin
  - Program lifecycle registry
  - explicit program_id routing
  - Ghidra capability wrappers and transactions
  - authenticated loopback HTTP bridge

Python agent service
  - bridge client
  - persistent per-program chatbot sessions
  - legacy-compatible native tool calling and context management
```

## Requirements

- Ghidra 12.1.2 is installed at `/opt/ghidra_12.1.2_PUBLIC`.
- Java 21 is available. No root-only package is required for the initial build.
- Python 3.12 or newer is available for the agent service.
- The agent environment has `openai` and `httpx` installed. From `agent/`, run `uv sync` or install the dependencies from `pyproject.toml`.

## Build The Extension

Run from this directory:

```sh
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC
"$GHIDRA_INSTALL_DIR/support/gradle/gradlew" -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" buildExtension
```

The extension ZIP is written to `dist/`. Install it from Ghidra's **File > Install Extensions** dialog, then enable **AETHER Ghidra bridge** in the tool configuration.

Right-click in Ghidra and open the **AETHER** submenu to analyse the selected location or open **Configuration**. GUI-saved values in `~/.config/aether-ghidra/config.json` take priority over environment variables. Saving restarts the plugin-managed Python agent; an externally running agent must be restarted separately.

The configuration dialog also controls grouped chatbot tools. Program inspection, analysis context, planning, memory, and conversation tools are enabled by default. Program mutation tools, including function, structure, and class updates, are disabled by default and must be enabled explicitly.

## Automatic Agent Startup

The Ghidra plugin starts the bundled Python service automatically when it is enabled. No separate Python command is normally required:

```sh
cd agent
python -m unittest discover -s tests
```

The Java bridge is bound to `127.0.0.1` and does not use authentication. The Python agent connects to it through `AETHER_GHIDRA_URL` when an alternate localhost port is needed.

The Java bridge defaults to `127.0.0.1:8765`; override its port before launching Ghidra with `AETHER_GHIDRA_PORT`.

The Java plugin searches for an agent-local environment, then `uv`, then system Python, and launches the service on `http://127.0.0.1:8780`.

Environment overrides:

- `AETHER_AGENT_PYTHON`: Python executable or virtual-environment interpreter.
- `AETHER_AGENT_DIR`: directory containing the `aether_ghidra` Python package when using a source checkout.
- `AETHER_AGENT_URL`: agent service URL, default `http://127.0.0.1:8780`.
- `AETHER_GHIDRA_DEBUG=1`: enable Java bridge and Python agent debug messages; set before launching Ghidra.
- `AETHER_GHIDRA_LOG_FILE`: optional Python log file path used only when `LOG_FILE` is absent from the agent config.
- `AETHER_GHIDRA_CONVERSATION_LOG_FILE`: optional JSONL transcript path for conversations sent to model endpoints.

Set `CONVERSATION_LOG_FILE` in `~/.config/aether-ghidra/config.json`, or use the environment override above, to enable a separate conversation transcript. Each line records the model, outbound messages, tool definitions, and response for one completion. API keys are never written to this file. The Ghidra configuration dialog exposes the same setting as **Conversation log file (JSONL)**.

The Python service exposes:

- `GET /v1/programs`
- `POST /v1/invoke` with `program_id`, `capability`, and `arguments`
- `POST /v1/analyze` with `program_id`, `address`, and an optional request
- `POST /v1/chat` with `program_id`, `message`, and an optional `address`
- `GET /v1/session/{program_id}` for conversation and agent state
- `POST /v1/session/clear` with `program_id`
- `POST /v1/index-jobs` with `program_id`, optional `resume`, and optional `reindex`
- `GET /v1/index-jobs/{job_id}` and `POST /v1/index-jobs/{job_id}/cancel`
- `POST /v1/index-stats` with `program_id`
- `POST /v1/index-entries` with `program_id`, optional `offset`, and optional `limit`
- `POST /v1/index-search` with `program_id` and `query`
- `POST /v1/plan` as a compatibility response for callers that only request planning metadata

## Use The Context Action

1. Open a Program in Ghidra's CodeBrowser and wait for the decompiler view to finish loading.
2. Right-click an address in either the disassembly listing or the decompiler view, open **AETHER**, and choose **Analyse selected location**.
3. The Java plugin starts Python, sends the explicit Program ID and address, and displays the agent result in Ghidra.

For interactive work, right-click an address and choose **AETHER > Chat with AETHER**. This opens a persistent dockable chat panel for the active Program. The panel restores the in-memory session, sends the selected address as context, supports clearing the session, and provides a true cancel action for running chat jobs.

For whole-program indexing, use **Window > AETHER Indexing** or right-click an address and choose **AETHER > Index / Resume Binary**. The provider displays persisted function entries in a sortable table with names, addresses, importance, categories, summaries, operations, constants, called functions, and callers. Use the filter column selector and text field to search all columns or constrain the search to a specific column. Called functions and callers are collected directly from Ghidra call references rather than generated by the LLM. The index is persisted per binary, can be cancelled and resumed, and exposes progress, statistics, dynamic tags, cached pseudocode, failed entries, and an index-backed `search_function_index` chatbot tool. **Re-index** clears the current persisted index before starting again.

For recovered C++ information, use **Window > AETHER Classes** or **AETHER > Class Information**. The provider organizes recovered classes into an inheritance hierarchy, with derived classes nested under their direct bases, while grouping each class data structure with its related vtables. Selecting a class loads its direct bases, transitive inheritance chain, fields, identified non-virtual class functions, vtables, inherited or overridden virtual-function slots, and the grouped structures. Right-click a class or any grouped structure and use **Open in Data Type Manager** to focus it in Ghidra's Data Type Manager or **Edit Type** to open Ghidra's native datatype editor. Refresh reads the analysis generated during initial analysis and RTTI recovery.

For an already analyzed C++ Program, use **AETHER > Recover C++ RTTI Classes**. AETHER also triggers this workflow automatically after initial analysis for programs supported by Ghidra's recovery script, including Windows/MSVC and GCC/Itanium programs. The workflow runs Ghidra's `RecoverClassesFromRTTIScript.java`, then runs the AETHER RTTI Inheritance analyzer and refreshes the class provider. The menu action remains available to retry recovery, and the equivalent headless script is `AetherRecoverClassesAndAnalyze.java`.

To annotate, choose **AETHER > Annotate with AETHER...**. Select **Manual** to choose functions from the bounded call tree, or **LLM-guided** to let the model select relevant functions from that same frozen candidate set. In Manual mode, **Select all default-named** selects every function still carrying Ghidra's default symbol name in the displayed call graph; the root remains selected because it is always part of the context. The LLM-guided gatherer receives candidate metadata once plus deterministic compact pseudocode sketches; declarations, comments, duplicate statements, and low-value formatting are removed before selection. It asks the LLM for a focused but slightly broad set, encouraging inclusion of relevant default-named functions at deeper call-graph levels without selecting runtime/library helpers solely to increase the count. Gathering and annotation are separate phases: gathering may use only call-tree/context capabilities, while annotation receives the user's analysis guidance followed by compact pseudocode only. Pseudocode lines with available provenance are prefixed with one or more `0x...` instruction addresses; lines without a corresponding address are preserved unchanged and are not mutation targets. Existing function and code-unit comments are embedded at their known addresses. The model can call six mutation tools (`rename_function`, `rename_variable`, `retype_variable`, `update_function_definition`, `set_function_comment`, and `set_code_unit_comment`). Function-definition updates replace the complete ordered parameter list, support return-type changes and varargs, use the identified calling convention when storage is omitted, and accept explicit register or stack storage for custom layouts. Auto-parameters are preserved automatically during full definition updates and may be retyped, but cannot be renamed, removed, or moved to another storage location. `rename_function` applies immediately; the other mutations commit as one atomic batch. Successful changes are recorded under `~/.config/aether-ghidra/annotation-history/`. Memory, planning, and general retrieval tools are not available to this workflow. Use **AETHER > Undo last annotation** to restore the previous values. Annotation writes are disabled by default and must be enabled in **AETHER > Configuration**.

For source-checkout development, the service can still be started manually from `agent/` with `python -m aether_ghidra.api.server`.

## Headless Mode

Headless mode uses the same `ProgramRegistry`, `BridgeServer`, and Python agent as the GUI plugin. The interface is a Ghidra script that owns the current headless `Program` instead of a `PluginTool`.

Run the long-lived headless bridge against an imported Program:

```sh
export AETHER_GHIDRA_PORT=8765
export AETHER_AGENT_URL=http://127.0.0.1:8780
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
  -process "/popcapgame1.exe" -noanalysis \
  -scriptPath "$GHIDRA_AETHER_DIR/ghidra_scripts" \
  -postScript AetherHeadlessScript.java
```

While that process is running, use `GET /v1/programs` to obtain the session-scoped `program_id`, then submit annotation jobs through `POST /v1/annotation-jobs`. The headless smoke script `AetherAnnotationSmoke.java` exercises call-tree gathering, pseudocode context, an atomic comment write, and restoration of the original comment.

To test indexing headlessly with the included fixture, create/import a temporary project and keep the bridge alive:

```sh
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC
export AETHER_GHIDRA_PORT=8878
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /tmp/opencode aether-index-api \
  -import "$PWD/testdata/index_fixture/bin/index_fixture" \
  -scriptPath "$PWD/ghidra_scripts" \
  -postScript AetherHeadlessScript.java
```

While it runs, query `GET http://127.0.0.1:8878/v1/programs` for the `program_id`, then use the agent API on port `8780`:

```sh
curl -s http://127.0.0.1:8780/v1/index-stats \
  -H 'Content-Type: application/json' \
  -d '{"program_id":"<PROGRAM_ID>"}'
curl -s http://127.0.0.1:8780/v1/index-jobs \
  -H 'Content-Type: application/json' \
  -d '{"program_id":"<PROGRAM_ID>","resume":true}'
```

The fixture and its expected symbols are documented in `testdata/index_fixture/README.md`. A real indexing run requires the configured LLM credentials; `index-stats` and `index-search` are safe checks before starting one.

Set `OPENAI_API_KEY` and optionally `OPENAI_BASE_URL` and `OPENAI_MODEL` before starting Ghidra, or write them to `~/.config/aether-ghidra/config.json`. The provider uses the legacy transport behavior: OpenAI-compatible requests, a 600-second timeout, and disabled TLS certificate verification.

For debugging, set `DEBUG` to `true` and optionally `LOG_FILE` in `~/.config/aether-ghidra/config.json`, or use the environment variables above. Application logs include request routes, program IDs, capabilities, durations, tool names, and result sizes. Annotation jobs additionally report flow stages, progress, LLM rounds, model tool calls, bridge calls, operation counts, and total elapsed time in the Ghidra console when the managed Python agent is running. Conversation bodies are written only to the separate JSONL transcript when configured. Both local services report protocol version `2` in their health responses.

## External MCP Server

External agents can connect to the standalone MCP server over stdio:

```sh
cd agent
uv run python -m aether_ghidra.api.mcp_server
```

At MCP initialization, AETHER first probes the existing interactive bridge. If it is unavailable, it starts an empty managed headless runtime with no loaded Program. `list_programs` returns an empty list while the runtime is ready; Program-scoped tools return an actionable `no_program_loaded` error until the agent creates or opens a project and imports a binary. The initialization response and `list_analysis_sessions` report the startup state and job.

The MCP server exposes one backend-independent Ghidra surface with at most one open Project. It uses the active interactive Project when available and otherwise owns one managed headless Project. Use `create_project` for a new workspace or `open_project` for an existing `.gpr`/`.rep` Project; both open it immediately. `list_open_project` reports that Project, and `list_programs` enumerates every stored Program without opening closed Programs. `open_program` and `close_program` control individual Programs by their stable Ghidra project-domain path, such as `/folder/client.exe`. `close_project` takes no arguments, verifies saves for all open Programs, and only then stops the managed backend.

Project persistence records only the `.gpr` path in `~/.config/aether-ghidra/mcp-projects.json` (override with `AETHER_MCP_PROJECT_MANIFEST`), and the most recently used saved Project is restored on the next MCP session. `import_binary` imports into the open Project; if none is open, it creates a unique temporary Project under `AETHER_MCP_PROJECT_DIR` (default `/tmp/aether-ghidra-projects`). Poll `get_import_job` until analysis and RTTI recovery complete. Program tools accept the stable `program_id`; opaque `analysis_id` handles remain available for clients that use broker handles. Managed headless sessions remain alive until their Project or analysis session is explicitly closed, or the MCP server shuts down. The startup timeout only bounds readiness checks and does not expire a ready session. The MCP surface excludes chat, conversation, memory, and planning tools while exposing Program reads and writes.

After import, `get_analysis_status` reports whether Ghidra auto-analysis is still running and includes `rtti_recovery_state` while import-time C++ class recovery is running or has completed. The import job completes after that recovery barrier when the installed bridge supports the status field. Function indexing is asynchronous; `get_function_index_job` always returns a structured `progress` object with phase, state, percentage, indexed count, total count, current function, and message.

## Initial Capabilities

- `get_program_metadata`
- `get_analysis_status`
- `list_functions`
- `get_function`
- `get_function` (returns function metadata plus address-aware pseudocode and resolved calls)
- `get_data_at_address`
- `get_xrefs_to`
- `rename_function`
- `rename_variable`
- `set_function_comment`
- `set_code_unit_comment`
- `get_function_call_tree`
- `get_annotation_context`
- `apply_annotation_batch`
- `list_struct` and `get_struct` (plain structures and class-backed structures, including available inheritance metadata)
- `create_struct`, `add_fields`, `update_fields`, `remove_fields`, and `resize_struct`
- `create_class`, `update_class`, and `delete_class`

During initial analysis or import, AETHER runs Ghidra's `RecoverClassesFromRTTIScript.java` and then runs **AETHER RTTI Inheritance** after reference analysis. The same workflow runs for GUI programs, headless MCP imports, and interactive bridge imports; the existing **AETHER > Recover C++ RTTI Classes** action remains available to rerun it manually. Recovery follows the compiler and architecture support provided by Ghidra, including 32/64-bit Windows/MSVC and GCC/Itanium programs. The analyzer consumes Ghidra's applied RTTI models and recovered class data types to persist direct and transitive inheritance, base-subobject offsets, vtables, and parent/child virtual-function slot relationships. `get_struct` reads this analysis output; it does not trigger RTTI parsing.

Program operations use stable Ghidra project-domain `program_id` values. Open Programs also receive optional opaque broker `analysis_id` handles, which are invalidated when the backing session or Program closes. Function-targeting MCP tools accept an exact structured `address`; returned function metadata also uses `address` as its sole identity field. Writes are serialized per Program and run inside Ghidra transactions. Function, variable, definition, and comment writes can be issued individually or as an atomic `apply_annotation_batch`; structure and class writes apply immediately. Class metadata is stored with the Program and references native Ghidra structures. RTTI is consumed from Ghidra's existing analysis output rather than exposed as a separate AETHER tool.
