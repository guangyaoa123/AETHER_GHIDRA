---
name: whole-binary-annotation
description: "Perform exhaustive, resumable whole-binary annotation in Ghidra through the AETHER MCP: examine every function, preserve reliable symbols and libraries, apply language-aware names and confidence comments, recover high-confidence structures and fields, and track all coverage in PROGRESS.md. Runs autonomously end-to-end without asking for confirmation. Use this skill whenever the user asks to annotate an entire executable, rename all functions, recover all structs/classes, clean up a whole Ghidra program, continue a partially annotated binary, or achieve maximum safe reverse-engineering coverage, even if they do not explicitly say 'whole-binary annotation.'"
compatibility: Requires the AETHER Ghidra MCP and an open or importable Ghidra Program.
---

# Whole-Binary Annotation

Annotate the complete binary, not only interesting entry points. 
Work in bounded, resumable batches. After each batch, continues work on your own, do not stop or wait for user input until everything is completed.  
Prefer evidence-backed names and types; use conservative generic annotations when evidence is insufficient.

## Non-Negotiable Rules

- Run autonomously. Do not ask for confirmation or stop because a name is ambiguous, a single edit fails, indexing fails, or a provider is unavailable.
- The only early stopping conditions are: no open or importable Program, auto-analysis never completes, or the backend rejects every write. Record the exact blocker and next action in `PROGRESS.md`.
- Use exact structured addresses for functions and locations. Names are discovery labels, never identities.
- Never claim completion while a pending function, structure, verification, or indexing action remains.
- When the main agent becomes idle, the OpenCode review gate runs the configured read-only reviewer; do not bypass its verdict before producing a final response.

## Progress and Resumption

Create `PROGRESS.md` in the task workspace before the first mutation. If it exists, read it before querying Ghidra and resume its pending work. Use [references/progress-template.md](references/progress-template.md) as the schema.

`PROGRESS.md` is the authoritative resume ledger. Record:

- binary identity, hashes, language, compiler, `program_id`, and analysis/RTTI/index state;
- exact discovered, examined, annotated, preserved, deferred, and pending counts;
- one disposition row for every function and structure candidate;
- the current phase, last completed batch, and an exact `Next Action` resume pointer;
- failures, namespace collisions, unresolved evidence, and the next workaround.

Checkpoint before and after every execution window, after every failed edit,
before a long provider or index request, and before ending a session. Do not
paste full pseudocode into the ledger. Keep notes short enough that another
agent can resume immediately.

If context is getting large or the session may end, finish the current safe
window, update `Last Completed Batch`, `Next Action`, counts, and pending
queues, then stop only after recording the checkpoint. A later run must read
that pointer, verify the same binary identity, and continue rather than start
over.

## Phase 1: Initialization

1. List AETHER sessions and the open project.
2. Open the requested Program by stable `program_id`, or import the binary.
3. Wait for Ghidra auto-analysis and RTTI recovery to complete. Never mutate while analysis is active.
4. Read Program metadata and identify language/toolchain from executable metadata, symbols, RTTI, vtables, exception data, package paths, and imported APIs.
5. Record the identity and readiness state in `PROGRESS.md`.
6. Do not start function indexing yet. Index only after annotation and verification.

If RTTI/class data is missing, record that limitation and continue with paged
function and structure inspection.

## Phase 2: Complete Inventory of Functions/Structs

Enumerate every function with paged `list_functions` in stable address order.
Use `include_call_relationships` only when call-graph evidence is needed.
Record every function as one of:

- reliable debug-symbol function;
- import or external;
- compiler, language-runtime, or recognized library function;
- thunk or forwarding wrapper;
- application function requiring annotation;
- RTTI deduced class functions;
- Any other undetermined default-named functions;

Only application function requiring annotation, RTTI deduced class functions and undetermined default-named functions  will be passed to Phase 3.

Also inventory native structures, class-backed structures, RTTI classes,
inheritance, vtables, constructors, destructors, allocators, deallocators,
globals, repeated base-pointer offsets, and functions sharing an apparent
object.

All class and structs will be passed to phase 3.

Choose work in this order unless evidence says otherwise: entry point and
`main`, RTTI anchors, call-graph hubs and evidence-rich functions, then the
remaining functions grouped by object, class, or subsystem. Write complete
counts and pending queues before applying annotations.

## Phase 3: Annotation
You are look at decompiled code that may contain inaccuracy. Your job in this phase is to use the tools at your disposal to improve the decompilation output. This includes, but not limited to, renaming function/variables (both local and global), re-constructing class/structs, updating function definition and setting comments.

### Naming Rules

Follow the binary's established style, but apply these rules strictly:

- Preserve reliable debug, import, runtime, canonical library, and trivial thunk names unless strong contrary evidence exists.
- The default name for functions starts with FUN_. Default name for vtable function follows: Class::vfunctionXX. You should overwrite any function with default names
- For C and C++, namespace separators are always `::`. Never encode a namespace hierarchy with underscores. Use `std::list::get`, never `std_list_get`; use `Namespace::Class::method`, never `Namespace_Class_method`.
- `rename_function` accepts qualified names and creates the namespace hierarchy. If a qualified rename returns `already_exists` or `namespace_failed`, keep the `::` hierarchy, choose a distinct evidence-based base name, and record the collision. Never retry by converting `::` to `_`.
- Rename every default-named parameter and local (`param_N`, `local_XX`, `in_XX`, `unaff_XX`) with an evidence-based name via `rename_variable`, identified by its exact function address. Never rename auto-parameters or names proven by reliable symbols; if a default name must remain, record the reason. Use `retype_variable` alongside renaming when evidence supports a precise type.
- Use class-qualified names only when RTTI, vtables, a typed receiver, constructors/destructors, or exclusive object ownership supports the relationship. A partially understood helper may use `Class::role_<address>`.
- For Go, preserve reliable package, receiver, runtime, wrapper, and ABI symbols. Rename unnamed Go application functions only with Go-specific evidence.
- For ambiguous application functions, use a useful generic name such as `unknown::handler_<address>`, `process_object_<address>`, `update_state_<address>`, or `Class::unknownMethod_<address>`.
- Use exact addresses for all renames. Add confidence labels to function comments, never to names.

Every confidence comment should use:

```text
[Confidence: high|medium|low]
Purpose: <concise behavior and context>.
Evidence: <specific calls, strings, constants, fields, callers, or RTTI evidence>.
```

### Comments

Every annotated application function carries two comment layers:

- Function level: the confidence comment above, set with `set_function_comment`.
- Code level: comments on exact code units with `set_code_unit_comment`, using
  the address prefixes in `get_function`'s `code` lines to pick locations. Add
  `eol` comments for short notes and `pre` comments for multi-line context at
  evidence-bearing call sites, notable constants and strings, structure-field
  accesses, and non-obvious branches or loops. Skip trivial wrappers and thunks.
- Keep code comments factual and short (`session nonce`, `length from header`).
  Never duplicate the function comment. A function whose code has no
  evidence-bearing address may omit code comments; record that in the ledger.

Library/Utility Functions only require function level comments

### Evidence and Definitions

For each application function, inspect `get_function` result:
metadata, address-aware `code`, and compact `calls`. Use `call_site` with the
parent function address when resolving a call. Inspect callers, callees,
xrefs, constants, strings, error paths, object offsets, and class metadata as
needed. Do not rename solely because of a similar body, nearby address, or
vtable slot.

Correct definitions only with call-site evidence, preferably from two or more
callers. Check parameter count and widths, return-value use, calling
convention, stack cleanup, varargs patterns, `this` typing, and wrapper
agreement. Use `update_function_definition` with the complete ordered
parameter list. Omit storage unless custom storage is proven. Re-read the function and representative callers after a
correction; revert or document changes that reduce coherence.

### Structures and Classes

If there are evidence of a struct pointer in a function, you must create a new struct/class or find an appropriate existing struct and apply to the variable/parameter.

Recover fields only from stable base-pointer and offset evidence correlated
across constructors, methods, cleanup paths, and callers. Retype local/global
 variables to propagate datatype when evidence supports. Use RTTI and vtables
for inheritance and `this` types. Create or update structures without overlap
or truncation. Apply semantic names and precise types only with high
confidence; otherwise use narrow primitives or names such as `field_0x28`.
Do not infer pointers, enums, ownership, array lengths, or nested structures
from naming intuition. Re-decompile representative methods after structural
changes and reject incoherent layouts.

### Bounded Execution

Use planning batches of roughly 10-30 application functions or one cohesive
class/subsystem. Fetch and reason about evidence in execution windows of at
most 5-10 functions because `get_function` includes pseudocode. Annotate each
window before fetching the next; do not re-fetch unchanged functions.

For each window:

1. Select exact pending addresses from `PROGRESS.md`.
2. Gather evidence and decide function names, parameter/local renames, code-level comments, definitions, and data structure changes.
3. Re-read affected functions and structures to verify the live result.
4. Record every disposition, failure, count, and the next exact queue in `PROGRESS.md`.


Do not hold hundreds of speculative mutations in context. Continue through all
pending windows and batches. If a mutation fails, preserve the failure and
work around it; do not abandon the batch.

### Refinement

After first-pass coverage reaches every function:

- revisit low-confidence and generic functions using the named call graph;
- revisit constructors and methods after structure typing improves code;
- correct remaining undefined-heavy definitions only with call-site evidence;
- check virtual families for consistent names;
- identify statically linked libraries exposed by new evidence;
- ensure every default-named application function is renamed or explicitly preserved with a reason;
- ensure every structure candidate has applied fields or a documented blocker.

Continue until a full pass produces no evidence-backed improvement.

## Phase 4: Final Verification

Do not trust the ledger alone; the live Program is the source of truth.

1. Re-enumerate all functions with paged `list_functions`.
2. Flag every default-named application function (`FUN_`, `SUB_`, and equivalents). Preserve only thunks/runtime stubs with recorded reasons.
3. Confirm every application function has an evidence-based or conservative annotation and confidence comment, or a recorded preservation reason.
4. Confirm non-trivial annotated functions carry code-level comments at their evidence-bearing addresses, not only the function comment.
5. Scan renamed C/C++ functions for underscore-encoded namespaces, especially `std_*` and `Class_method` patterns. Correct them to `std::...` or `Class::...` when evidence supports the hierarchy; never leave a namespace defect unrecorded.
6. Re-list structures/classes and confirm every candidate was reviewed, applied, or documented as blocked.
7. Re-check corrected definitions against live call sites.
8. Reconcile every count, disposition, and pending queue with the live results. Fix discrepancies and repeat until clean.
9. Record the verification result and timestamp, then set Phase to `complete` only when no pending annotation or verification work remains.
10. Do not report completion until the annotation gate records a `completed` reviewer verdict for this final state.

## Post-Completion Indexing

Only after the Completion Gate, start or resume the whole-program function
index. Poll its job, record the job ID and progress in `PROGRESS.md`, and run
a sample search after success. If indexing fails because of credentials or a
provider issue, record it as a pending follow-up without claiming the
annotation itself is incomplete.

## Completion Gate

`PROGRESS.md` must demonstrate:

- every discovered function has a disposition;
- every application function is semantically or conservatively annotated;
- annotated functions carry function-level confidence comments plus code-level comments at evidence-bearing addresses, and no default-named non-auto variable remains without a recorded reason;
- reliable symbols, libraries, runtimes, Go symbols, and thunks obey preservation policy;
- no renamed function encodes a namespace with underscores;
- every structure/class candidate was reviewed and high-confidence fields were applied;
- corrected definitions were re-verified against call sites;
- no pending batch or verification action remains;
- final live-program reconciliation is clean and timestamped;
- the annotation reviewer returned `completed` and that verdict is recorded with a timestamp;
- indexing was started/resumed after completion, or its failure is recorded as a follow-up.

Keep `PROGRESS.md` accurate enough for another agent to resume without a narrative handoff.
