# PROGRESS.md Template

Use one section per binary. Preserve completed history when resuming.

```markdown
# Whole-Binary Annotation Progress

## Binary Identity
- Program: <name>
- Program ID: <stable project-domain path>
- Executable: <path>
- SHA-256: <hash>
- Format / Architecture: <value>
- Detected Language / Compiler: <value and evidence>
- Analysis State: <state>
- RTTI Recovery State: <state>
- Function Index Job: <job-id or unavailable>
- Function Index State: <state and persisted percentage>
- Last Updated: <timestamp>

## Current Phase
- Phase: readiness | inventory | annotate-functions | recover-structures | refine | verify | index | complete
- Last Completed Batch: <identifier>
- Next Action: <exact resumable action>
- Blockers: <none or details>
- Annotation Order: <entry/main → RTTI anchors → hubs/evidence-rich → remaining, grouped by object/subsystem>

## Function Coverage
- Discovered: 0
- Examined: 0
- Application renamed: 0
- Application generic/low-confidence: 0
- Commented: 0
- Code comments set: 0
- Variables renamed: 0
- Definitions corrected: 0
- Debug symbols preserved: 0
- Go symbols preserved: 0
- Imports/externals preserved: 0
- Compiler/runtime preserved: 0
- Libraries preserved/canonicalized: 0
- Thunks preserved: 0
- Deferred: 0
- Pending: 0

### Function Batches
| Batch | Address Range / Group | State | Functions | Notes |
|---|---|---:|---:|---|

### Function Dispositions
| Address | Before | After | Disposition | Confidence | Evidence / Reason |
|---|---|---|---|---|---|

### Definition Corrections
| Address | Before Signature | After Signature | Signs Observed | Call Sites Verified |
|---|---|---|---|---:|

### Pending Function Queue
- <address or group>: <why it remains>

## Structure Coverage
- Candidates: 0
- Reviewed: 0
- Created: 0
- Updated: 0
- High-confidence semantic fields: 0
- Generic fields: 0
- Deferred candidates: 0
- Pending: 0

### Structure Dispositions
| Structure / Candidate | Size | State | Applied Fields | Unresolved Offsets / Evidence |
|---|---:|---|---|---|

### Pending Structure Queue
- <candidate>: <required evidence>

## Refinement Log
| Pass | Changes | Remaining Generic Functions | Remaining Unresolved Fields |
|---|---|---:|---:|

## Verification
- [ ] Every discovered function has a disposition.
- [ ] Every application function is semantically or generically annotated.
- [ ] Annotated functions have no default-named non-auto variables left without a recorded reason.
- [ ] Non-trivial annotated functions have code-level comments at evidence-bearing addresses.
- [ ] Reliable debug and Go symbols were not renamed.
- [ ] Imports, runtimes, libraries, and thunks were preserved or canonicalized.
- [ ] No renamed C/C++ function encodes a namespace with underscores instead of `::`.
- [ ] Every structure candidate was reviewed.
- [ ] No high-confidence field remains unapplied.
- [ ] Corrected function definitions still agree with their call sites.
- [ ] No pending batch remains.
- [ ] Final Program re-read matched this ledger (result: <clean | fixed>; timestamp: <value>).
- [ ] Function index started/resumed after completion (job: <id>) or failure recorded as pending follow-up (<reason>).
```
