# AGENTS.md --- BinaryAnalysis

## Project intent

BinaryAnalysis is a multi-representation binary program analysis
framework. It accepts low-level binary representations and structured
decompiler representations, then uses shared program, memory, and
security analysis contracts.

## Before changing code

-   Read `CODEX_TASK.md`, `ARCHITECTURE.md`, `ACQUISITION_DESIGN.md`,
    `ENGINEERING_STANDARDS.md`, `CODEX_WORKFLOW.md`, `DECISIONS.md`,
    and the applicable milestone in `EXECUTION_PLAN.md`. For complex
    development use `TASK_SPEC_TEMPLATE.md` and check `BACKLOG.md`.
-   Inspect actual code, callers, schemas, and nested AGENTS
    instructions before editing.
-   Do not assume P1--P7 decisions or previous implementations are
    correct.
-   Do not invent paths, APIs, IDA SDK capabilities, or verification
    results.
-   Establish the repository baseline and approved task scope before
    implementation. A proposed architecture or ADR is not an approval.

## Architecture invariants

-   Frontend-specific objects must not escape adapters.
-   CTree is structured input; do not parse rendered pseudocode as
    primary semantics.
-   HIR/CIR must be serializable and frontend-independent.
-   CTree and low-level frontends share analysis engines.
-   Unsupported/partial semantics and inferred types remain explicit.
-   Keep Acquisition, Artifact, Cache, Analysis Result, and
    Debug/Evidence Artifact separate.
-   Preserve many-to-many provenance.
-   Keep RVA, IDA VA/EA, runtime VA, and file offset as distinct address
    spaces.
-   Debug inspection must not silently execute new analysis queries.
-   Do not let historical phase names dictate package boundaries.

## Engineering rules

-   Define contracts before consumers.
-   Use typed, documented public APIs and clear variable names.
-   Version serialized schemas and preserve identity semantics.
-   Avoid circular imports, hidden global state, broad exception
    swallowing, and empty abstractions without consumers.
-   Update architecture/decision/plan documents when decisions change.
-   Never claim a milestone is complete without evidence against
    acceptance criteria.
-   Freeze architecture, data contracts, and module boundaries before
    coding their consumers. Changing a frozen core contract requires an
    owner-approved Architecture Change Request.
-   For complex work, deliver a bounded end-to-end vertical slice across
    its actual input, persistence, analysis, result, and evidence path.
    A class, function, file, or local test alone is not completion.
-   After two targeted changes fail the same acceptance issue, stop
    patching and document a root-cause analysis before further edits.
-   Codex may report IMPLEMENTED, VERIFIED, or REVIEWED with evidence;
    only the project owner sets APPROVED.

## Work protocol

Baseline → approved task/gates → inspect → plan → one bounded vertical
slice → system verification → architecture review → update docs/log.
Default: Codex does not commit or push; the project owner reviews and
submits. Do not cross an architecture decision boundary or start the
next milestone without owner approval. Detailed gates and status rules
are in `CODEX_WORKFLOW.md`.
