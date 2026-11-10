# AGENTS.md --- BinaryAnalysis

## Project intent

BinaryAnalysis is a multi-representation binary program analysis
framework. It accepts low-level binary representations and structured
decompiler representations, then uses shared program, memory, and
security analysis contracts.

## Before changing code

-   Read `CODEX_TASK.md`, `ARCHITECTURE.md`, `ACQUISITION_DESIGN.md`,
    `ENGINEERING_STANDARDS.md`, and the approved milestone in
    `EXECUTION_PLAN.md`.
-   Inspect actual code, callers, schemas, and nested AGENTS
    instructions before editing.
-   Do not assume P1--P7 decisions or previous implementations are
    correct.
-   Do not invent paths, APIs, IDA SDK capabilities, or verification
    results.

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

## Work protocol

Inspect → plan → implement one bounded vertical slice → verify → review
diff → update docs → commit. Do not cross an architecture decision
boundary without owner approval.
