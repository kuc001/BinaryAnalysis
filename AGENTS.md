# AGENTS.md --- BinaryAnalysis

## Project intent

BinaryAnalysis is a multi-representation binary program analysis
framework. It accepts low-level binary representations and structured
decompiler representations, then uses shared program, memory, and
security analysis contracts.

## Before changing code

-   Follow the Document Loading Policy below. Read the task's applicable
    contracts and decisions before changing code; record a Document
    Preflight for each complex development task.
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

## Document Loading Policy

For each complex development task, first read this file, `CODEX_TASK.md`,
applicable ADRs in `DECISIONS.md`, relevant `ARCHITECTURE.md` sections,
the current milestone in `EXECUTION_PLAN.md`, the task in `BACKLOG.md`,
and relevant rules in `CODEX_WORKFLOW.md` and
`ENGINEERING_STANDARDS.md`. Use `TASK_SPEC_TEMPLATE.md` for a complex
task specification; update `BUILD_LOG.md` when recording verification.
Select additional material by task:

| Task | Additional reading |
|---|---|
| F0 Project-to-CIR acquisition | `ACQUISITION_DESIGN.md`; `ARCHITECTURE.md` Project/Frontend/HIR/CIR/Provenance sections; ADR-001/002/003/004/006/008/010/012. Read `design/analysis/ANALYSIS_CORE_CONTRACT.md` identity sections only if the F0 identity boundary needs them. |
| F1 CTree/HIR | `ACQUISITION_DESIGN.md`, relevant original requirements in `archive/original-requirements/TASK_2.md`, and applicable HIR/CIR/provenance contracts. |
| C1 Alias/SSE | `design/analysis/ANALYSIS_CORE_CONTRACT.md`, `research/legacy/ALGORITHM_MIGRATION_MAP.md`, `research/legacy/LEGACY_DATAFLOW_ALGORITHM_AUDIT.md`, `research/modern/ARCHITECTURE_EXTENSIBILITY_REVIEW.md`. Read the modern paper review only for a specific optimization question. |
| C2/C3 algorithm research | Both `research/modern/` reviews and `design/analysis/ANALYSIS_CORE_CONTRACT.md`. |
| Historical/reset audit | Read `archive/` selectively when the task calls for historical provenance. |

Treat AGENTS/workflow/standards, Accepted ADR directions and applicable
approved contracts as requirements; pending design contracts are proposals,
research files are evidence, and archives describe historical state. A
research report cannot override an Accepted ADR. An unapproved proposal is
not a frozen schema. Do not reread every historical paper for each task.

At the beginning of each complex development task, briefly report a
**Document Preflight** with Task ID, Git HEAD, current milestone, documents
actually read and relevant sections, applicable ADRs, pending contracts,
historical documents not applicable, conflicts or missing references, and
scope authorization. Do not claim to have read unopened material. This is
an execution check in the conversation, not a separate report file.
