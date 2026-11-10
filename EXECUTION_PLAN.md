# BinaryAnalysis execution plan — A2 proposal

2026-11-10. Milestones are bounded approval gates, not P1–P7 package boundaries. A2 is a committed design proposal; all ADRs remain Proposed. B0 was requested as preflight only. The governance enhancement is documentation-only and does not approve B1 migration, B2 deletion or B3 CLI/packaging changes. Stage descriptions below are plans, not completion claims.

## Status ledger

Use only `NOT_STARTED`, `PLANNED`, `IN_PROGRESS`, `BLOCKED`, `IMPLEMENTED`, `VERIFIED`, `REVIEWED`, `APPROVED`. Meanings, transitions and gate evidence are defined in `CODEX_WORKFLOW.md`. `IMPLEMENTED` records a deliverable, not acceptance. Only the project owner may set `APPROVED`; proposed ADRs and a Git commit do not imply approval. Update this ledger with evidence links whenever status changes.

| Milestone | Status | Evidence / next gate |
|---|---|---|
| A | IMPLEMENTED | `REPOSITORY_AUDIT.md`; owner review remains unrecorded |
| A2 | IMPLEMENTED | `ARCHITECTURE.md`, `ACQUISITION_DESIGN.md`, `DECISIONS.md`; ADR-001–012 remain Proposed |
| B0 | IMPLEMENTED | `RESET_MANIFEST.md` and audit/plan revisions; owner review of manifest remains |
| B1 | NOT_STARTED | Needs approved B1 task spec, reset scope and relevant ADRs |
| B2 | NOT_STARTED | Needs B1 evidence, per-file deletion approval and protected-data review |
| B3 | NOT_STARTED | Needs B2 evidence and applicable C/D contracts |
| C | PLANNED | Depends on approved architecture/data-contract boundaries |
| D | PLANNED | Depends on C contract gate |
| E | PLANNED | Depends on C/D and target IDA compatibility |
| F | PLANNED | Depends on E and shared memory contract |
| G | PLANNED | Depends on F and security policy contract |
| H | PLANNED | Depends on D–G and verification policy |

The task queue and task-level dependencies are in `BACKLOG.md`; exact commands, results and skipped checks belong in `BUILD_LOG.md`. The seven gate names and their entry/exit criteria are in `CODEX_WORKFLOW.md`. A milestone may have IMPLEMENTED documentation while its design gate is still pending owner decision.

## A — Repository audit

Goal: inspect production code, imports, schemas, CLI, scripts/tests dependencies and classify value. Input: current checkout and product requirements. Output: `REPOSITORY_AUDIT.md` with facts, inference, recommendations and limits. Acceptance: key paths traced to code and unresolved decisions listed. Current audit exists but is not owner-approved; A2 corrects stale findings. Risk: static inspection misses runtime/external CI behavior. Document: audit and decision register.

## A2 — Architecture Decision & Design Freeze

Goal: independently verify A evidence and specify HIR/CIR, CTree export, memory, provenance, confidence and acquisition/result boundaries. Input: A audit, source code, TASK_1/2, product and engineering constraints. Output: revised `REPOSITORY_AUDIT.md`, `ARCHITECTURE.md`, `ACQUISITION_DESIGN.md`, `DECISIONS.md`, this plan. Modules inspected: CIR/wire, core contracts/identity, frontends/FunctionStore, memory, dataflow/alias/demand/taint, orchestration, CLI, scripts and packaging. Risk: deployed IDA API/version unknown and proposed schema not yet exercised. Acceptance: A/B HIR/CIR comparison, explicit HIR/CIR/memory/provenance contracts, ADR-001–012 Proposed, B–H dependencies and gates, source-backed corrections. Verification: static reads and doc/diff review only; **no tests, code changes, commit or push**. Exit: owner reviews and explicitly approves or requests revisions. Until then B is blocked by governance, not by technical progress.

## B0 — Repository Reset Preflight (current, documentation only)

Goal: turn the A/A2 audit into a file-by-file reset decision. Input: current checkout, A2 proposal, script/test/output inventory and call sites. Output: `RESET_MANIFEST.md`, corrected audit, architecture/acquisition clarifications and this plan. Dependencies: A2 design available for review; no ADR is self-approved. Modules inspected: `scripts/*`, `tests/*`, generated roots, CLI, solver, FunctionStore, entrypoints. Risk: unseen external CI or user data. Acceptance: every script/test file classified, production consumers and prerequisites recorded, protected data named, no deletion or code edit. Document: six B0 documents. Exit: owner reviews manifest and authorizes a specific B1 scope.

## B1 — Production script dependency migration

Goal: make current supported execution independent of `scripts/` without changing approved semantics. Input: owner-reviewed B0 manifest, decisions on legacy mode/verification, approved contracts. Output: package-owned write guard and solver worker, source fingerprint replacement, optional legacy adapter; compatible acquisition producer or explicit retention of `p7_acquire.py` until D. Dependencies: B0 approval and relevant ADR approval. Modules: CLI, solver process port, application/acquisition adapters, script callers. Risk: broken subprocess protocol, legacy behavior or FunctionStore input production. Acceptance: approved replacement cases verify each migrated call path and receipt; no supported path references a removed script; old generator remains until replacement validated. Document: migration mapping, decisions and build evidence. Exit: owner approves exact B2 deletion list.

## B2 — Historical tests/scripts/output cleanup

Goal: remove approved old harness/files only after functionality and semantic requirements survive. Input: B1 evidence, new-contract scenario specifications, owner-approved per-file targets and data backup/hash manifest. Output: bounded removal of approved scripts/tests/generated files; protected inputs retained. Dependencies: B1, and D acquisition replacement for `p7_acquire.py` if B1 did not supply one. Modules: `scripts/`, `tests/`, `.p1-work/`, `.p7-work/`, `.debug/` and references. Risk: unique evidence, hidden dynamic/CI invocation or tracked user reports. Acceptance: no production/CLI/CI/docs/dev-workflow references to removed files; replacement behaviors and fixtures verified; exact removed paths and preserved hashes recorded; no untracked user file touched. Document: executed deletion log and residual risk. Exit: owner reviews product entrypoints.

## B3 — CLI, packaging and documentation consolidation

Goal: provide coherent retained product entrypoints after B2. Input: approved contracts and B1/B2 migration evidence. Output: CLI routing to Project→Acquisition→Artifact/Cache→Frontend/HIR/CIR→analysis→debug, consistent `pyproject.toml` and current docs; retain `emtaint` import unless owner changes ADR-006. Dependencies: B2 and relevant C/D contracts where the new application path needs them. Modules: `main.py`, `emtaint/__main__.py`, `emtaint/cli.py`, packaging and docs. Risk: premature CLI promises before C/D or lost -i/-t behavior. Acceptance: documented supported commands resolve to working services, no stale phase path, packaging metadata consistent, compatibility decisions explicit. Document: CLI migration guide, decisions and verification evidence. If C/D are not ready, defer new commands rather than claim completion.

## C — Stable identities and representation contracts

Goal: freeze serializable project/function/source/HIR/CIR/provenance/confidence/address/partial contracts before consumers. Input: approved A2, representative VEX and CTree export specimens. Output: schema versions, typed identity and conversion rules, HIR v1/CIR v2, compatibility/migration adapters and contract fixtures. Dependencies: approved A2/ADRs and B1 preservation of existing producer paths; it need not wait for B2 deletion. Modules: `core/identity.py`, `core/contracts.py`, `ir/canonical/*`, frontend contracts, wire. Risks: old artifact breakage and unstable no-EA/local identity. Acceptance: round-trip across process without SDK objects; explicit unsupported and many-to-many mappings; typed address conversion; historical wire handled only through declared adapter. Document: architecture/schema/decision changes and verification evidence.

## D — Acquisition and stores

Goal: project-level multi-frontend build and reuse. Input: C contracts, project manifest, binary/metadata. Output: immutable module/function source/HIR/CIR/provenance artifacts, dependency DAG, store/cache services and explicit acquire/automatic analyze use cases. Dependencies: C, ADR-004/010. Modules: current `frontends/function_store.py`, `saved_cir.py`, `scripts/p7_acquire.py` replacement, storage/application. Risks: stale cache, races, incomplete publication, overly broad invalidation. Acceptance: exact reuse and selective invalidation, concurrent single publication, corrupt/partial/incompatible detection, crash recovery, no hardcoded firmware/P7 path. Document: acquisition schema and operational recovery guide.

## E — Frontend and HIR vertical slice

Goal: export one representative CTree function structurally, serialize/reload HIR outside IDA, lower supported subset to shared CIR; maintain existing VEX path. Input: C/D contracts and target IDA/Hex-Rays compatibility probe. Output: IDA exporter, CTree source artifact, HIR, lowering diagnostics and provenance; Microcode export contract only. Dependencies: C/D, ADR-003/007/012 and target IDA environment approval. Modules: `frontends/ida_vex`, new adapter only when consumed, HIR/CIR, provenance. Risks: API version differences, inaccurate type/layout, missing EA, unsupported opcodes. Acceptance: call target, local/array/member/pointer, control and no-EA cases preserved; unsupported footprint explicit; one CTree and VEX case feed the same CIR query contract. Document: supported-version matrix, exporter schema and coverage report.

## F — Unified program and memory semantics

Goal: reconcile high/low candidate objects and run one memory/alias/dataflow/demand pipeline. Input: E CIR/provenance and C memory contracts. Output: object/path reconciliation, byte-range overlap, MemoryVersion, CFG/CG/ICFG and summary dependencies, shared query API. Dependencies: E, ADR-001/008/011/012. Modules: `memory/*`, `graph/*`, `analysis/dataflow/*`, `analysis/aliasing/*`, `analysis/framework/*`, `solver/*`. Risks: false MustAlias, unsound strong updates, solver budget effects. Acceptance: CTree `v2[3]` and `[SP+offset]` can be related only by evidence; MayAlias stays May; partial overlap and unknown propagation observable; no frontend-specific memory engine. Document: memory contract, soundness limits, result schema and evidence.

## G — Shared security and interprocedural analysis

Goal: use F contracts for summaries, taint and vulnerability assessment across representations. Input: function CIR, graphs, memory/def-use/alias results, policies. Output: versioned summaries, taint candidates and separately validated findings with evidence dependencies. Dependencies: F and conflict policy ADR-011. Modules: `analysis/taint/*`, `analysis/bugfinder/*`, `orchestration/*`, `procedures/*`. Risks: candidate paths mistaken for vulnerabilities, callee effects lost, recursive invalidation. Acceptance: both frontend paths share algorithms; unresolved call/guard/unsupported propagates partial; changing policy invalidates security results without reacquiring; cross-function dependencies explicit. Document: policy/summary/result contracts and representative case evidence.

## H — Debugging and evaluation

Goal: make outputs inspectable and measure correctness, performance and reuse. Input: D–G artifacts/results and representative binary/decompiler scenarios. Output: read-only cross-representation inspector, address mapping, causal trace, reports, comparison/benchmark evidence and recovery observations. Dependencies: D–G, approved replacement verification policy. Modules: `analysis_debugging/*`, result storage, CLI application use cases. Risks: inspection accidentally runs queries, provenance holes, misleading negative findings. Acceptance: every finding links to stored evidence where available; ambiguous/unmapped links visible; inspection read-only; address domains distinct; verification commands/results and limitations recorded. Document: user/debug guide, build log, updated audit and plan.

Each implementation milestone starts only after its applicable architecture, data-contract and module-boundary gates and an owner-approved task scope. Implement a bounded vertical slice, verify the system path, review compliance and update decisions/docs/log. Codex does not commit or push by default; the project owner reviews and submits. This governance task stops before B1.
