# BinaryAnalysis execution plan — A2 proposal

2026-11-10. Milestones are bounded approval gates, not P1–P7 package boundaries. A2 is design only; all ADRs remain Proposed. No B work starts until the owner approves A2 and the affected architecture decisions. Stage descriptions below are **plans**, not completion claims.

## A — Repository audit

Goal: inspect production code, imports, schemas, CLI, scripts/tests dependencies and classify value. Input: current checkout and product requirements. Output: `REPOSITORY_AUDIT.md` with facts, inference, recommendations and limits. Acceptance: key paths traced to code and unresolved decisions listed. Current audit exists but is not owner-approved; A2 corrects stale findings. Risk: static inspection misses runtime/external CI behavior. Document: audit and decision register.

## A2 — Architecture Decision & Design Freeze

Goal: independently verify A evidence and specify HIR/CIR, CTree export, memory, provenance, confidence and acquisition/result boundaries. Input: A audit, source code, TASK_1/2, product and engineering constraints. Output: revised `REPOSITORY_AUDIT.md`, `ARCHITECTURE.md`, `ACQUISITION_DESIGN.md`, `DECISIONS.md`, this plan. Modules inspected: CIR/wire, core contracts/identity, frontends/FunctionStore, memory, dataflow/alias/demand/taint, orchestration, CLI, scripts and packaging. Risk: deployed IDA API/version unknown and proposed schema not yet exercised. Acceptance: A/B HIR/CIR comparison, explicit HIR/CIR/memory/provenance contracts, ADR-001–012 Proposed, B–H dependencies and gates, source-backed corrections. Verification: static reads and doc/diff review only; **no tests, code changes, commit or push**. Exit: owner reviews and explicitly approves or requests revisions. Until then B is blocked by governance, not by technical progress.

## B — Safe repository reset

Goal: remove historical phase scaffolding only after preserving supported production behavior. Input: approved A2/ADRs, script import/call map and owner verification policy. Output: package-owned probe/solver/optional legacy capabilities, removal impact record, cleaned scripts/tests/docs per approved scope; retain `p7_acquire.py` until D provides a compatible acquisition replacement or migrate its generator in B under the approved contract. Dependencies: A2, ADR-005/006/009/010. Modules: `cli.py`, `solver/process_port.py`, `scripts/*`, legacy orchestration, packaging. Risks: CLI regression, lost solver worker/fixtures, external CI references. Acceptance: no production imports/exec of **removed** scripts; agreed CLI modes run via package; new verification strategy and replacement fixtures are explicit before deletion. Document: audit, decisions, build log and migration notes.

## C — Stable identities and representation contracts

Goal: freeze serializable project/function/source/HIR/CIR/provenance/confidence/address/partial contracts before consumers. Input: approved A2, representative VEX and CTree export specimens. Output: schema versions, typed identity and conversion rules, HIR v1/CIR v2, compatibility/migration adapters and contract fixtures. Dependencies: B migration safety, ADR-001/002/008/011/012. Modules: `core/identity.py`, `core/contracts.py`, `ir/canonical/*`, frontend contracts, wire. Risks: old artifact breakage and unstable no-EA/local identity. Acceptance: round-trip across process without SDK objects; explicit unsupported and many-to-many mappings; typed address conversion; historical wire handled only through declared adapter. Document: architecture/schema/decision changes and verification evidence.

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

Each milestone starts only with explicit owner approval for its architecture boundaries. Implement a bounded vertical slice, verify it, review the diff and update decisions/docs before any permitted commit. A2 explicitly stops after documentation review.
