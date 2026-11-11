# BinaryAnalysis execution plan — current gates and historical disposition

Baseline: `codex/architecture-reset`, HEAD `e6c1cf738f849b9bd6ad4cd40cc7c6f6fb1932aa` at DOC-CLEANUP start. `scripts/` and `tests/` are absent. ADR-001–008 and ADR-010–012 have owner-Accepted **directions**; detailed identity, schema and module contracts remain subject to freeze. ADR-009 is Proposed. `DECISIONS.md` preserves B1-GUARD cancellation and older B0/B1/B2 reasoning as history, not F0 dependencies. Only the owner may set `APPROVED` or authorize an implementation boundary.

## Status ledger

`NOT_STARTED`, `PLANNED`, `IN_PROGRESS`, `BLOCKED`, `IMPLEMENTED`, `VERIFIED`, `REVIEWED`, `APPROVED` have the meanings in `CODEX_WORKFLOW.md`. `IMPLEMENTED` describes a scoped deliverable, not owner acceptance. Historical `CANCELLED` applies to B1-GUARD only.

| Milestone | Status | Evidence / next gate |
|---|---|---|
| A / A2 | IMPLEMENTED | Repository audit and accepted ADR directions; exact C/D/E contracts and ADR-009 remain open |
| R1-A | IMPLEMENTED | `research/legacy/` audit, `main.py` hash, migration map and capability candidates; final acceptance/runtime equivalence unclaimed |
| R1-B | IMPLEMENTED | `design/analysis/ANALYSIS_CORE_CONTRACT.md`, static alias counterexample, gap matrix and C1 task spec; owner contract decision pending |
| R1-C | IMPLEMENTED | `research/modern/MODERN_SOURCE_ANALYSIS_REVIEW.md` and `research/modern/ARCHITECTURE_EXTENSIBILITY_REVIEW.md`; static owner review pending |
| F0 — Project-to-CIR Acquisition Vertical Slice | VERIFIED | Owner approved bounded decisions A–F on 2026-11-11; real Project/Input → AngrVexFrontend → CIR/CFG/Origin → immutable Artifact Store → detached reload passed the three F0 gates; owner implementation review remains pending |
| F1 — CTree/HIR preparation | PLANNED | Contract preparation and target IDA/Hex-Rays environment probe may be scoped early; no implementation or verification claim |
| C1-STORE-LOAD-ALIAS-SSE | PLANNED | First existing-CIR Store/Load→memory→alias→SSE→persisted result/evidence slice; requires owner approval of exact task and affected contract/module gates, not B1/B2 cleanup |
| C2/C3 algorithm experiments | PLANNED | Research proposals only; C1 verification and separate owner tasks required |
| C — wider representation contracts | PLANNED | Versioned CIR v2/HIR/source identity, address/provenance and compatibility freeze remain separate from C1's minimal contract |
| D — Acquisition and stores | PLANNED | Project-level source/HIR/CIR artifact/cache/result lifecycles; applicable C contracts and owner scope |
| E — CTree frontend | PLANNED | Structured exporter and HIR lowering after C/D and target IDA compatibility probe |
| F — wider unified memory/program analysis | PLANNED | Cross-frontend object reconciliation, CG/ICFG and summary iteration after relevant C/E gates; C1 is its first bounded algorithm slice using existing CIR |
| iCall recovery | NOT_STARTED | C1 dependency/evidence and callsite/CG revision contract; owner scope |
| Interprocedural summary | NOT_STARTED | Refined CG/context and memory-effect contract; owner scope |
| On-demand taint | NOT_STARTED | C1 plus summary/source/sink contracts; owner scope |
| Vulnerability evidence | NOT_STARTED | Taint candidates and independent validation/result policy; owner scope |
| H — debugging/evaluation | PLANNED | Stored read-only evidence, representative cross-frontend and performance evaluation after applicable slices |

## R1-A → R1-B → R1-C → F0 → C1 gate sequence

R1-A supplied local algorithm evidence, not a migrated code oracle. The primary historical source is `references/legacy-emtaint/dataflow`; the audited `references/legacy-emtaint/main.py` is separately hashed in `research/legacy/LEGACY_DATAFLOW_SNAPSHOT.md`. The original upstream EmTaint commit remains unknown. R1-B narrows that evidence to the first shared CIR Definition, Memory, AliasQuery, SSE and provenance/result contracts in `design/analysis/ANALYSIS_CORE_CONTRACT.md`. Its static `analysis/aliasing/query.py` path shows a possible false complete `NOALIAS` for an uninitialized pointer. R1-B changed documentation only, without approving CIR v2.

F0 delivers a real, reloadable CIR/CFG/Origin acquisition from a declared Project input and `AngrVexFrontend`. Its bounded order is Project/Input Resolver → Minimum Acquisition Service → AngrVexFrontend → CIR/CFG/Origin → Artifact Store → independent-process reload. The owner approved the exact F0 subset; `BUILD_LOG.md` records all three runtime gates and the local symlink-creation limitation. Its artifact integrity is `VALID` while CIR/CFG semantic completeness is `PARTIAL`. Full incremental cache, concurrent publication and multi-frontend fusion remain later. F1 CTree/HIR contract work and environment probe may be prepared early under separate scope; no F1 capability is complete.

C1 starts after F0 from a **hash-checked, reloadable CIR Store/Load input**, follows the versioned memory and alias decision through a shared forward/backward dependency graph, and persists a result with read-only explanation. `BACKLOG.md` contains its input/output, callers, candidate modification files, prohibited changes, ten semantic scenarios, invalidation and stop conditions. Before C1 code, the owner resolves: scope and endpoint; alias/uncertainty/guard contract; private derived v1 IDs versus durable v2 IDs; result/evidence schema and cache invalidation; representative input and verification path; module ownership. Do not infer approval of all CIR v2 or HIR fields. If a selected change crosses a frozen boundary, submit an ACR before modifying code.

R1-C used the local full papers to separate C1 semantics from later algorithms. Its proposed minimum is address alias plus independent byte overlap/coverage, deterministic artifact/revision-bound private IDs for persisted C1 results, and a verified CIR input. F0 now supplies the real hash-checked acquisition witness; `frontends/saved_cir.py` remains a CIR/Origin decoder, while the F0 artifact reader validates and reconstructs the saved CFG and provenance. This does not authorize C1. C1a supplies semantic query/evidence, C1b supplies persistence/reload/invalidation/read-only Inspector; both are required for completed C1. The possible false complete `NOALIAS` in `analysis/aliasing/query.py` remains P0. R1-C is documentation IMPLEMENTED, not C1 or CIR v2 APPROVED.

```text
R1-A local audit (IMPLEMENTED, owner acceptance pending)
  → R1-B minimal contract (documentation, owner review pending)
  → R1-C modern algorithm/extensibility review (IMPLEMENTED, owner review pending)
  → owner F0 task + affected acquisition/artifact contract freeze
  → F0 Project/Input → AngrVexFrontend → CIR/CFG/Origin → Artifact Store → Reload
  → owner C1 task + affected contract/module freeze
  → C1a semantic Store/Load/Alias/SSE query and evidence
  → C1b deterministic persistence/reload/invalidation and read-only explanation
  → owner review of evidence
  → later iCall/summaries/taint/evidence and separately scoped C2/C3 experiments
```

## Historical reset disposition

The previous plan required B1-CLI/SOLVER/LEGACY/ACQUIRE/SOURCE, B2 cleanup and B3 entry consolidation. That sequence described files and scripts already removed from this worktree and is **superseded as an execution plan**. It must not trigger guard implementation, new shims, Legacy Bootstrap restoration, old script migration or a block on F0/C1. Accepted ADR directions and B1-GUARD cancellation remain in `DECISIONS.md`; `archive/reset-2026/RESET_MANIFEST.md` and Git history are historical evidence. A newly observed live dependency is triaged from current source. `frontends/function_store.py` still has guard-era receipt expectations; a later C1 reader choice needs preflight, but F0 uses its approved minimal acquisition path.

## Later bounded milestones

**C:** Freeze durable source/HIR/CIR v2/value/definition/effect identity, many-to-many provenance, address conversions, partial semantics and v1 read compatibility with representative VEX/CTree inputs. An approved C1 private index is not the whole C milestone. Do not relabel old v1 artifacts.

**D:** F0 begins project-level Acquisition and immutable Artifact storage with real input and reload. Complete Cache, Analysis Result and Debug/Evidence stores, two-level incremental fingerprints, concurrent publication and broad invalidation need later task gates. Existing producer/reader paths require fresh source inspection. No old script restoration is implied.

**E:** Export structured CTree in a validated IDA/Hex-Rays environment, serialize HIR outside IDA and conservatively lower to the shared CIR. Preserve no-EA/unsupported and type/layout uncertainty. Microcode production remains later scope.

**F:** Reconcile high/low memory candidates and run shared CFG/dataflow/alias/demand; C1 is the first single-function Store/Load slice. Later Refined CG/ICFG and summaries require their own contracts and revisions. MayAlias is never a strong-update proof.

**Security sequence:** iCall recovery publishes candidate versus confirmed edges; interprocedural summaries carry context and memory effects; on-demand taint uses the shared dependency graph; vulnerability assessment distinguishes candidate path from validation. Each step has a separate owner task, result/evidence contract and acceptance witnesses.

**H:** Inspect stored evidence without new analysis queries; evaluate correctness, partial/failure paths, performance, reload/invalidation and cross-frontend behavior. Runtime claims require exact commands/results in `BUILD_LOG.md`. The seven gates in `CODEX_WORKFLOW.md` apply to each implementation task. No successor starts automatically after a document is written or a test passes.
