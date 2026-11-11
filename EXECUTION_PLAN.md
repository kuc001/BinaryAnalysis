# BinaryAnalysis execution plan — current gates and historical disposition

Baseline: `codex/architecture-reset`, HEAD `ddfbc5fccaecaf9d624600aa32c4a17ced8b300f` on 2026-11-11, clean before R1-B edits. `scripts/` and `tests/` are absent. ADR-001–008 and ADR-010–012 have owner-Accepted **directions**; their detailed identity, schema and module contracts remain subject to freeze. ADR-009 is Proposed. `DECISIONS.md` retains the B1-GUARD cancellation and older B0/B1/B2 reasoning. Those cleanup tasks are historical, not active prerequisites for new algorithm work. Only the project owner may set `APPROVED` or authorize a new implementation boundary; no Git submission is authorized by this plan.

## Status ledger

`NOT_STARTED`, `PLANNED`, `IN_PROGRESS`, `BLOCKED`, `IMPLEMENTED`, `VERIFIED`, `REVIEWED`, `APPROVED` have the meanings in `CODEX_WORKFLOW.md`. `IMPLEMENTED` describes a scoped deliverable, not owner acceptance. Historical `CANCELLED` applies to B1-GUARD only.

| Milestone | Status | Evidence / next gate |
|---|---|---|
| A / A2 | IMPLEMENTED | Repository audit and accepted ADR directions; exact C/D/E contracts and ADR-009 remain open |
| R1-A | IMPLEMENTED | Local 164-file dataflow audit plus `main.py` hash, algorithm map and allowlist; owner reviewed main direction as basically credible, final acceptance and runtime equivalence unclaimed |
| R1-B | IMPLEMENTED | `ANALYSIS_CORE_CONTRACT.md`, static alias counterexample, gap matrix and C1 task spec; static document review/owner contract decision pending |
| R1-C | IMPLEMENTED | `MODERN_SOURCE_ANALYSIS_REVIEW.md` and `ARCHITECTURE_EXTENSIBILITY_REVIEW.md`; full-text paper and current-code static review, owner review pending |
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

## R1-A → R1-B → R1-C → C1 gate sequence

R1-A supplied local algorithm evidence, not a migrated code oracle. The primary historical source is `references/legacy-emtaint/dataflow`; the audited `references/legacy-emtaint/main.py` is separately hashed in `LEGACY_DATAFLOW_SNAPSHOT.md`. The original upstream EmTaint commit remains unknown. R1-B narrows that evidence to the first shared CIR Definition, Memory, AliasQuery, SSE and provenance/result contracts in `ANALYSIS_CORE_CONTRACT.md`. Its static `analysis/aliasing/query.py` path shows a possible false complete `NOALIAS` for an uninitialized pointer. R1-B changes documentation only: no production code, tests, legacy execution or full CIR v2 approval.

C1 starts from an **existing, hash-checked CIR Store/Load input**, follows the versioned memory and alias decision through a shared forward/backward dependency graph, and persists a result with read-only explanation. `BACKLOG.md` contains the exact input/output, callers, candidate modification files, prohibited changes, ten semantic scenarios, invalidation and stop conditions. Before code, the owner resolves: C1 scope and endpoint; alias/uncertainty/guard contract; private derived v1 IDs versus durable v2 IDs; result/evidence schema and cache invalidation; representative input and verification path; module ownership. Do not infer approval of all CIR v2 or HIR fields from this smaller contract. If a selected change crosses a frozen boundary, submit an ACR before modifying code.

R1-C used the local full papers to separate immediate C1 semantics from later algorithms. Its proposed minimum is address alias plus independent byte overlap/coverage, deterministic artifact/revision-bound private IDs for any persisted C1 result, and an actually verified saved-CIR input. `frontends/saved_cir.py` exists but returns no CFG object; its report carries CFG rows requiring a bounded validation adapter. No saved new-format acquisition was found in the searched worktrees, so the owner must select or authorize a real acquisition witness. C1a supplies semantic query/evidence, C1b supplies persist/reload/invalidation/read-only Inspector; both are required for completed C1. The possible false complete `NOALIAS` in `analysis/aliasing/query.py` remains P0. R1-C is documentation IMPLEMENTED, not C1 or CIR v2 APPROVED.

```text
R1-A local audit (IMPLEMENTED, owner acceptance pending)
  → R1-B minimal contract (documentation, owner review pending)
  → R1-C modern algorithm/extensibility review (IMPLEMENTED, owner review pending)
  → owner C1 task + affected contract/module freeze
  → C1a semantic Store/Load/Alias/SSE query and evidence
  → C1b deterministic persistence/reload/invalidation and read-only explanation
  → owner review of evidence
  → later iCall/summaries/taint/evidence and separately scoped C2/C3 experiments
```

## Historical reset disposition

The previous plan required B1-CLI/SOLVER/LEGACY/ACQUIRE/SOURCE, B2 cleanup and B3 entry consolidation before later milestones. That sequence described files and scripts already removed from this worktree and is **superseded as an execution plan**. It must not trigger guard implementation, new compatibility shims, Legacy Bootstrap restoration, old script migration or a block on C1. The accepted ADR directions and the record of B1-GUARD cancellation remain in `DECISIONS.md`; `RESET_MANIFEST.md` and Git history remain historical evidence. A newly observed live dependency is triaged from current source, not assumed from the old manifest. Current `frontends/function_store.py` still has guard-era receipt expectations, so C1's chosen existing-CIR input path needs a concrete preflight and may require a bounded reader adapter; that finding does not reactivate B1/B2.

## Later bounded milestones

**C:** Freeze durable source/HIR/CIR v2/value/definition/effect identity, many-to-many provenance, address conversions, partial semantics and v1 read compatibility with representative VEX/CTree inputs. An approved C1 private index is not the whole C milestone. Do not relabel old v1 artifacts.

**D:** Build project-level Acquisition and separate immutable Artifact, Cache, Analysis Result and Debug/Evidence stores with two-level fingerprints, partial publication and invalidation. Existing producer/reader paths require fresh source inspection. No old script restoration is implied.

**E:** Export structured CTree in a validated IDA/Hex-Rays environment, serialize HIR outside IDA and conservatively lower to the shared CIR. Preserve no-EA/unsupported and type/layout uncertainty. Microcode production remains later scope.

**F:** Reconcile high/low memory candidates and run shared CFG/dataflow/alias/demand; C1 is the first single-function Store/Load slice. Later Refined CG/ICFG and summaries require their own contracts and revisions. MayAlias is never a strong-update proof.

**Security sequence:** iCall recovery publishes candidate versus confirmed edges; interprocedural summaries carry context and memory effects; on-demand taint uses the shared dependency graph; vulnerability assessment distinguishes candidate path from validation. Each step has a separate owner task, result/evidence contract and acceptance witnesses.

**H:** Inspect stored evidence without new analysis queries; evaluate correctness, partial/failure paths, performance, reload/invalidation and cross-frontend behavior. Runtime claims require exact commands/results in `BUILD_LOG.md`. The seven gates in `CODEX_WORKFLOW.md` apply to each implementation task. No successor starts automatically after a document is written or a test passes.
