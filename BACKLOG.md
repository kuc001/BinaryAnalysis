# BinaryAnalysis task backlog — active dependency queue

As of 2026-11-11, `codex/architecture-reset` HEAD `ddfbc5fccaecaf9d624600aa32c4a17ced8b300f` has no `scripts/` or `tests/` directory. The prior B1/B2 cleanup specifications in Git history and `DECISIONS.md` are historical decisions, **not active work or prerequisites**. B1-GUARD remains cancelled; do not recreate it, a script compatibility layer or Legacy Bootstrap. ADR-009 remains Proposed. Only the owner records `APPROVED`. R1-B documentation work does not authorize C1 production edits.

| ID | Status | Bounded outcome | Dependency / next gate |
|---|---|---|---|
| R1-A | IMPLEMENTED | Local legacy algorithm audit, hash inventory and migration map delivered; owner considers main direction credible | Owner acceptance of research remains pending; no algorithm migration acceptance inferred |
| R1-B | IMPLEMENTED | `ANALYSIS_CORE_CONTRACT.md`, alias defect path, current gap matrix, C1 specification and plan consolidation | Owner review of specific C1 contracts and task scope; no whole CIR v2 approval |
| R1-C | IMPLEMENTED | Full-text modern algorithm transfer review and architecture/C1 readiness review in two new documents | Static review and owner decision on C1 minimum contract; no algorithm code or whole CIR v2 freeze |
| C1-STORE-LOAD-ALIAS-SSE | PLANNED | First Store/Load→memory→alias→SSE→dependency result/evidence slice | Owner approval of C1 scope and affected architecture/data/module boundary, input and persistence choices; independent of historical B1/B2 work |
| C2-ALGORITHM-EXPERIMENTS | PLANNED | Proposed pure-copy pruning, bounded lazy edge and shared consumer comparisons | C1 verified, separate owner task; no implementation authorization from R1-C |
| C3-ADVANCED-SOLVER-EXPERIMENTS | PLANNED | Proposed CFL/IDE, merge/replay, selective context and incremental recomputation prototypes | C1/C2 evidence and separate owner scope |
| ICALL-RECOVERY | NOT_STARTED | Function-pointer candidates with Alias/SSE evidence and versioned Refined CG | Verified/approved C1 boundary, callsite/CG contract and owner task scope |
| INTERPROCEDURAL-SUMMARY | NOT_STARTED | Contextual value/memory effects across calls | Refined CG and summary revision/invalidation contract, owner scope |
| ON-DEMAND-TAINT | NOT_STARTED | Source/sink demand through CIR, memory and summaries | C1 + summary contract, owner scope |
| VULNERABILITY-EVIDENCE | NOT_STARTED | Separate candidate taint paths and validated findings | Taint/result/evidence contracts, owner scope |

## C1-STORE-LOAD-ALIAS-SSE — task specification for owner review

**Identity and gates.** Priority P0 for a possible false `NOALIAS` in the public alias wrapper, P1 for the bounded slice. Baseline is the clean HEAD above. Architecture directions ADR-001/002/008/010/011/012 remain Accepted; their detailed CIR v2/identity/result contracts are not all frozen. R1-B proposes the minimal boundary in `ANALYSIS_CORE_CONTRACT.md`. C1 remains `PLANNED` until the owner approves that boundary, private-v1-ID versus durable-v2-ID policy, result storage endpoint, representative input and module ownership. If implementation changes a frozen core boundary, prepare an ACR with impacted producers/consumers, compatibility, invalidation, verification and rollback before code.

**R1-C readiness clarification.** `ARCHITECTURE_EXTENSIBILITY_REVIEW.md` recommends separate address `AliasKind` and byte `AccessOverlap/ByteCoverage`; C1 must not use a range-level `NO_ALIAS` as proof that pointers cannot alias. It requires a deterministic, versioned private v1 ID recipe bound to CIR body hash, producer/acquisition fingerprint, function/CFG revision, block, effect/role ordinals, with reload mapping and stale rejection. A bare ephemeral ID cannot be persisted as a durable DefinitionId. Preferred real input is an existing `frontends/saved_cir.py` acquisition plus a bounded validated `frontend-report.json` CFG adapter, after trusted receipt/hash/CFG/origin preflight; no saved new-format CIR acquisition was found in the searched worktrees. `frontends/function_store.py` remains an alternative only after its guard-era receipt precondition is met or boundedly adapted. These are owner decisions, not a grant to edit core schema.

**Two bounded gates, one C1 outcome.** C1a: correct Store/Load/Alias/overlap/SSE forward and backward queries, uncertainty and inspectable dependency evidence. C1b: deterministic versioned result identity, persistence/reload, dependency invalidation and read-only Inspector over a real CIR input. C1a alone is not complete C1. Full Hermes, IDE/CFL, Merge-Replay, selective object sensitivity, incremental SVFA, full points-to, iCall and taint remain outside C1.

**Goal and endpoint.** Given an existing hash-checked CIR function containing ordered `StoreEffect`/`LoadEffect`, compute a byte-aware, guard-aware data-dependency result. The observable path is:

```text
existing CIR artifact + origin records + CFG revision
 → CIR effect/definition/use index
 → address demand + MemoryLocation candidates
 → WriteMemory/ReadMemory + MemoryVersion
 → AliasQuery per relevant byte/range
 → shared SSE forward/backward dependency graph
 → persisted DataDependencyResult + explanation evidence
 → read-only inspector reload
```

This is one bounded single-function, existing-CIR slice; it does not implement CTree acquisition, iCall, cross-function summaries, taint, vulnerability validation or a complete CIR v2 wire format. The input's binary/function identity, artifact hash, memory image and CFG revision must be explicit. Outputs identify each Load use, candidate Store/Initial/Havoc definitions, affected byte ranges, guard, alias kind, query completeness, uncertainty reasons, evidence IDs and dependency fingerprint. A completed negative dependency needs exhaustive separation proof. No result is silently erased by a missing location.

**Call and module ownership.** An application use case loads existing CIR/CFG and provenance via a read-only artifact reader, validates versions and invokes an analysis coordinator. The coordinator indexes effects, calls `CIRAccurateDataFlow`/demand and `MemoryRuntimePort`/`PythonMemoryEngine`, queries alias and reaching definitions, builds one SSE dependency graph, publishes result/evidence, then the inspector reads it. Frontend adapters cannot import analysis policy; analysis cannot import IDA/angr runtime objects; storage validates records and dependencies but does not decide alias truth. A direct `LegacyDemand.memory_definitions` answer and a versioned-memory answer must not silently compete; choose one declared semantic authority and use the other only as an explicitly characterized comparison.

**Expected modification files, subject to approved design:** `emtaint/analysis/aliasing/query.py` (false NoAlias), `emtaint/analysis/dataflow/accurate.py`, `emtaint/analysis/dataflow/legacy_demand.py` (only if used), `emtaint/analysis/sse/dag.py` plus a consumed dependency-query module under `emtaint/analysis/`, `emtaint/memory/engine.py`, `emtaint/memory/memory_version.py`, `emtaint/memory/query_port.py`/`state.py` only if the approved contract requires them, `emtaint/results/` for a versioned result/evidence store, and `emtaint/analysis_debugging/inspectors.py` for recorded explanation. An existing-CIR reader such as `emtaint/frontends/function_store.py` may need a bounded adapter, but its current guard-era receipt assumptions and loader path require inspection; it is not a reason to restore `scripts/`. `emtaint/core/contracts.py`, `emtaint/ir/canonical/model.py` and `wire.py` are **conditional** on separate owner approval of the exact schema/identity change and compatibility plan. Update `ARCHITECTURE.md`, `EXECUTION_PLAN.md`, `BACKLOG.md`, `BUILD_LOG.md` and relevant contract docs during implementation. This is an impact list, not blanket modification authorization.

**Prohibited changes in C1:** `references/legacy-emtaint/*`, old scripts/tests/bootstrap/guard recreation, independent CTree alias engine, silent CIR v1 relabeling as v2, unapproved HIR/CIR identity or wire edits, legacy `VarExpr`/`TraceExpr`/`SimAction` as public API, new frontend acquisition, iCall/taint migration, commit/push by Codex. Preserve unrelated user changes.

**Propagation rules.** Compute address definitions on demand. For every Store/Load pair in a reachable CFG path, compare pointer/address alternatives and byte intervals at the appropriate MemoryVersion, retaining unknown candidates. Proven address `MUST_ALIAS` plus exact covered bytes, unique target and true path guard permits a strong kill on those bytes; proven disjoint objects can yield address `NO_ALIAS`, while disjoint exact byte intervals yield access `DISJOINT` without implying pointer NoAlias. Overlap without full proof creates weak old/new alternatives. Partial overlap reconstructs bytes in target endian order. Conditional Store creates guarded alternatives; Join preserves multiple reaching definitions; UnknownEffect/Call/Havoc with a possibly affected footprint contributes an explicit unknown dependency. Both forward and backward SSE queries traverse the same definition/use/memory edges and return consistent explanation IDs. Loops use a bounded worklist and record fixed-point or remaining frontier.

**Semantic acceptance scenarios (each checks result, completeness and explanation after persist/reload):**

| # | Input condition | Required observation |
|---|---|---|
| 1 | Singleton object, same exact byte interval, true guard | Complete MustAlias; one reaching Store; strong overwrite only with all preconditions |
| 2 | Proven disjoint objects or disjoint exact ranges on one singleton | Object separation: address NoAlias with proof. Same-object disjoint ranges: access DISJOINT with proof, pointer alias assessed separately. No Store→Load byte edge for that pair. |
| 3 | Two alternatives with possible overlap | MayAlias; old and new definitions retained, no strong kill |
| 4 | Uninitialized pointer or unknown object/offset, including mixed known+unknown alternatives | UNKNOWN/partial with reason; never complete NoAlias; downstream dependency remains possible |
| 5 | Partial Store/Load overlap | Covered and prior bytes both represented, endian-correct composite; no whole-range kill |
| 6 | Guarded Store with symbolic/false/true paths | Conditional dependency for symbolic, absent for proven false, strong only on proved true path |
| 7 | Full overwrite of old definition on every feasible path | Old bytes killed with proof; backwards and forwards agree |
| 8 | CFG join with multiple reaching Stores | Both definitions and guards/evidence retained; no arbitrary winner |
| 9 | Unsupported effect or Havoc touching queried region | Explicit unknown alternative and partial/unsupported status; no clean negative |
| 10 | Steps/alias candidates/solver or wall-time budget exceeded | Known edges retained, remaining frontier and budget dimension recorded; no complete result |

Also run the minimal public `query_alias` counterexample in `ANALYSIS_CORE_CONTRACT.md` once C1 is authorized, including a mixed uninitialized/resolved set. Verify one actual stored CIR input, result reload, corrupt/stale artifact rejection, changed-memory/CFG/policy invalidation, and inspector read-only behavior. A local mock or passing unit test alone is insufficient for `VERIFIED`; record exact commands, exits, skipped checks and representative system evidence in `BUILD_LOG.md` when code work is authorized.

**Failure/stop conditions.** Stop affected work and report P0 if a `NO_ALIAS`/strong update lacks complete proof, a missing definition becomes a negative, or persisted identity/address conversion changes silently. Stop the slice at a pending owner decision for a frozen schema, identity, result-store or module boundary; submit an ACR if necessary. If two targeted fixes fail one acceptance issue, document root cause before further edits. Exhausted budget returns partial evidence rather than success. C1 implementation and verification end at owner review; do not auto-start iCall or taint.

## Historical reset disposition

The earlier B0/B1/B2/B3 rows described a prior checkout with `scripts/` and `tests/`. Their rationale and B1-GUARD cancellation remain in `DECISIONS.md`, `RESET_MANIFEST.md` and Git history. Current absence of those directories removes their executable cleanup and compatibility tasks from this active queue. Any newly discovered *live* old-script dependency is a fresh, evidence-backed issue; it is not automatic restoration of B1 or a blanket blocker for C1.
