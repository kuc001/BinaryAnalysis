# R1-B — Analysis core contract proposal

**Status: proposed for owner review, 2026-11-11.** This document specifies the smallest shared semantic boundary for C1 Store/Load/Alias/SSE. It does not freeze CIR v2, change an Accepted ADR, authorize C1 code, or claim that current classes already satisfy this contract. Evidence is the local R1-A audit and the current `emtaint/` source at `codex/architecture-reset` HEAD `ddfbc5fccaecaf9d624600aa32c4a17ced8b300f`. `scripts/` and `tests/` are absent in this checkout. Address, identity, provenance and artifact/result separation follow `ARCHITECTURE.md` and `ACQUISITION_DESIGN.md`.

## 1. Scope and semantic status

The shared engine consumes serialized CIR effects, a function/CFG revision, an initial memory image and a query context. It publishes an **analysis result** with dependencies and evidence; acquisition CIR and source artifacts are immutable inputs. A query result has independent axes: `AliasKind = MUST_ALIAS | MAY_ALIAS | NO_ALIAS | UNKNOWN` and `Completeness = COMPLETE | PARTIAL | TIMEOUT | UNSUPPORTED` (plus `FAILED` as an execution error). `MAY_ALIAS` is a completed conservative relation when all feasible alternatives have been considered but some may overlap; `UNKNOWN` means no defensible relation can be selected. `PARTIAL`, `TIMEOUT` and `UNSUPPORTED` describe why the answer is not exhaustive; they cannot be converted to a completed negative. A result may retain known dependencies while reporting a stopped frontier. Every status carries reason codes, affected effects/locations, budgets and evidence IDs. No caller may use a truthiness conversion of an alias result.

### Proposed read-only interface shapes (design, not current Python APIs)

```text
resolve_definition(CIRValueId, FunctionRevision, QueryContext, QueryBudget)
    -> DefinitionSet + Assessment + EvidenceRefs
resolve_location(CIRPointerValueId, AccessWidth, ProgramPoint, MemoryVersionId,
                 QueryContext, QueryBudget)
    -> LocationAlternatives + Assessment + EvidenceRefs
query_alias(LocationAlternatives, LocationAlternatives, MemoryVersionId,
            QueryContext, QueryBudget)
    -> AliasDecision(kind, completeness, evidence, unresolved_reasons)
forward_dependents(DefinitionId, ProgramPoint, QueryContext, QueryBudget)
    -> DependencyResult
backward_definitions(UseId, ProgramPoint, QueryContext, QueryBudget)
    -> DependencyResult
```

`QueryContext` identifies binary/function/CFG revision, call context if any, source artifact IDs, memory state, path predicate and analysis policy revision. A query budget bounds visits, alias alternatives, solver calls, expression nodes and wall time. An empty `LocationAlternatives` must carry a reason (`UNINITIALIZED`, `UNRESOLVED_ADDRESS`, `UNSUPPORTED_EFFECT`, `BUDGET_EXHAUSTED`, or a proved impossible path); only a separately proved impossible path may be excluded. This shape prevents “empty means NoAlias”.

## 2. CIR Definition contract

| Field | Required meaning | Current v1 relationship |
|---|---|---|
| Value identity | A typed, function-scoped semantic value; each defined value has one immutable `CIRValueId` within a function artifact revision. Names are display metadata. | `ValueRef(id: str, type)` and `CIRFunction.values` validate declaration/type but do not define versioned producer identity (`core/contracts.py:191-200`; `ir/canonical/model.py:376-408`). |
| Effect identity | Stable ID for one ordered effect in a function export, scoped by binary/function/artifact fingerprint and block/effect slot; preserves synthetic/no-EA distinctions. | Effects have `origin: str` but no own ID (`ir/canonical/model.py:35-112`). Block order can locate an effect only within the current artifact, not across revisions. |
| Definition identity | Stable ID for the output of an effect or an explicit input/phi/unknown definition. A Store has a MemoryDefinition identity even without scalar output; a Load has a value definition linked to `ReadMemory`. | v1 has result `ValueRef` for Compute/Load and ordered effects, but no common `DefinitionId`/`UseId` on CIR. `memory/state.py:300` defines a different analysis-level union of SSE and memory-version IDs; do not conflate it with CIR identity. |
| Operation, inputs, outputs | Typed `Compute`, `Load`, `Store`, register, Call, control and Unknown/Havoc effect; inputs reference earlier/phi definitions or explicit initial symbols; outputs list value and memory effects. Each use has an index/role so repeated operands remain distinct. | v1 has typed effect families and `operands()`; no explicit use/definition graph (`ir/canonical/model.py:14-112,363-408`). |
| Origin, guard, completeness | Effect references zero or many source/provenance nodes via a separate graph; guard is a typed Boolean value/definition with polarity and path context; completeness records unsupported footprint. | `Origin` is one point/producer/opcode; Load/Store guard exists; module assessment and UnknownEffect exist, but per-definition coverage and many-to-many provenance need the approved v2 contract (`core/contracts.py:123-134`; `ir/canonical/model.py:410-430`). |

One `DefinitionId` is indexed once and shared by both directions: forward asks which uses/effects depend on it; backward asks which definitions may reach a given use. Direction changes traversal, never the identity or Store/Load semantics. A data-dependency edge is `(producer DefinitionId, consumer UseId, kind, guard, memory version, evidence, assessment)`. Phi/join carries all feasible predecessors and guards. A result cannot state “no dependency” when an input definition, memory effect or path is unsupported.

**C1 schema choice:** C1 may use a private analysis index derived deterministically from v1 `(artifact fingerprint, function, block, effect index, output role)` to exercise current CIR Store/Load without mutating v1 bytes. Publishing these IDs across artifacts or persisting them as the durable CIR v2 identity requires owner-approved C contract freeze. v1 remains readable as historical input; no relabeling as v2. R1-C further requires an approved recipe version and binding to CIR body hash, producer/acquisition fingerprint, binary/function and CFG revision plus role ordinal before such private IDs enter an analysis-owned persisted result; reload must verify all inputs and reject stale mappings. Bare in-memory IDs cannot support C1b cross-process results. See `ARCHITECTURE_EXTENSIBILITY_REVIEW.md` §4.

## 3. Memory contract

`MemoryObjectId` identifies an abstract storage candidate, not a concrete pointer value. It includes binary plus kind/anchor (frame slot, global range, allocation site/context, or UNKNOWN), cardinality/lifetime and source/confidence. `AccessPath` records root and ordered Offset/Index/Member/Deref/UnknownOffset segments, with symbolic offsets and layout evidence. `MemoryLocation` combines object candidate, access path or symbolic address, address-space tag, byte range, access width, endian, guard and assessment. Exact `ByteRange` is half-open `[start, end)` in bytes; unknown bounds remain symbolic. `AccessWidth` is whole bytes for C1. Address domains (`RVA`, `IDA EA/VA`, runtime VA, file offset) require explicit conversion evidence; equal integers in different domains prove nothing.

These are four distinct predicates:

1. **Address equality** compares pointer values under a specified address domain, memory state and guard. Equal numeric expressions do not prove equal objects if conversion/provenance is missing.
2. **Object equality** compares abstract `MemoryObjectId`s. Same summary object may represent several concrete allocations; distinct abstract roots may overlap unless disjointness is proved.
3. **Pointer alias** asks whether two pointer alternatives can denote the same concrete byte/address. It needs target-set completeness and contextual evidence.
4. **Access overlap** asks whether two *sized* byte ranges intersect. Two accesses with different starting addresses can overlap; two equal pointers with different widths do not imply equal accesses. C1's Store→Load relation uses overlap/coverage, not only pointer equality.

`MemoryVersion` is an immutable state transition: Initial, `WriteMemory(parent, location, value, guard, update, evidence)`, guarded Join, or `HavocMemory(parent, footprint, reason, guard)`. `ReadMemory(version, location, result, guard)` binds a read to the exact version seen at that program point. Store→Load analysis enumerates byte-wise reaching definitions when ranges overlap; partial overlap reconstructs the result from covered and preserved bytes with endian-aware extract/concat. A **strong update** may kill an earlier definition only with complete MustAlias for the affected exact byte interval, unique live target, exact coverage and a path guard known true on the queried path. Otherwise use **weak update**, retain old/new alternatives and mark uncertainty. A guarded Store creates guarded alternatives; false guard has no write. Havoc invalidates affected bytes and produces an explicit unknown alternative; unsupported footprint may be `*`. Unknown object/offset, uncertain address-space relation and partial lowering remain unknown/partial, never negative evidence.

Memory versions and SSE nodes are analysis state, stored as versioned analysis result/evidence, not embedded into immutable acquisition CIR. Cache keys include CIR/artifact fingerprint, function/CFG revision, initial memory image, analysis and memory semantics versions, query context, policy and budget. A change to any dependency invalidates affected results; debug inspection reads persisted data only.

## 4. AliasQuery contract and current counterexample

**R1-C semantic clarification (proposal, not frozen schema):** The initial R1-B table described a *location/access relation* and used `NO_ALIAS` for disjoint byte intervals even when base pointers could be equal. That conflates pointer/address alias with accessed-byte overlap. The table below is now scoped to **address relation**. C1 should attach independent `AccessOverlap`/`ByteCoverage` conclusions, each with guard, version, completeness and evidence, as option A in `ARCHITECTURE_EXTENSIBILITY_REVIEW.md` §3. A byte-disjoint pair can suppress only that Store→Load byte dependency. Existing `memory/engine.py` behavior is not relabeled as a proven pointer-alias API by this text.

`AliasQueryInput` has two nonempty *or explicitly unresolved* sets of `MemoryLocation` alternatives, their original pointer value/definition IDs, access widths, query program point and `MemoryVersionId`. `AliasEvidence` records each compared pair, object and byte-range facts, path guard, source/provenance IDs, disjointness or equality proof, analysis assumptions, budget and completeness. `UnresolvedReason` records missing or contradictory bindings, uninitialized pointer, unknown object/offset, unsupported effect, infeasible path, or budget/timeout. A proof is scoped to the version and context; a future Store or context change cannot reuse it blindly.

| Kind | Permitted condition |
|---|---|
| `MUST_ALIAS` | All feasible alternatives resolve to the same proved concrete address under guard; no unresolved alternative. Equal abstract object ID or overlapping access interval alone is insufficient. |
| `NO_ALIAS` | Every feasible address cross-pair has complete separation proof, both alternative sets are exhaustively enumerated, and no unresolved/unknown alternative remains. Disjoint accessed bytes alone do not prove this. |
| `MAY_ALIAS` | At least one feasible address cross-pair may coincide and the finite alternatives were examined completely, without proof that all coincide. Does not authorize a strong update. |
| `UNKNOWN` | Missing/uninitialized/unsupported location or incomplete enumeration prevents a defensible Must/May/No answer; preserve known pair facts and unresolved reasons. |

**Static defect path (P0 semantic risk, no execution claim):** `analysis/aliasing/query.py:44-52` separates `left_empty` for `uninitialized_frame_pointer`. At lines 57-64 it excludes that value from bindings. At lines 67-69 it adds `NO_LOCATION_ALTERNATIVES` only when both `left` and `left_empty` are empty. If the left side consists solely of one uninitialized frame pointer, `left=()`, `left_empty=(u,)`, so there is no reason. With one valid right binding, `left_locations=()`; the pair loop never runs, `complete=True`, then lines 118-124 return `NOALIAS`. The evidence string even says the uninitialized pointer contributes an empty alternative. This is a completed negative without separation proof. A mixed left set `{u, resolved location}` can also return `NOALIAS` if all *resolved* pairs are `NO`, because the NoAlias branch lacks the `left_empty` guard used by the MustAlias branch. The underlying `PythonMemoryEngine.resolve_alias` is more conservative for unknown objects (`memory/engine.py:187-216`); the unsound downgrade occurs in this wrapper. `AliasResult` constructor checks explicit evidence for Must/No (`memory/state.py:60-75`), but `AliasQueryResult.predicted` is an independent string and bypasses that invariant. Separately, the wrapper passes `demand.initial.memory` for every pair (`query.py:107-110`), so a caller cannot currently choose the query-point MemoryVersion; this is a context/precision gap requiring a scoped C1 decision, not proof that every current answer is wrong.

**Minimal later reproduction design, not run in R1-B:** supply a stub demand whose `value(left)` returns one sentinel `u`, `uninitialized_frame_pointer(u)` is true, whose `value(right)` returns one bound pointer `r`, and whose `address_binding(r)` yields a registered singleton object/exact offset. `query_alias(demand, left, right, origin)` currently follows the path above and is expected to report `predicted="NOALIAS", complete=True`; the required contract result is `UNKNOWN` with `UNINITIALIZED`, incomplete assessment and no NoAlias proof. Repeat with `value(left)=(u, l)` and an exact `l` disjoint from `r`; a pairwise NoAlias must still not erase `u`. Add a budget-exhausted binding variant. C1 must test these against the public query path and downstream Store→Load dependency so a false negative cannot silently suppress a reaching definition.

## 5. Bidirectional SSE contract

`SymbolicExprId` identifies a typed immutable node in a hash-consed expression DAG. Nodes include scalar operations, constants, unknown leaves, path-conditioned choice and `MemoryRead(version, location)` leaves. Memory reads are barriers to pure scalar substitution; they expand only through the versioned Memory query with a budget. A unified dependency graph holds `Definition Dependency` (value defined by inputs), `Use Dependency` (where a definition is consumed), and `Memory Dependency` (read byte → candidate Write/Initial/Join/Havoc versions). Each edge records guard, origin/provenance, completeness and evidence. The same graph answers forward and backward queries; forward is not a separate list whose facts may diverge from backward.

An expression update substitutes a definition with a typed expression in one context and preserves the original edge/evidence. Kill/redefinition is a proof about reaching definitions per byte and path, not removal by equal variable name. Join retains predecessor alternatives and guards; an infeasible branch may be pruned only with proof. Loops iterate a monotone worklist to a declared fixed point or widen/stop with `PARTIAL` and a remaining frontier. Deduplication keys include definition/use identity, memory version, context, guard equivalence and relevant semantic assumptions; AST text/hash equality alone is insufficient. `QueryBudget` exhaustion yields `TIMEOUT` or `PARTIAL` with known edges and unvisited frontier, never an empty complete graph. Legacy `VarExpr`, `TraceExpr` and `SimAction` stay research-only.

## 6. Provenance, result and inspector chain

For a C1 dependency, persist an explanation DAG:

```text
CIR EffectId + source/provenance edge
  -> WriteMemory/ReadMemory at MemoryVersionId + location/guard evidence
  -> AliasDecision for every relevant Store/Load byte pair
  -> SSE SymbolicExprId and definition/use dependency edge
  -> versioned DataDependencyResult + completeness/budget/unknown reasons
```

Edges may be many-to-many and may have no machine EA. Provenance labels are categories (`BINARY_CONFIRMED`, `DECOMPILER_RECOVERED`, `DECOMPILER_INFERRED`, `USER_ANNOTATED`, `ANALYSIS_DERIVED`, `UNKNOWN`), not a total trust order. A result cites artifact IDs and graph/memory/query revisions. Analysis Result and Debug/Evidence Artifact have separate identities/lifecycles; a read-only inspector resolves stored IDs and reports unavailable evidence instead of invoking demand, alias or solver code. No amount of pretty evidence upgrades an uncertain semantic result.

## 7. Current implementation gap matrix

| Source and observed capability | Reuse in C1 | Gap / risk | Scope decision |
|---|---|---|---|
| `ir/canonical/model.py:35-112,376-430`: typed Compute/Load/Store, guards, ordered blocks, v1 wire module | Reuse v1 effects as inputs | No durable effect/definition/use IDs, per-definition completeness or many-to-many mapping; `CIRModule.memory_snapshots` mixes input and analysis state | Private derived IDs for C1 prototype; owner review before CIR v2/wire publication |
| `core/contracts.py:74-105,123-134,191-200,327-367`: Assessment, Origin, ValueRef, scoped analysis IDs | Reuse typed value/assessment primitives | `Origin` is one point; `ValueRef.id` is a string; statuses do not directly encode alias query TIMEOUT/UNSUPPORTED + kind | Add result/evidence contract with explicit status; v2 identity/provenance requires freeze |
| `memory/state.py:17-92,104-208`: location intervals, four AliasKind values, update preconditions and version records | Reuse byte intervals and version types | Strong update precondition checks are necessary but path/guard, alternative completeness and source mapping need review | Extend behavior/evidence in analysis layer where possible; frozen schema edits need approval |
| `memory/engine.py:187-216,218-328`: conservative unknown object, disjointness proof, write/read/join/havoc | Reuse engine and DefinitionResolver | Wrapper can erase unknown alternatives; budget `resolve_alias` does not visibly consume query budget; version IDs are scoped runtime sequence IDs; `_notes` accumulates assessments | C1 fixes query semantics and measures scope/invalidation before durable persistence |
| `memory/query_port.py:13-61`: typed query protocol and budget, read/write/points-to/definition results | Reuse port shape | No explicit AliasQuery context/evidence record or outcome status; `UnimplementedMemoryQueryPort` raises unsupported | Contract for result status and adapter needed; do not treat raise/empty as NoAlias |
| `memory/memory_version.py:112-201`: byte-wise reaching definitions, guarded/weak choice, Join and Havoc | Reuse partial-overlap mechanics | Need prove result/evidence round trip, no-loss path guards, exact kill and budget frontier; current resolver collects version IDs but not a complete persisted explanation DAG | C1 integration/evidence slice |
| `analysis/aliasing/query.py:34-151`: demand-to-location classification | Reuse entry after correction | Uninitialized/empty location can produce complete `NOALIAS`; result is string/boolean completeness; pair query uses `demand.initial.memory` rather than explicit query-point version | P0 acceptance case; classify unknown before pairwise NoAlias, freeze query context/version |
| `analysis/sse/dag.py:14-103`: hash-consing, lazy typed substitution; memory read is leaf | Reuse DAG | No public bidirectional dependency graph/query, path/loop fixed-point outcome or persisted explanation | C1 index and result layer; no old mutable expression API |
| `analysis/dataflow/accurate.py:52-395`: CIR transfer handles guarded Store/Load and assessment | Reuse transfer subset | Load/Store effects lack durable IDs; provenance trail and result persistence are incomplete for C1; guarded alternatives need end-to-end proof | C1 bounded real path |
| `analysis/dataflow/legacy_demand.py:470-608`: on-demand reaching Store worklist and alias checks | Reuse strategy selectively | Fallback initial read, MayAlias/partial unknown and summary behavior must be reconciled with versioned memory path; avoid two competing truth sources | One shared dependency semantics in C1; legacy compatibility path remains separate until assessed |

## 8. Why this core supports later algorithms and what needs approval

The legacy B/F traces ask two directions over one definition/use relation; a shared CIR/memory dependency graph answers both without synchronizing mutable expression queues. Alias is called only when a Store/Load or pointer-demand frontier needs it, with budget and unresolved alternatives retained. The same memory-version and dependency evidence lets iCall resolution ask where a function-pointer value came from, and lets taint ask whether a source definition reaches a sink through memory and calls. Later interprocedural summaries add context/CG revisions; vulnerability assessment reads candidate paths and separate validation evidence. This is a dependency design, not proof of complete legacy algorithm coverage.

Owner decisions before C1 code: (1) approve the bounded C1 task and whether private derived v1 definition/effect IDs may be used; (2) freeze the C1 Memory/Alias/SSE result, uncertainty, guard and evidence contract, including `UNKNOWN` versus empty alternatives; (3) decide durable identity, schema version, v1 read compatibility and result/cache/invalidation boundary before publishing IDs; (4) decide whether C1 includes a real persisted result/inspector endpoint under existing storage or requires a new approved artifact contract; (5) resolve the target verification fixtures and supported frontend path. These decisions do **not** approve all CIR v2 fields or the later iCall/Taint contracts. No Accepted ADR conflict was found in this proposal; if the chosen durable identity or storage path changes a frozen boundary, prepare an ACR before code.
