# BinaryAnalysis task backlog — active dependency queue

The `codex/architecture-reset` worktree has no old `scripts/` or P1–P7 `tests/`. Historical B1/B2 cleanup and Legacy Bootstrap are not active prerequisites. ADR-009 remains Proposed. Only the owner records `APPROVED`. **F0 is implemented and verified within its approved boundary; owner implementation review is pending. C1a/C1b remain planned and unauthorized for coding.**

| ID | Status | Bounded outcome | Dependency / next gate |
|---|---|---|---|
| R1-A | IMPLEMENTED | Local legacy algorithm audit, hash inventory and migration map delivered; owner considers main direction credible | Owner acceptance of research remains pending; no algorithm migration acceptance inferred |
| R1-B | IMPLEMENTED | `design/analysis/ANALYSIS_CORE_CONTRACT.md`, alias defect path, gap matrix and C1 specification | Owner review of C1 contracts; no whole CIR v2 approval |
| R1-C | IMPLEMENTED | `research/modern/` reviews of modern algorithms and architecture extensibility | Static review and owner decision; no algorithm code |
| F0-PROJECT-TO-CIR-ACQUISITION | VERIFIED | Real project input → VEX → CIR/CFG/Origin → immutable artifact → detached reload | Owner approved bounded F0 decisions A–F on 2026-11-11; three gates have recorded runtime evidence in `BUILD_LOG.md`; implementation review/APPROVED remain with the owner |
| F1-CTREE-HIR-PREPARATION | PLANNED | CTree/HIR contract preparation and target IDA/Hex-Rays environment probe | May be scoped early by owner; no exporter or HIR completion inferred |
| C1-STORE-LOAD-ALIAS-SSE | PLANNED | Store/Load→memory→alias→SSE→dependency result/evidence, with C1a/C1b gates | F0 real CIR artifact/reload witness, plus owner approval of C1 contract/scope; not authorized for coding |
| C2-ALGORITHM-EXPERIMENTS | PLANNED | Proposed pure-copy pruning, bounded lazy edge and shared consumer comparisons | C1 verified, separate owner task; no implementation authorization from R1-C |
| C3-ADVANCED-SOLVER-EXPERIMENTS | PLANNED | Proposed CFL/IDE, merge/replay, selective context and incremental recomputation prototypes | C1/C2 evidence and separate owner scope |
| ICALL-RECOVERY | NOT_STARTED | Function-pointer candidates with Alias/SSE evidence and versioned Refined CG | Verified/approved C1 boundary, callsite/CG contract and owner task scope |
| INTERPROCEDURAL-SUMMARY | NOT_STARTED | Contextual value/memory effects across calls | Refined CG and summary revision/invalidation contract, owner scope |
| ON-DEMAND-TAINT | NOT_STARTED | Source/sink demand through CIR, memory and summaries | C1 + summary contract, owner scope |
| VULNERABILITY-EVIDENCE | NOT_STARTED | Separate candidate taint paths and validated findings | Taint/result/evidence contracts, owner scope |

## F0-PROJECT-TO-CIR-ACQUISITION — approved specification and verification

### Identity, authority and baseline

- **Task/status/priority:** F0 Project-to-CIR Acquisition Vertical Slice; `VERIFIED`, P1. Parent: F0 in `EXECUTION_PLAN.md`. Scope approver: project owner, 2026-11-11 F0 Owner Approval & Implementation instruction; implementation review remains pending. Codex cannot set `APPROVED`.
- **Repository baseline:** `codex/architecture-reset`, HEAD `e3ea39a007f294c1040a2a23089c95a35c14ecaa`, clean at F0 preflight on 2026-11-11. Preserve any subsequent user changes. The current `emtaint` CLI is a legacy analysis-mode parser, not a Project acquisition command.
- **Accepted direction and F0 freeze:** ADR-001/002/003/004/005/006/008/010/012 select the CIR common boundary, direct VEX→CIR path, manifest plus function artifacts, separate artifact/result/evidence lifecycles and current `emtaint` import name. The owner approved this F0-only Project, publication, integrity and detached-reload subset with two-dimensional status. Broader fingerprint/rebinding/cache, whole CIR v2 and ADR-008 cross-representation graph contracts remain Proposed.

### Goal, real input and boundaries

**Observable outcome:** Given one explicit Project input, acquire one real function through the existing `AngrVexFrontend`, persist its CIR function, source CFG, Origin records and bounded frontend provenance, then load and validate those records in a fresh process without invoking angr or analysis. Return an immutable `AcquisitionRef` and a read-only acquisition summary. F0 intentionally ends at verified analysis inputs; Dataflow/Alias/SSE results, cache reuse and vulnerability evidence belong to later tasks.

**Verified real witness:** `D:\works\dataflow\EmTaint\BinaryAnalysis-worktrees\firmware-binaries\rv130_v44\httpd`, 626,308 bytes, SHA-256 `334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787`. ELF32 little-endian, `ET_EXEC`, `EM_ARM`; executable file-backed segment VA `[0x8000,0x98130)`, file range `[0,0x90130)`, image base `0x8000`. ELF entry **VA `0x10e58`**, `FunctionId` RVA `0x8e58`. Runtime `AngrVexFrontend.discover((0x10e58,))` recovered `_start` with one ARM/default-mode input block; lift produced one CIR block, 95 effects, 74 Origins, 119 SourceHints, 74 InstructionHints and a one-node/zero-edge incomplete CFG. The entry succeeds without a backup selection. RVA, source VA, IDA EA, runtime VA and file offset remain distinct domains.

**Reuse and implemented paths:** `emtaint/frontends/angr_vex/frontend.py` and `vex_input.py` retain native CFGFast/VEX lifting and pinned 9.3.4 runtime; `vex_lowering.py` yields CIR, incomplete source CFG, report and provenance; `ir/canonical/wire.py` retains `CIR-Wire-v1`. New `emtaint/project.py` resolves JSON Project input, `emtaint/acquisition.py` orchestrates the actual frontend, `emtaint/artifacts.py` publishes and validates independent artifacts, and `emtaint/acquire_cli.py` supplies the new subcommand through `__main__.py`. `frontends/saved_cir.py` gained a byte-input decoder reused by its old directory reader and the new pinned reader. The guard-era `FunctionStore` and old analysis CLI logic remain outside F0.

**Actual implementation scope:** `emtaint/project.py`, `emtaint/acquisition.py`, `emtaint/artifacts.py`, `emtaint/acquire_cli.py`, `emtaint/__main__.py`, `emtaint/frontends/saved_cir.py`, new `tests/f0/test_acquisition.py` and `.gitignore` for ignored local F0 evidence. No public Core Identity, CIR model or Wire format changed.

**Excluded:** old `scripts/`, WriteGuard, Legacy Bootstrap, P7 receipt compatibility, legacy `FunctionStore` repair, C1 Alias/SSE, CTree/HIR export, CG/summary/taint, CIR v2, full incremental cache/fingerprint rebinding, concurrent writers, historical migration, analysis-result persistence and broad CLI replacement. Never commit or push automatically.

### Owner-approved F0 contracts and implemented behavior

1. **ProjectSpec-F0-v1 and resolver.** One UTF-8 JSON file with `project_schema_version`, `binary_path` (absolute or relative to spec directory), `binary_sha256`, `frontend: "angr-vex"`, `function_vas: ["0x10e58"]`, `expected_image_base: "0x8000"`, and `allow_partial: true`; artifact output root is an explicit command/API parameter outside semantic identity. Resolver rejects duplicate/empty selections, wrong digest, non-ELF/unsupported architecture, changed loader base or addresses outside file-backed executable bytes. It returns immutable `ResolvedInputs` containing exact bytes/hash, normalized VA and RVA selection and ELF/loader address map; invalid input raises a stated error. The file path is provenance, not binary identity. The witness Project file was generated locally without copying firmware into production code.
2. **Acquisition API.** `resolve(ProjectSpec) -> ResolvedInputs`; `acquire(ResolvedInputs, FrontendSelection, ArtifactRoot) -> AcquisitionOutcome`; `load(AcquisitionRef, FunctionId, *, project=None) -> FunctionInputs`. A successful `AcquisitionOutcome` carries a published reference, function ID, artifact integrity `VALID`, semantic completeness and diagnostics; failures raise explicit `InputError`/`ArtifactError`/I/O errors with no successful reference. `FunctionInputs` carries one `CIRModule`, `ControlFlowGraph`, Origin-backed `ProvenanceIndex`, frontend report and verified artifact hashes. `.venv\Scripts\python.exe -m emtaint acquire --project <project.json> --artifact-root <dir>` prints a pinned JSON receipt. The public `load` API provides fresh-process read-only reload without native lifting; optional `project` performs current-binary/loader comparison.
3. **Identity and address domains.** `BinaryId` is the SHA-256 of exact binary bytes; `FunctionId(BinaryId, 0x8e58)` uses image RVA. Store selected VA, ELF link base, angr mapped base, segment VA/file-offset mapping and conversion policy in typed or explicitly tagged fields. Never collapse source VA, RVA, file offset, IDA EA and runtime VA. F0 artifact ID is `(kind, schema version, SHA-256 of canonical stored bytes)`; a manifest binds those IDs to the exact binary, selected function, loader inputs, `Producer`, CIR wire version and frontend/lowering versions. No cross-binary rebinding or function semantic cache reuse is claimed. A changed binary or loader/configuration cannot hit an old acquisition.
4. **Immutable layout and validation.** `AcquisitionManifest-F0-v1` names one generation, binary/function identities, ELF segment/VA/RVA mapping, producer/tool/CIR versions, semantic completeness, assessment/diagnostics, and every artifact's kind/version/relative path/size/SHA-256. The generation contains `architecture.json`, `producer.json`, `assessment.json`, `origins.json`, `frontend-report.json`, `source/function-<rva>.json`, `cir/function-<rva>.json`, `cfg/function-<rva>.json`, `provenance/source-hints.json` and `provenance/instruction-hints.json`. Source selection stores recovered function bounds/edges, block byte hashes and coverage; it is not a replayable VEX dump. CFG stores function/node/edge/entry/exit/status/reason. Paths are fixed, relative and confined to one generation, rejecting traversal, absolute paths and links. The manifest is written last. The verified reader pins its external manifest digest, checks all sizes/hashes and cross-references, then passes already-verified bytes to the reused saved-CIR decoder; the old directory reader alone is not a trusted receipt.
5. **Publish, partial and errors.** Stage on the artifact root's volume, verify there, then rename to a new absent immutable generation; return its explicit ref only after publication. Readers ignore staging. F0 has no cache pointer, overwrite, concurrent-writer guarantee or recovery algorithm. Artifact integrity (`VALID`, `MISSING`, `STALE`, `CORRUPT`, `INCOMPATIBLE`) and semantic completeness (`COMPLETE`, `PARTIAL`) are separate dimensions. The real witness reloads as **integrity `VALID`, semantics `PARTIAL`** because the bounded CIR and CFG assessments remain incomplete, even though its 74 recorded statements have no unsupported opcode. `allow_partial: false` fails before publication. Detached `load` needs the pinned receipt and all saved artifacts, not the original binary or native runtime; explicitly passing `project` checks current bytes and loader/address mapping and may report `STALE`.
6. **Ownership and provenance.** Project resolver owns path/hash/address normalization; native angr/VEX objects remain inside `frontends`; acquisition orchestrates but does not perform analysis; artifact writer/reader owns bytes, schema/ref validation and immutable publication; `graph`/`core`/`ir` remain frontend-independent. Persist `Origin` and all available `SourceHint`/`InstructionHint` records rather than flattening them to one source per CIR value. Treat them as bounded VEX/source evidence, not the future cross-representation ADR-008 Provenance Graph. Loading/inspection is read-only and does not execute new analysis or angr queries. Acquisition CFG is an incomplete source CFG, not a refined analysis CG/CFG result.

The approved Project input used for the witness is:

```json
{
  "project_schema_version": "ProjectSpec-F0-v1",
  "binary_path": "D:\\works\\dataflow\\EmTaint\\BinaryAnalysis-worktrees\\firmware-binaries\\rv130_v44\\httpd",
  "binary_sha256": "334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787",
  "frontend": "angr-vex",
  "function_vas": ["0x10e58"],
  "expected_image_base": "0x8000",
  "allow_partial": true
}
```

This path is a local witness location, not a serialized identity. `AcquisitionRef` contains the generation path, externally pinned manifest SHA-256 and schema version. `cir/function-<rva>.json` uses `wire.dumps(CIRFunction)`; shared architecture/producer/assessment files use the same codec. `origins.json` retains the saved reader's ID-keyed map with `block`, `statement_index`, `instruction_rva` and `source_opcode`. CFG, source selection and hint files are versioned JSON. The manifest hashes every referenced file and records its size; content hashes detect corruption but do not authenticate provenance without the caller-held pinned digest.

**Decision gates:** The project owner approved A–F for this bounded F0 implementation on 2026-11-11, including two-dimensional status and detached load. Repository Baseline, F0 Architecture/Data Contract/Module Boundary freezes, Vertical-Slice Development and System Verification are recorded in `BUILD_LOG.md`. Architecture compliance was self-checked for the reviewable diff; owner implementation review/`APPROVED` remains pending. Broader CIR v2, ADR-008 graph, cache/rebinding and analysis contracts are not frozen by F0; changing a frozen public boundary still requires an ACR.

### Vertical path and falsifiable acceptance

```text
ProjectSpec + actual ELF/hash/entry VA
  -> resolver: bytes, BinaryId, loader map, selected RVA
  -> AngrVexFrontend.discover/lift: FunctionInput, VEX chunks, CIR module,
     CFG input, Origin map, provenance hints, assessment/report
  -> immutable manifest + function/CFG/Origin/provenance artifacts
  -> fresh-process verified load: FunctionInputs + read-only summary
```

1. The exact witness binary resolves to its declared SHA-256, `EM_ARM`, base `0x8000`, entry VA `0x10e58` and `FunctionId` RVA `0x8e58`; discovered block extents are recorded. A wrong hash/base or out-of-range function is rejected before publish.
2. On approved runtime, one selected function is lifted. The manifest references the same `BinaryId`/`FunctionId` as every CIR body, CFG node/edge, Origin and hint. Report statement coverage and unsupported/lift failures are observable. Expected semantic status is `PARTIAL` unless complete coverage is actually established; no fabricated `COMPLETE` claim.
3. A fresh process loads through the F0 reader with the native frontend unavailable or explicitly blocked. It reproduces the same CIR body hash, CFG nodes/edges/status, Origin records, hints and diagnostics; inspection is read-only and triggers no analysis query.
4. Tampering independently with CIR, CFG, `origins.json`, hint sidecar or manifest, or deleting a referenced file, yields `CORRUPT`/`MISSING` and no usable acquisition. A foreign function ID, dangling CFG edge or hint-to-origin/value link is rejected even when an attacker recomputes one file hash.
5. Replacing the binary or changing the declared loader base makes the old ref `STALE`; an unsupported manifest/CIR schema yields `INCOMPATIBLE`. Staging without a published manifest is invisible. An incomplete lift is usable only through an explicitly partial ref; `allow_partial: false` cannot publish it.
6. Only the selected function is materialized. No Alias/SSE, taint, CTree, CG refinement, analysis result, cache hit, old script or guard path is invoked. The artifact remains usable without its source binary when all pinned manifest hashes and references validate; an explicit current-Project comparison reports `STALE` when the source is absent or changed.

**Verification outcome:** `.venv\Scripts\python.exe -m emtaint acquire --project <project.json> --artifact-root <dir>` exited 0 on the real ELF. A separate Python process loaded the pinned generation without importing angr/pyvex/cle/archinfo. The final F0 suite ran 13 tests successfully with one environment-limited link-creation skip; the link-guard code path was tested separately. `BUILD_LOG.md` records exact commands, hashes, negative cases and the remaining platform limitation. If two targeted fixes fail one acceptance issue, stop and record root cause per `CODEX_WORKFLOW.md`.

## C1-STORE-LOAD-ALIAS-SSE — task specification for owner review after F0

**Identity and gates.** Priority P0 for a possible false `NOALIAS` in the public alias wrapper, P1 for the bounded slice. Architecture directions ADR-001/002/008/010/011/012 remain Accepted; detailed CIR v2/identity/result contracts are not all frozen. R1-B proposes the minimal boundary in `design/analysis/ANALYSIS_CORE_CONTRACT.md`. C1 remains `PLANNED` until F0 supplies a real reloadable CIR input and the owner approves C1's boundary, private-v1-ID versus durable-v2-ID policy, result storage endpoint and module ownership. If implementation changes a frozen core boundary, prepare an ACR before code.

**R1-C readiness clarification.** `research/modern/ARCHITECTURE_EXTENSIBILITY_REVIEW.md` recommends separate address `AliasKind` and byte `AccessOverlap/ByteCoverage`; C1 must not use a range-level `NO_ALIAS` as proof that pointers cannot alias. It requires a deterministic, versioned private v1 ID recipe bound to CIR body hash, producer/acquisition fingerprint, function/CFG revision, block, effect/role ordinals, with reload mapping and stale rejection. A bare ephemeral ID cannot be persisted as a durable DefinitionId. F0's verified artifact is the preferred real input. `frontends/saved_cir.py` with a validated report-CFG adapter remains an alternative if its receipt and identities can be proven. These are owner decisions, not a grant to edit core schema.

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

Also run the minimal public `query_alias` counterexample in `design/analysis/ANALYSIS_CORE_CONTRACT.md` once C1 is authorized, including a mixed uninitialized/resolved set. Verify F0's stored CIR input, result reload, corrupt/stale artifact rejection, changed-memory/CFG/policy invalidation, and inspector read-only behavior. A local mock or passing unit test alone is insufficient for `VERIFIED`; record exact commands, exits, skipped checks and representative system evidence in `BUILD_LOG.md` when code work is authorized.

**Failure/stop conditions.** Stop affected work and report P0 if a `NO_ALIAS`/strong update lacks complete proof, a missing definition becomes a negative, or persisted identity/address conversion changes silently. Stop the slice at a pending owner decision for a frozen schema, identity, result-store or module boundary; submit an ACR if necessary. If two targeted fixes fail one acceptance issue, document root cause before further edits. Exhausted budget returns partial evidence rather than success. C1 implementation and verification end at owner review; do not auto-start iCall or taint.

## Historical reset disposition

The earlier B0/B1/B2/B3 rows described a prior checkout with `scripts/` and `tests/`. Their rationale and B1-GUARD cancellation remain in `DECISIONS.md`, `archive/reset-2026/RESET_MANIFEST.md` and Git history. Current absence of those directories removes their executable cleanup and compatibility tasks from this active queue. Any newly discovered *live* old-script dependency is a fresh, evidence-backed issue; it is not automatic restoration of B1 or a blocker for F0/C1.
