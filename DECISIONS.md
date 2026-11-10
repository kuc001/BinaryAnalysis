# BinaryAnalysis architecture decision register

2026-11-10 owner decision. **ADR-001–008 and ADR-010–012 are Accepted only to the extent stated below; ADR-009 remains Proposed.** SOURCE_CONFIRMED denotes source evidence; an Accepted architecture direction does not approve unfinalized schema fields, target IDA versions, deletion, or other milestones. See `REPOSITORY_AUDIT.md` for current-code paths.

**B0 preflight note:** `RESET_MANIFEST.md` supplies file-level migration, deletion and retention gates. The Module Identity / Function Semantic Fingerprint detail in `ACQUISITION_DESIGN.md` remains an implementation contract to freeze under ADR-004; this approval selects module manifest plus function artifacts, not an unreviewed identity rebinding algorithm. The owner subsequently revoked B1-GUARD authorization; the revised guard-removal cleanup plan awaits approval, and no deletion is authorized in this round.

| ADR / status | Current evidence / context | Owner-approved direction or open recommendation | Remaining implementation decision |
|---|---|---|---|
| 001 — Accepted | SOURCE_CONFIRMED `ir/canonical/model.py` has typed effects; `core/contracts.py` lacks aggregate types and many-to-many origins. | Evolve CIR v2; retain reasonable v1 read compatibility. | Exact v2 schema/identity and compatibility window require C contract freeze. |
| 002 — Accepted | SOURCE_CONFIRMED no production HIR or CTree implementation. | CTree uses independent HIR; VEX lowers directly to CIR. | HIR schema, coverage and serialization remain C/E work. |
| 003 — Accepted | SOURCE_CONFIRMED `IdaVexFrontend` reads CFG JSON/ELF, not Hex-Rays. | IDA-side structured CTree exporter; no live Hex-Rays objects in the main process. | Target SDK/version/license/invocation still need a compatibility probe. |
| 004 — Accepted | SOURCE_CONFIRMED `scripts/p7_acquire.py` writes per-function CIR plus module loader/report. | Module Manifest + Function Artifact. | Fingerprint, partial publish and rebinding rules still require contract freeze. |
| 005 — Accepted | SOURCE_CONFIRMED CLI/solver depend on scripts; old tests contain semantic cases. | Migrate production capabilities before deleting old tests; build a new architecture-based verification suite. | Preserve semantic requirements and verify replacements before B2 deletion. |
| 006 — Accepted | SOURCE_CONFIRMED distribution is `binaryanalysis`; import package is `emtaint`. | Retain `emtaint` Python import package for now. | Any future rename requires a separate owner decision. |
| 007 — Accepted | SOURCE_CONFIRMED no production Microcode exporter. | Keep only architecture extension interface now; implement Microcode later. | No current Microcode production implementation is authorized. |
| 008 — Accepted | SOURCE_CONFIRMED Origin/ProvenanceIndex lack cross-representation many-to-many mapping. | Independent versioned many-to-many Provenance Graph. | Exact edge/schema/identity semantics require C contract freeze. |
| 009 — Proposed | SOURCE_CONFIRMED CLI delegates to legacy script; solver has script worker. | Migrate necessary production capability first; assess retirement afterward. | Legacy Backend retirement time and final mode policy remain undecided. |
| 010 — Accepted | SOURCE_CONFIRMED FunctionStore derives CFG edges/tail calls; CIRModule embeds MemorySnapshot. | Manage Acquisition Artifact, Analysis Result, Cache and Debug/Evidence Artifact separately. | Migration and historical result import policy remain D design details. |

## ADR-011 — Multi-Representation Semantic Conflict Resolution

**Status:** Accepted by owner on 2026-11-10 for parallel facts and explicit conflict records; detailed conflict schema remains to be frozen.

**Context:** CTree variable type/layout and VEX/machine width/effects may disagree. Evidence categories are not a total trust ranking; an instruction can prove a 32-bit store without proving `int *` type or array stride. Cross-frontend use must avoid turning hypotheses into facts.

**Current source evidence:** `core/contracts.py` has ValueType and Assessment but no fact-level source/conflict record. `memory/engine.py:resolve_alias` uses object IDs, exact intervals and explicit disjoint proofs; `points_to` conservatively returns registered objects plus unknown. `analysis/aliasing/query.py` consumes these results. No production CTree/Microcode comparison exists.

**Alternatives:** (A) frontend priority overwrite; (B) keep parallel facts and conflict records, refine only with explicit evidence; (C) reject any function with conflict. **Recommendation: B.** A loses evidence and can overstate MustAlias; C throws away useful byte-level facts. Represent conflict as `fact IDs, compared property, source artifact IDs, relation, affected queries, resolution evidence/status`. Preserve BINARY_CONFIRMED, DECOMPILER_RECOVERED, DECOMPILER_INFERRED, USER_ANNOTATED, ANALYSIS_DERIVED, UNKNOWN on each fact. Continue width-bounded memory effects when proven; use may-object/weak-update for disputed layout; return UNKNOWN for exact-layout queries; mark affected analysis results partial. Do not upgrade user annotations or decompiler types silently. Candidate taint path remains candidate.

**Technical tradeoff/migration:** More facts and query-specific assessment, but one shared Alias/Memory engine. Existing Origin/Assessment and result formats need a v2 conflict link and explicit invalidation. **Remaining contract decision:** whether explicit user assumptions may override a conflict for a scoped query, and which evidence resolves a conflict as binary-confirmed.

## ADR-012 — Unified Analysis Model Boundary

**Status:** Accepted by owner on 2026-11-10 for CIR as the shared analysis-engine input boundary with HIR retaining high-level semantics; detailed contracts remain to be frozen.

**Context:** CTree contains declarations/control/types absent from CIR v1, while VEX supplies lower-level effects. Shared Dataflow/Alias/Taint must have one semantic query boundary without discarding CTree evidence.

**Current source evidence:** `ir/canonical/model.py` defines Compute, Load/Store/Call/Branch/Return/Unknown and CIRFunction/Module; `core/contracts.py` ValueRef is typed scalar ID and Origin is one point; `memory/state.py` MemoryVersion and `memory/query_port.py` MemoryQueryPort are analysis contracts; `analysis/dataflow/fast.py` and `accurate.py` consume CIR. `frontends/ida_vex/frontend.py` feeds VEX lowering. No production HIR exists.

**Alternatives:** A: CTree→HIR→CIR, VEX/Microcode→CIR, with HIR retained as source semantic artifact. B: CTree→HIR and low-level→CIR feeding a third unified analysis model. C: dual HIR/CIR analysis engines. **Recommendation: A**, conditional on the first vertical slice demonstrating conservative lowering. A adds HIR schema, lowering and provenance but reuses CIR/MemoryQueryPort and avoids B's third synchronization boundary or C's duplicate algorithms. HIR holds declarations, lvalues, aggregate/type hypotheses and structured control. CIR v2 holds ordered scalar/memory/call/control effects, definition IDs, object/path references, guards and partial footprints. Provenance links HIR nodes to zero/many CIR definitions/values; no full AST copy in CIR. Unsupported HIR maps to UnknownEffect/Havoc and coverage diagnostics. Analysis consumes CIR+program+memory contracts only.

**Technical tradeoff/migration:** Requires CIR v2 identity/schema and historical artifact adapter; HIR remains independently reloadable. If the representative slice cannot preserve essential semantics with explicit uncertainty, submit an Architecture Change Request before changing the accepted boundary. **Remaining contract decision:** exact v2 identity/migration policy and criteria for reopening.

The owner cancelled B1-GUARD before implementation. The earlier guard migration plan and package API are withdrawn; revised B1 cleanup specifications require owner approval before code changes. B2 cleanup remains outside this round.

## Approval impact matrix — owner decision recorded

The owner accepted the directions above except ADR-009. The detail gates below are outstanding implementation contracts or, for ADR-009, the undecided retirement policy. Code/schema impacts are projected changes, not changes made by approval. Remaining details do not reverse an accepted direction.

| ADR / status | Approved direction or open alternative | Production code impact | Schema/data impact | Later implementation impact | Detail gate | Remaining detail |
|---|---|---|---|---|---|---|
| 001 / Accepted | Evolve typed effects to CIR v2; keep v1 or replace IR | `ir/canonical`, lowering, dataflow/memory consumers | New version/identity and v1 reader migration | C→E/F analysis contract | C, D/E/F | v2 scope and v1 compatibility period |
| 002 / Accepted | CTree-only independent HIR→CIR; HIR for all frontends | New HIR exporter/lowering consumer boundary | HIR v1 and source-to-CIR coverage | E CTree slice, D artifact selection | C/E contract freeze | HIR schema and source-retention format |
| 003 / Accepted | IDA-side structured exporter; live SDK bridge/text parsing | New IDA adapter, no live object in core | CTree source artifact and version metadata | E requires SDK probe | E | target IDA/Hex-Rays versions, license and invocation |
| 004 / Accepted | Module manifest + per-function artifacts; monolith | Acquisition/store/cache and FunctionStore adapter | Manifest, two-level fingerprint, dependencies, rebinding | D incremental build, B1-SOURCE design | D; B1-SOURCE contract | partial publish, fingerprint and binary-ID rebinding |
| 005 / Accepted | New contract/system verification after legacy cleanup; retain old suite or accept no suite | B1 replacement checks, B2 test reset | New fixtures/evidence formats, not old test files | B1 acceptance and B2 deletion gate | B1 verification policy, B2 | replacement verification policy and retained semantic oracles |
| 006 / Accepted | Retain `emtaint` import temporarily; immediate rename | Imports, CLI, packaging only if rename | Artifact producer/package metadata identity | B3 and compatibility | B3 naming, outside current B1 guard-removal scope | import/CLI compatibility window |
| 007 / Accepted | Extension interface now; production Microcode implementation deferred | Future adapter only | Future Microcode source schema/provenance | Separate later scope | Microcode implementation, not B1 | timing and target maturity |
| 008 / Accepted | Versioned many-to-many graph; extend Origin or EA inference | Lowerers, debug/provenance consumers | New graph IDs/edges and typed address conversion | C/E/F/H | C provenance, E/H | identity/unmapped/conflict edge rules |
| 009 / Proposed | Retain necessary legacy capability during guard removal; assess retirement later | CLI, `p7_legacy_reference`, old-Python child launch/parser boundary | Legacy plan/resume, receipts and source hashes while retained | B1-LEGACY, B1-SOURCE, B2 | Retirement decision remains open; guard-only bootstrap removal needs a working child path | final mode policy, sunset and evidence policy |
| 010 / Accepted | Separate acquisition/result/cache/evidence; mixed store | FunctionStore, CIRModule/wire, stores | Split artifact/result manifests and migration | D and B1-SOURCE key policy | D, B1-SOURCE contract | historical result retention/import policy |
| 011 / Accepted | Parallel facts and explicit conflicts; priority overwrite or reject function | Type/memory/alias/query assessment | Conflict record, fact provenance/result links | F/G conservative behavior | F/G | scoped user assumptions and conflict-resolution evidence |
| 012 / Accepted | CIR common analysis boundary with HIR preserved; third model or dual engines | Shared analysis interfaces and lowering | CIR v2/HIR link and coverage record | C/E/F/G architecture | C/E/F/G; D schema contract | exact CIR/HIR mapping and ACR reopening criterion |

## Owner decision — cancel B1-GUARD and remove auxiliary WriteGuard

**Status:** Effective owner decision, 2026-11-10; not a new ADR and not an approval of ADR-009. The owner identified WriteGuard, ProbeWriteGuard, ForbiddenMutation and Legacy Readonly Bootstrap as auxiliary P1–P7 controls outside the target product architecture. B1-GUARD is `CANCELLED` before implementation. Do not migrate or reimplement the guard, its monkeypatch, violation reporting or child bootstrap under another name. The earlier B1-GUARD authorization and proposed package API are superseded.

**Implementation boundary:** The future cleanup must remove live guard imports, install/restore, `guarded_open`, `ForbiddenMutation` handling and `violations` fields/status checks while retaining explicit CLI/Solver/Acquisition output folders, ordinary file/error management and supported Legacy Backend execution. `legacy_readonly_bootstrap.py` also hosts old-Python actions and PLY parser setup, so its business behavior must be separated before the guard-specific file is deleted. `p1_runtime.py` has no independent business capability. Source-manifest hashes, sealed helper lists, legacy plan/resume hashes, historical receipts and old guard test cases need explicit handling. ADR-009 remains Proposed; this decision does not authorize Legacy Backend retirement, CIR/HIR/algorithm changes or B2 deletion.

**Approval gate:** This round updates only Markdown planning documents. The owner must approve the revised B1 cleanup specifications and exact later deletion sequence before production code changes. No code, test, file deletion or Git submission is recorded as performed by this decision.
