# R1-C — Modern Source Analysis Transfer Review

**Research scope:** static R1-C paper review dated 2026-11-11; milestone status and approval remain in `BACKLOG.md` and `EXECUTION_PLAN.md`. Evidence is the ten local full papers in `references/papers/`, the local R1-A audit, and inspected source at HEAD `ddfbc5fccaecaf9d624600aa32c4a17ced8b300f`. Page numbers below are **PDF page numbers**, including cover pages. A DOI URL is a publisher identifier; the PDFs, not search snippets, supply algorithm evidence. LISPA's author-hosted full text and official conference listing were found; its DOI was reported only by secondary indexes and is marked `NOT_VERIFIED` as publisher metadata. Paper claims are confined to their language, benchmark and comparator. No BinaryAnalysis speedup or correctness is inferred.

## Reading key and migration decision

Each record supplies the required 16 fields in this order: (1) citation; (2) primary URL/local full text; (3) source language/IR; (4) target; (5) mechanism; (6) structures; (7) transfer; (8) termination; (9) soundness/completeness assumptions; (10) precision/performance trade; (11) experiment/comparator; (12) value here; (13) binary obstacle; (14) minimum contract; (15) stage; (16) decision. `NOT_VERIFIED` on a field means the paper or available source did not establish that detail for this review. `ADOPT_EARLY` means a bounded *idea*, not a full paper implementation.

### 1. Hermes — deep review

1. **Citation:** He et al., *Hermes: Making Path-Sensitive Pointer Analysis Scalable for Sparse Value-Flow Analysis*, PACMPL 10 OOPSLA1, 2026, DOI [10.1145/3798211](https://doi.org/10.1145/3798211).
2. **Source:** [publisher DOI](https://doi.org/10.1145/3798211); `references/papers/Hermes-OOPSLA-2026.pdf`, pp. 7, 10–17, 20–22.
3. **Language/IR:** C/C++ programs lowered to pointer-analysis statements (Alloc/Phi/GEP/Load/Store/Call); its rules assume a resolved program and guarded object locators.
4. **Target:** path-sensitive pointer analysis plus sparse value-flow bug search (e.g. null dereference and leak).
5. **Mechanism:** Symbolic input objects and values represent uninstantiated memory reachable through parameters; a callee side-effect summary records symbolic locators and stored values. At calls, the summary is applied symbolically. The resulting LSEG initially omits selected interprocedural interface nodes/edges, then resolves only nodes needed for source-to-sink transfer and later path-condition reachability (Defs. 3.1, 3.5, Algorithm 1, pp. 12–16). A Value Access Graph guides access-path loading toward relevant source values (Def. 3.6, Algorithm 2, pp. 15–17). This is more specific than generic lazy graph building.
6. **Structures:** pointer/value map, guarded memory map, symbolic side-effect summary, LSEG nodes with **data and control** edges plus edge guards, VAG with offset labels, input/output/transfer summaries.
7. **Transfer:** Store/Call update symbolic locations; Load relates guarded stored values to loaded values; `ResolveFlows` adds guarded interprocedural value-flow edges for selected interface nodes. The paper's graph omits irrelevant edges *while retaining a procedure capable of resolving them* (Fig. 6, pp. 10–11; Algorithms 1–2, pp. 14–17).
8. **Termination:** finite graph/worklist under its source language and summary traversal assumptions; VAG traversal uses visited/key stopping conditions. Its paper mechanism is not a substitute for BinaryAnalysis budget/status handling (pp. 16–17).
9. **Assumptions:** soundness of pruning depends on the underlying points-to/guard relation and correctly identified potential sources/reachability conditions. A missing LSEG edge is `PENDING`, never a negative proof. Full BinaryAnalysis soundness under unknown machine effects is `NOT_VERIFIED`.
10. **Trade:** avoids exponential guarded layout materialization until bug search; selected interface expansion can still be costly and path condition reasoning remains necessary.
11. **Experiment:** 12 open-source C/C++ projects; compared with Falcon, reported mean pointer-analysis speedup at least 9.84× and bug-search speedup at least 4.79× without losing detected bugs under the paper's evaluation (abstract; §5, pp. 20–22). These are **paper measurements**.
12. **Value:** bounded lazy Store→Load edge generation later; source-to-sink queries can share C1 memory definitions.
13. **Binary obstacle:** symbolic object layout, unknown calls, mixed address spaces, byte overlap and machine guards have no equivalent guarantee from C/C++ GEP rules.
14. **Minimum contract:** stable Definition/Use and MemoryVersion IDs, guarded candidate edge/frontier, alias evidence, summary and call-graph revisions, explicit incomplete status.
15. **Stage:** C1 records real dependencies and unresolved frontier; C2 experiments with lazy expansion; full interprocedural version later.
16. **Decision:** `PREPARE_CONTRACT`. LSEG is a guarded sparse value-flow graph, **not** the present `SymbolicExprDAG`: hash-consed expression nodes do not own CFG edges, summaries or unresolved interface nodes. A separate value-flow index is warranted when a consumer needs it; do not create an unused graph now. C1 can lazily compute requested memory edges if every unvisited candidate stays pending and a negative answer requires complete expansion.

### 2. LISPA — deep review

1. **Citation:** Jiaqi He and Karim Ali, *Efficient Pointer Analysis via Def-Use Graph Pruning*, CASCON 2025 ([official session](https://conf.researchr.org/details/cascon-2025/technical-papers-track/60/Efficient-Pointer-Analysis-via-Def-Use-Graph-Pruning)). **Publisher DOI `NOT_VERIFIED`**: local/author PDF lacks it; secondary indexes report `10.1109/CASCON66301.2025.00063`, pending publisher confirmation.
2. **Source:** [author-hosted full paper](https://sanadlab.org/assets/pdf/JiaqiCASCON2025.pdf); `references/papers/LISPA-CASCON-2025.pdf`, pp. 1, 3–6, 8–10.
3. **Language/IR:** C/C++ LLVM partial SSA; pointer levels estimated with Steensgaard-style preanalysis (p. 3).
4. **Target:** flow-sensitive points-to computation with fewer redundant SSA temporary points-to sets.
5. **Mechanism:** identifies intermediate values whose points-to sets are copies of existing address-taken variables. Rather than solve those temporary sets, it redirects their def-use edges to the temporary's uses. It retains address-taken variable definitions, dominance/iterated-frontier joins and pointer-level processing (pp. 3–5).
6. **Structures:** pointer levels, dominance graph, def-use graph (DUG), points-to sets for retained variables, gen/kill sets.
7. **Transfer:** redirected def-use edges preserve a *proved copy* relation; strong update kills incoming definitions only under its pointer-analysis assumptions; weak stores retain use/def information. Call argument/return edges extend the DUG (pp. 4–5).
8. **Termination:** fixed point over DUG per descending pointer level, finite points-to domain (pp. 2–5).
9. **Assumptions:** classification of an SSA temporary as semantics-preserving copy and complete def-use edges. It does **not** authorize dropping arbitrary CIR computations or opaque effects.
10. **Trade:** fewer points-to sets and graph updates; preanalysis and redirected-edge witness are extra work.
11. **Experiment:** 27 real C/C++ programs; mean 2.14× runtime and 2.38× memory improvement versus LEVPA, the paper's predecessor (abstract; §IV, pp. 8–10). No binary result is claimed.
12. **Value:** later def-use index optimization, especially redundant VEX WrTmp copies.
13. **Binary obstacle:** VEX temporaries may encode address arithmetic, truncation/extension, endian-dependent load, partial register write, guard or UnknownEffect. Three counterexamples: `t = base + 4; Load(t)` cannot bypass `t` without preserving `+4`; `t = zext32(ptr); Store(t, v)` changes pointer interpretation; `t = Load(p); Store(q,t)` is a memory-version dependency, not a pure copy. A guarded ITE and subregister write are further counterexamples.
14. **Minimum contract:** typed Compute/ReadRegister/WriteRegister/Load/Store roles, value width, ordered EffectId, Def/Use edges, guard, memory version, provenance of every redirected edge.
15. **Stage:** C2 optimization experiment after C1 baseline.
16. **Decision:** `EXPERIMENT_LATER`; prune only a proven pure value copy, retain a witness chain to skipped effects and compare against unpruned answers. Register aliases and pointer arithmetic prevent a blanket WrTmp rule.

### 3. IDEDroid — deep review

1. **Citation:** Li et al., *Boosting the Performance of Alias-Aware IFDS Analysis with CFL-Based Environment Transformers*, PACMPL 8 OOPSLA2, 2024, DOI [10.1145/3689804](https://doi.org/10.1145/3689804).
2. **Source:** [publisher DOI](https://doi.org/10.1145/3689804); `references/papers/IDEDroid-OOPSLA-2024.pdf`, pp. 4–5, 7–11, 18–22.
3. **Language/IR:** Java/Android app statements and field accesses, IFDS/IDE exploded supergraph.
4. **Target:** field-sensitive alias-aware taint with smaller data-fact domain.
5. **Mechanism:** explicit access-path fact explosion is recast as a CFL balanced-field reachability condition. IDE edge functions act as environment transformers that symbolically compose field operations; a path is accepted when the transformer/field language admits it (§2.2–3.3, pp. 4–9).
6. **Structures:** IFDS facts, exploded supergraph, field-labelled edges, CFL grammar/reachability, IDE edge functions and summaries.
7. **Transfer:** field load/store generate transformer operations; sequential edges compose functions and joins combine alternatives. Alias information controls field-sensitive propagation (pp. 7–11).
8. **Termination:** finite IFDS/IDE fact and function domains with tabulation; BinaryAnalysis's unbounded symbolic offsets do not inherit this finiteness automatically.
9. **Assumptions:** Java field identity and supported Android semantics; the reported precision guarantee is relative to its access-path formulation, not a proof about arbitrary binary addresses.
10. **Trade:** fewer explicit facts with transformer composition cost; relation is a solver representation, not a new MemoryObject ontology.
11. **Experiment:** 24 Android apps versus FlowDroid; reported 2.1×–2368.4× speed range, mean 222×, and up to 20% fewer false positives in paper setup (abstract, §5). Do not transfer figures to C/C++ binaries.
12. **Value:** later path transformer strategy over shared Store/Load facts; existing APG can provide access-path terms but is not an IFDS/IDE solver.
13. **Binary obstacle:** `base+offset` may have symbolic/unknown offset, wraparound, endian and partial-byte overlap. Java field concatenation cannot encode these without a byte-range relation and unknown transformer outcome.
14. **Minimum contract:** stable access-path/byte-range semantics, guarded MemoryVersion, typed Def/Use, alias and overlap evidence, finite/abstracted transformer domain, explicit unknown.
15. **Stage:** C3 research prototype, after C1 and a representative field-like subset.
16. **Decision:** `EXPERIMENT_LATER`; CFL transformer is an analysis strategy, not a replacement for memory-object or access-path identity.

### 4. Merge-Replay — deep review

1. **Citation:** Gui, He and Xue, *Merge-Replay: Efficient IFDS-Based Taint Analysis by Consolidating Equivalent Value Flows*, ASE 2023, DOI [10.1109/ASE56229.2023.00027](https://doi.org/10.1109/ASE56229.2023.00027).
2. **Source:** [author repository record](http://hdl.handle.net/1959.4/105888); `references/papers/Merge-Replay-ASE-2023.pdf`, PDF pp. 2, 7–9, 11–12.
3. **Language/IR:** Android Java/FlowDroid IFDS facts.
4. **Target:** coupled backward alias and forward taint solver.
5. **Mechanism:** a fact is `(data abstraction, activation statement)`; forward taint and backward alias worklists inject facts into each other. At selected callsites, facts with the same abstraction receive a symbolic activation, with concrete activations retained. Replay reconstructs relevant concrete facts before activation, and call-context matching prunes spurious flows (Algorithm 1–2, PDF pp. 7–9).
6. **Structures:** forward/backward path edges and summaries, `Symb2Reps`, `SymbolIncoming`, symbolic activation/context.
7. **Transfer:** backward alias propagation creates inactive facts; forward propagation activates and propagates them. Merge carries representative activation set; replay materializes originals on corresponding return/call paths (pp. 7–9).
8. **Termination:** both finite worklists empty; merge at callsites limits overhead. Replay is not allowed to silently discard a represented fact.
9. **Assumptions:** theorem of result preservation applies to its specific algorithm **before** additional context pruning (Theorem 1, PDF p. 9); BinaryAnalysis fact-equivalence proof remains open.
10. **Trade:** fewer duplicate path edges, bookkeeping/replay cost; context-aware pruning improves its paper precision.
11. **Experiment:** 40 Android apps considered; comparison to FlowDroid; among 34 completed by both, average memory reduction 5.2× (PDF p. 12). Time and precision figures are paper-specific; do not treat all 40 as paired completed runs.
12. **Value:** future duplicate demand/taint flow suppression with recoverable evidence.
13. **Binary obstacle:** the same expression can depend on different MemoryVersions, guards, source sites or call contexts; dropping them can remove real Store→Load edges.
14. **Minimum contract:** separate ExpressionId, AnalysisFactId `(program point, context, memory version, guard, source/evidence, activation, status)`, and ValueFlowDependencyId; representative-to-members map and replay frontier.
15. **Stage:** C3 after canonical dependency facts and cross-call context.
16. **Decision:** `EXPERIMENT_LATER`. SSE hash consing proves only identical expression-node keys, not fact equivalence. Different versions, guards, contexts or source evidence remain distinct unless a proven abstraction and replay witness preserve every observable dependency.

### 5. SILVA — deep review

1. **Citation:** Wang et al., *SILVA: A Scalable Incremental Layered Sparse Value-Flow Analysis*, TOSEM 34(8), 2025, DOI [10.1145/3725214](https://doi.org/10.1145/3725214).
2. **Source:** [publisher DOI](https://doi.org/10.1145/3725214); `references/papers/SILVA-TOSEM-2025.pdf`, pp. 3–5, 11–20, 22–28.
3. **Language/IR:** C/C++, LLVM-like Andersen constraints, sparse value-flow and Mod-Ref summaries.
4. **Target:** incremental layered SVFA after code changes.
5. **Mechanism:** update flow/context-insensitive points-to constraints under edge deletion/insertion, SCC/topological propagation and deferred point-set changes; maintain provenance bindings from derived CopyEdges to their deriving Load/Store/copy constraints, deleting a derived edge only when its binding set empties (Fig. 8–9, pp. 13–15). Incremental function-summary analysis separates intra-procedural summary contributions from call-derived inter-procedural contributions. It clears deleted elements along the old CG, re-adds along the new CG in SCC-aware bottom-up order, and propagates to callers only when the overall summary changes (Algorithms 3–5, pp. 21–24). Mod-Ref instantiates this scheme (§4.3.2).
6. **Structures:** constraint graph, points-to sets, SCCs, edge-derivation binding map, change queues, call graph, Mod/Ref summaries, memory SSA/sparse value-flow graph.
7. **Transfer:** changed address/copy/load/store constraints alter points-to sets; function pointer changes alter indirect call edges (Algorithms 1–2, pp. 10–20). For summaries, a callee contribution is filtered through a call-specific operation before union into the caller's inter-summary; a removed contribution does not delete a still locally or multiply derived summary element (Fig. 12 and Algorithms 3–5, pp. 21–24). Mod/Ref changes then invalidate affected sparse edges and caller queries.
8. **Termination:** finite changed-edge and point-set queues reach fixed point; insertions include SCC maintenance (pp. 12, 19–20).
9. **Assumptions:** proofs compare incremental and full results for its Andersen constraints; unsupported binary instructions, new frontend mapping and unknown dependency footprints are outside that equivalence.
10. **Trade:** retain dependency/provenance indexes and invalidation complexity to avoid full recomputation; large changes can erase benefit.
11. **Experiment:** five C/C++ projects; mean 7× incremental SVFA versus full SVF on selected commits (Table 4, p. 28); paper also reports PTA/MRA comparisons in §6. These are not projected BinaryAnalysis gains.
12. **Value:** explicit derivation support is a design warning for future cache invalidation; C1 should fingerprint result dependencies.
13. **Binary obstacle:** call target and memory relation revisions can change without source-code edits; uncertain effects produce unknown footprints, requiring broad invalidation.
14. **Minimum contract:** stable artifact/function/CFG/CG/policy revisions, dependency edges with all derivations, unknown footprint marker, result/cache fingerprint and reload check.
15. **Stage:** C1 basic invalidation correctness; C3 selective incremental recomputation.
16. **Decision:** `PREPARE_CONTRACT`; do not implement SILVA's whole points-to/Mod-Ref engine in C1.

## Supplemental positioning (five files, although task text calls them four)

| Paper and source | Language / target and mechanism | Structures, transfer, termination and proof boundary | Evidence, migration and classification |
|---|---|---|---|
| Ma et al., *Context Sensitivity without Contexts*, PLDI 2023, [DOI 10.1145/3591242](https://doi.org/10.1145/3591242), local `Cut-Shortcut-PLDI-2023.pdf` pp. 1–4, 9–15 | Java pointer analysis. Suppress imprecise pointer-flow edges and add source-to-target shortcuts for three characterized call patterns, instead of cloning contexts. | Pointer-flow graph; flow-edge replacement to fixed point. Soundness is proved for its patterns, not unknown binary calls. | Doop/Tai-e comparisons to context-insensitive and selective/context-sensitive analyses (§6); exact aggregate speedup not asserted here. Requires callsite provenance and proof of cut/shortcut equivalence. C3 `EXPERIMENT_LATER`. |
| Yang et al., *Cut-Shortcut Whole-Program Pointer Analysis*, TPLS 2026, [DOI 10.1145/3818615](https://doi.org/10.1145/3818615), local `Cut-Shortcut-TPLS-2026.pdf` pp. 1–3, 16–24 | Expanded Java Cut-Shortcut with CFL formulation and more call patterns. | Refined pointer-flow graph; fixed-point reachability under paper rules. Earlier PLDI work is explicitly cited as overlap, so not an independent BinaryAnalysis replication. | Paper comparisons to context-sensitive baselines; exact aggregate result `NOT_VERIFIED` in this bounded review. Same binary obstacles; C3 `EXPERIMENT_LATER`. |
| Zhang et al., *Towards a Theoretically-Backed and Practical Framework for Selective Object-Sensitive Pointer Analysis* (Moon), OOPSLA 2025, [DOI 10.1145/3763111](https://doi.org/10.1145/3763111), local `Moon-OOPSLA-2025.pdf` pp. 1–3 | Java pointer analysis. Backward/forward VFG traversal finds objects likely to benefit from object sensitivity. | VFG/PFG reachability, selected objects and context-sensitive propagation to fixed point. Its upper-bound theory relies on its object model. | 30 Java programs; paper reports 37.2× / 382.0× versus 2/3-object-sensitive analyses with 0.1% / 0.2% precision loss. Needs stable heap allocation identity/context and graph witness; C3 `EXPERIMENT_LATER`. |
| Chen et al., *PacDroid*, ICSE 2025, [DOI 10.1109/ICSE55347.2025.00208](https://doi.org/10.1109/ICSE55347.2025.00208), local `PacDroid-ICSE-2025.pdf` pp. 1–3, 9–12 | Android Java security framework puts pointer analysis at center so alias, interprocedural values and Android lifecycle/ICC facts share one propagation substrate. | Pointer/call/taint facts and domain models to fixed point; Android model coverage bounds soundness. | Compared to FlowDroid/IccTA/P-Taint/Amandroid/DroidSafe in paper; 77 additional flows across 23 apps claimed (abstract). Transfer *shared semantic facts*, not Android lifecycle machinery. C2 `PREPARE_CONTRACT`. |
| Christakis et al., *Testing Static Taint Analyzers with Equivalence Modulo Taint* (TaintCC), ISSTA 2026, [DOI 10.1145/3832231](https://doi.org/10.1145/3832231), local `TaintCC-ISSTA-2026.pdf` pp. 1–3, 8–16 | Metamorphic testing, not an analysis transfer algorithm. Taint-preserving program variants must preserve source/sink flow oracle. | Transformation relation and flow-result comparison; finite generated cases, with preservation assumptions per transform. | Four analyzers, 16 developer-confirmed issues (abstract). Apply only after proving a binary/CIR transformation preserves relevant guards, memory and source/sink semantics; C2 validation experiment `EXPERIMENT_LATER`. |

For the supplemental records, a production-level transfer function or full proof adaptation to binary IR is `NOT_VERIFIED`; the table records the interface boundary rather than inventing one. Cut-Shortcut's Java call patterns and Moon's object model do not justify a C1 pointer precision policy. PacDroid's design principle does not make BinaryAnalysis an Android analysis framework. TaintCC is a verification method, not a new taint solver.

**Supplemental field completion (the table supplies fields 1–2, 4–5, 9, 11–16):**

| Paper | 3. Source IR | 6. Data structure | 7. Transfer/propagation | 8. Termination | 10. Precision/performance trade and 14. minimum contract detail |
|---|---|---|---|---|---|
| Cut-Shortcut PLDI | Java pointer-flow representation in Doop/Tai-e (§2, §6) | PFG with suppressed and shortcut edges | Propagate object flow over the modified PFG; only pattern-justified cuts | PFG points-to fixed point | Fewer context clones, but only proven cut patterns; callsite/flow-edge identity, proof and original-to-shortcut provenance required. |
| Cut-Shortcut TPLS | Java/Tai-e pointer-flow representation (§2, §8) | Refined PFG and CFL formulation | Suppress imprecise edges and add safe shortcuts, including expanded language patterns | Points-to propagation to fixed point (p. 4) | Context precision without full cloning for supported patterns; same graph/revision and cut evidence requirements. |
| Moon | Java PFG/VFG (§2–4) | VFG plus selected object/context map | Backward and forward reachability identifies sensitivity candidates; selected objects receive context-sensitive propagation | Finite graph/points-to fixed point | Selection reduces cost with measured small precision loss; allocation site, call context, graph witness and baseline comparison required. |
| PacDroid | Android Java app analysis IR; exact internal IR schema `NOT_VERIFIED` here | Unified pointer/semantic fact store; exact implementation layout `NOT_VERIFIED` | Pointer facts inform aliases, interprocedural values and security clients; exact transfer rules `NOT_VERIFIED` in this positioning review | Exact termination algorithm `NOT_VERIFIED` | Domain-model coverage and cost trade depend on Android features; shared fact identity, provenance, model revision and distinct client results required. |
| TaintCC | Java/Python/Android analyzer inputs; no common analysis IR | Program variants, transformations and paired flow reports | Transform input while preserving or predictably changing taint flows; compare analyzer outputs | Finite generated test set, **not** a dataflow fixed point | Oracle validity depends on proved transformation relation; transformation provenance, source/sink policy and result comparison contract required. |

## Legacy and R1-B comparison

| Dimension | Local legacy EmTaint evidence | Current BinaryAnalysis / R1-B proposal | Transfer conclusion |
|---|---|---|---|
| Forward/backward | VEX action-driven `TraceExpr`/`VarExpr` queues alternate with bounded passes; ten-pass cap is not a fixed-point proof (`research/legacy/LEGACY_DATAFLOW_ALGORITHM_AUDIT.md` §SSE). | `analysis/sse/dag.py` has expression hash consing and lazy substitution; R1-B proposes shared Def/Use/Memory dependencies. | Establish one queryable relation in C1. Hermes LSEG and Merge-Replay require distinct graph/fact identities later. |
| Alias | Seeded Store/Load substitutions; inactive collector can report NoAlias from absent candidates (audit §Alias). | Typed location/version model exists; `analysis/aliasing/query.py` can still return complete `NOALIAS` after filtering uninitialized pointers. | P0 false-negative risk remains. Modern pruning cannot hide unresolved locations. |
| Context and calls | Heuristic iCall collection and mutable procedure effects, no versioned refined CG proof (audit §iCall/taint). | Architecture proposes CG revisions and summaries; not implemented as a full shared solver. | Hermes, Cut-Shortcut and Moon wait for call/context identity and proof witnesses. |
| Incrementality | No tracked derivation graph in audited legacy path. | Artifact/cache boundaries proposed; memory archive is not a complete dependency result. | SILVA motivates stable derivations and invalidation, not immediate incremental PTA. |

`FUTURE_RESEARCH`: APA, Valve and cross-language analysis, only after C1 witness and explicit owner scope. No algorithm above is adopted as a ready-made binary implementation.
