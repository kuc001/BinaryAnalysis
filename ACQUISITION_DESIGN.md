# Acquisition, artifacts and caches — A2 proposal

Status: **Proposed**, pending ADR-004/010/012 and owner approval. Current `scripts/p7_acquire.py` and `frontends/function_store.py` are fixed-layout acquisition/reader implementations, not this service.

## 1. Ownership and interfaces

Acquisition Service resolves project inputs, selects independent or joint frontends, requests exports, validates/lower representations and publishes **analysis inputs**. Frontend Export is immutable IDA CFG/VEX, CTree or future Microcode source data with producer/version and completeness. HIR Artifact stores structured high-level semantics; CIR Artifact stores common effects; Provenance Artifact stores mapping edges/conflicts. Module metadata contains binary/loader/segments/symbol/type input facts. Artifact Store holds immutable bytes and manifests. Acquisition Cache maps semantic build keys to validated artifact IDs; it is an index, not a source of truth.

Analysis Result Store holds computed CFG refinements/CG, def-use, MemoryVersion, alias, summaries, taint and vulnerability results with exact input IDs and algorithm configuration. Analysis Result Cache keys those computations. Debug/Evidence Store holds trace, query events, provenance projections and explanations linked to result IDs. Neither Analysis Results nor Debug artifacts are inputs to Acquisition. A stored source CFG hint is acquisition data; a resolved CG edge is an analysis result.

Logical typed interfaces: `resolve(ProjectSpec)->ResolvedInputs`; `acquire(ResolvedInputs, FrontendSelection)->AcquisitionRef`; `load(AcquisitionRef, FunctionId)->FunctionInputs`; `analyze(FunctionInputs, AnalysisSpec)->ResultRef`; `inspect(ref)->StoredEvidence`. Each returns status/diagnostics, never silently launches analysis from inspect. Package placement follows actual consumers after contract approval.

## 2. Identity and manifest schema

Module manifest contains `manifest_schema_version`, project/binary content ID, format/architecture/endian/ABI, loader and relocation inputs, typed address conversion metadata, selected frontends and exact exporter/IDA/Hex-Rays/angr/lowering versions, source/HIR/CIR/provenance schema versions, build key, function table, module metadata references, dependency edges, completeness, unsupported/failed function list, diagnostics and publish generation. Each function entry contains FunctionId, source export IDs, HIR ID when applicable, CIR ID, provenance ID, CFG input ID, all content hashes and dependency IDs. The manifest does not pretend every function has every frontend.

Artifact identity is `(kind, schema version, content hash)` plus manifest dependency references. The hash covers deterministic canonical bytes; cross-version hashes never imply semantic compatibility. Function identity uses binary ID and RVA with explicit non-address identities for synthetic functions; source node IDs also include export fingerprint and function scope. Module symbols/types/relocations are separate chunks to avoid needless per-function copying. A failed function has an explicit status record, never a missing row interpreted as complete.

## 3. Fingerprints and dependency graph

Use two levels. **Module Identity** records Binary SHA256, architecture, ABI, loader configuration and module metadata identity. It identifies the binary universe and validates cross-function references; it is **not automatically an input to every function semantic cache key**. **Function Semantic Fingerprint** contains function code-byte hash, boundaries/mode, relevant relocations and metadata, exact frontend/version/maturity/options, relevant type/symbol dependencies, and lowering/schema version (or separate dependent lowering key). Function artifact references still carry Module Identity and BinaryId for provenance and compatibility. A binary SHA256 change with unchanged function bytes and unchanged relevant dependencies can reuse a function artifact under an explicit rebinding/identity policy; it must not blindly reuse old binary-scoped IDs. Rebinding creates a new identity-qualified manifest/provenance reference and validates loader/address conversions. If the dependency footprint, loader effect or identity rebinding cannot be proven, conservatively invalidate at module level.

CTree exports additionally include database state relevant to decompilation, user type/rename annotations and target SDK version. If dependencies cannot be enumerated safely, conservatively depend on the whole source database/export hash. Presentation-only pseudocode styling is a separate display artifact; IDA image base enters keys whenever it affects exported address mapping.

HIR key = source export ID + HIR schema/normalizer version. CIR key = HIR or VEX/Microcode source ID + lowering/ABI/schema versions. Provenance key = all mapped source IDs + mapping algorithm/version and address conversion inputs. Module manifest key = selected function artifact IDs and module metadata IDs. Analysis result key = exact acquisition IDs + algorithm/policy/budget/version + dependent summary/result IDs. Debug/evidence key = result/source IDs + trace schema/options, and does not change analysis truth.

```text
binary/loader/IDA metadata -> frontend export -> HIR -> CIR -> analysis result
                                      |             |         |
                                      +-- provenance+---------+-> evidence
module symbols/types ------> affected function exports/HIR/CIR
callee summary ------------> caller summary/CG/taint result
taint policy ---------------> taint/vulnerability only
```

Changes invalidate descendants only. Cross-function dependencies record callee ID, summary version, callsite, global/type references and uncertainty. Unknown dependency scope triggers conservative module-level invalidation. A frontend change need not rebuild an unrelated frontend export; policy change never reruns lifting. Recompute cyclic summary SCCs to a bounded fixed point and mark budget exhaustion partial.

## 4. Multi-frontend acquisition and compatibility

Frontends independently publish source exports, then the service assembles a function's available representations. CTree→HIR→CIR and VEX→CIR may coexist; neither silently replaces the other. Future Microcode→CIR follows the same contract. A combined view is an analysis selection referencing immutable per-frontend CIR IDs and a reconciliation/provenance result; conflicting effects remain explicit. One selected primary CIR per query plus corroborating evidence is the initial implementation recommendation; multi-CIR fusion requires its own approved semantics.

Compatibility checks require matching binary ID, architecture/ABI, address conversion context, accepted schema major versions and an explicit converter for older minor versions. Historical CIR-Wire-v1 and P7 acquisition may be imported through a versioned migration adapter only after validation; they cannot be declared compatible by filename or hash alone. Schema mismatch returns INCOMPATIBLE. Display pseudocode is retained for people but not parsed for semantics.

## 5. Atomic publish, concurrency and recovery

For a key, acquire a scoped cross-process lock/lease with owner, PID, nonce and expiry; recheck cache after lock. On Windows, use a real interprocess file lock or exclusive-create lock file with verified stale-owner recovery, not an in-memory mutex. Stage and publish on the **same volume**; write chunks to a unique staging directory, flush files and manifest, validate schema/references/hashes, write manifest last, then publish an immutable generation by same-volume rename to a previously absent destination. Windows rename/replace behavior differs when destinations exist or files are open, so never require overwriting a live generation; publish a new unique generation and atomically replace only the small cache pointer with a supported platform primitive or lock-protected compare-and-swap. Readers pin a generation and validate its manifest. Treat sharing violations and antivirus/file-indexer races as retriable with bounded backoff; after retry exhaustion return a visible error. Never assume directory rename alone is durable against power failure; recovery verifies manifest and hashes. A lease loser reuses the winning validated generation. On crash, staging is inspected by hashes/dependency IDs: resume only deterministic compatible chunks; otherwise quarantine/discard staging. Expired lease can be stolen only after validating the incumbent state. Partial manifests are explicitly published only for requested partial operation and never satisfy a complete request.

Load distinguishes MISSING, STALE, CORRUPT, INCOMPATIBLE, PARTIAL and VALID. Corruption is quarantined and rebuilt when inputs are available; no cache hit bypasses hash/schema validation. Garbage collection retains referenced generations and in-flight leases. Per-function rebuild publishes a new module manifest generation; readers pin the old generation until the new one is complete.

## 6. CLI/use case and acceptance

Target `python -m emtaint analyze --project project.yaml`: resolve project and requested frontend/analysis, validate acquisition cache, acquire missing or stale function artifacts, pin a manifest generation, then compute/reuse analysis results and link evidence. Target explicit `python -m emtaint acquire --project project.yaml` performs the same acquisition without analysis. Names are design targets; current CLI does not implement them. Acquisition never depends on P1–P7 paths or fixed firmware.

Acceptance for later implementation: unchanged inputs reuse exact IDs; a changed type invalidates affected functions and dependents; changed taint policy retains acquisition IDs; concurrent identical requests publish one valid generation; interrupted staging never appears valid; schema/corruption/partial states are observable; independently acquired CTree and VEX survive reload outside IDA; inspection performs no analysis query. No tests were run in A2.
