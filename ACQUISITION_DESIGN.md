# Acquisition, Artifact, Cache and Analysis Result Design

## 1. Keep the concepts separate

**Acquisition** is the reproducible process that resolves inputs,
invokes selected frontends, normalizes their outputs, captures
provenance and builds persistent analysis-input artifacts.

**Artifact** is an immutable, versioned, integrity-checked
representation produced by acquisition or analysis.

**Cache** is the mechanism that reuses an artifact/result when its
dependency fingerprint is still valid.

**Analysis Result** is computed by an analysis algorithm, e.g. CG,
Alias, Dataflow, Taint or Vulnerability.

**Debug/Evidence Artifact** records provenance, rule events, causal
dependencies and explanations.

Acquisition is not merely a cache. Cache is one capability around
artifacts.

## 2. Lifecycle

``` text
Project Inputs
   -> Input Resolution
   -> Fingerprint
   -> valid Acquisition Artifact?
       yes -> load
       no  -> run Frontends -> normalize HIR/CIR -> capture provenance
             -> validate -> staging -> atomic publish
   -> Analysis Engine
       -> Analysis Result Store/Cache
       -> Debug/Evidence Store
```

`analyze` should reuse a valid artifact or trigger Acquisition
automatically. An explicit `acquire` command remains useful for
precomputation and diagnosis.

## 3. Manifest

Proposed manifest fields (not finalized): - manifest/artifact schema
version - project and binary identity/hash - binary format,
architecture, endian, loader configuration - external input hashes (IDA
CFG, IDB/export metadata, symbols/types) - frontend
name/version/configuration fingerprint - HIR/CIR/provenance schema
versions - artifact chunk IDs and hashes - completeness:
requested/acquired functions, unsupported nodes, partial functions -
build diagnostics and timestamps

## 4. Fingerprints

Acquisition fingerprint includes semantic inputs: - binary content
hash - loader/relocation config - relevant metadata hashes - frontend
name and exact version - frontend config - normalization/lowering
version - HIR/CIR/provenance schema versions

Do not include presentation-only IDA display base if it does not affect
stored canonical semantics.

Analysis result fingerprint additionally includes: - input artifact
IDs - algorithm/version - budgets/options - summaries and summary
version - source/sink/policy configuration - dependency result IDs

Use a dependency DAG for invalidation. A taint policy change should not
rerun VEX lifting; a frontend/lowering change should invalidate
dependent CIR and downstream results.

## 5. Granularity

Consider binary/module metadata, segments, frontend export bundles,
per-function HIR/CIR, per-function provenance, module-level
types/symbols/relocations, and derived analysis results. Do not create
one file per tiny object without a concrete need. Preserve
cross-function consistency.

## 6. Persistence/recovery

-   Write to a unique staging location.
-   Validate schema and hashes.
-   Write manifest last.
-   Atomically publish completed artifact.
-   Coordinate concurrent builds for same fingerprint with a lock/lease.
-   Never mutate a valid artifact in place.
-   Distinguish missing, stale, corrupt, partial and incompatible
    artifacts.
-   Document resume/discard behavior for interrupted builds.
-   Garbage collection must respect dependency references and retention
    policy.

## 7. IDA/Hex-Rays boundary

Run Hex-Rays extraction in an IDA-compatible environment or exporter.
The analysis process consumes serialized interchange artifacts, not live
Hex-Rays objects. Preserve IDA/Hex-Rays version, database/input
identity, function EA, node identity, type serialization, extraction
errors and unsupported nodes. Do not pickle SDK objects.

## 8. Analysis Result Cache

Examples: - CG result: acquisition program/callsite artifact + call
resolution config/version. - Alias result: memory/program artifact +
alias algorithm version + query + budget. - Taint result: relevant
dataflow/memory artifacts + summaries + source/sink policy + taint
version. - Vulnerability result: analysis evidence + rule version +
validation config.

Every result identifies exact dependency artifact IDs and algorithm
versions.

## 9. Proposed interfaces

``` text
binaryanalysis acquire --project project.yaml
binaryanalysis analyze --project project.yaml --analysis taint
binaryanalysis artifact inspect <artifact-id>
binaryanalysis cache list --project project.yaml
binaryanalysis cache prune --project project.yaml
binaryanalysis debug explain <object-id>
```

Names are provisional and should be reconciled with current CLI during
audit.
