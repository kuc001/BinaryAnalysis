# BinaryAnalysis Reset and Rebuild --- Living Execution Plan

This is a delivery sequence, not a replacement P1--P7 architecture. Each
milestone needs explicit approval.

## Milestone A --- Repository audit and design decisions

Inventory packages, CLI, schemas, dependencies, persistence, CI, docs
and all production code. Trace imports from `scripts/`; map old tests
and reusable fixtures; assess modules KEEP/REFACTOR/REPLACE/REMOVE;
decide CIR/HIR and CTree integration; design artifact/cache lifecycles.

Deliver: `REPOSITORY_AUDIT.md`, approved `ARCHITECTURE.md`,
`ACQUISITION_DESIGN.md`, `DECISIONS.md`.

Exit: no classification based only on filenames; removal impact
documented; unresolved decisions visible; owner approves reset.

## Milestone B --- Safe repository reset

Migrate any production functionality out of `scripts/`; inspect
CI/CLI/docs/packaging references; remove legacy tests/scripts and P1--P7
artifacts only after approval; preserve package/entry points; update
ignore rules and docs.

Exit: no production imports or supported commands depend on deleted
scripts; no stale normative P1--P7 instructions; verification policy
approved.

## Milestone C --- Stable contracts

Define project/input identity, frontend contract, address spaces,
artifact manifest, schema versions, provenance, confidence/completeness,
HIR/CIR boundary.

Exit: ownership, serialization and compatibility are explicit; no SDK
object leaks into shared contracts.

## Milestone D --- Acquisition and Artifact Store

Implement input resolution, frontend selection, fingerprinting, artifact
build, staging/atomic publish, integrity checks, concurrent
coordination, partial recovery, artifact inspection, automatic reuse
from analyze.

Exit: identical semantic inputs reuse artifacts; changed dependencies
invalidate correct descendants; partial/corrupt artifacts are not
treated as valid.

## Milestone E --- Frontends and HIR

Stabilize binary frontend adapters; implement IDA-side structured CTree
export; define serializable HIR; preserve local-variable identity,
types, call target expressions, source locations and unsupported nodes.

Exit: CTree is structurally extracted; HIR independent of Hex-Rays
runtime; decompilation errors and partial extraction explicit.

## Milestone F --- CIR and provenance

Audit/evolve CIR; implement HIR-to-CIR and VEX-to-CIR contracts; plan
Microcode adapter; implement many-to-many provenance and
confidence/conflict records.

Exit: common analysis API accepts selected frontend outputs; no silent
semantic loss; provenance can be traversed both directions where
recorded.

## Milestone G --- Shared analysis

Rebuild/retain program graph, dataflow, memory objects/access paths,
on-demand alias, solver, interprocedural summaries, taint and
vulnerability evidence on approved contracts.

Exit: no frontend-specific analysis engines; uncertainty and evidence
retained.

## Milestone H --- Debugging and evaluation

Cross-representation inspectors, causal events, address translation,
artifact/result CLI, human reports, representative binary and decompiler
scenarios, performance and incremental reuse evaluation.

Exit: findings trace to source evidence where available; inspection
read-only; address spaces explicit; verification evidence reported
honestly.

## Execution rules

One milestone has one approved scope. Parallelize only independent
research or isolated adapters after contracts are stable. Keep
`DECISIONS.md` and `BUILD_LOG.md` current. Commit coherent units after
review. Stop at major owner decisions.
