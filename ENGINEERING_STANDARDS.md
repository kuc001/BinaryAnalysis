# Engineering Standards and Quality Policy

## 1. Design before implementation

For cross-cutting work: state outcome/non-goals, inspect consumers, draw
dependencies, define contracts/schema/identity, specify failure and
partial behavior, split into reviewable milestones, and obtain approval
for core IR changes. Do not create empty skeletons first.

## 2. Python standards

-   Type annotations for public and cross-module APIs.
-   Clear semantic names; avoid cryptic one-letter names.
-   Docstrings for public APIs and explanatory comments for non-obvious
    algorithms.
-   Small functions with explicit inputs/outputs.
-   No hidden import-time work or accidental global state.
-   No broad exception swallowing or silent fallback.
-   Explicit enums/typed records for semantic states.
-   Deterministic, versioned serialization.
-   No unnecessary abstractions or dependencies without a concrete
    consumer.

## 3. Boundaries

-   Frontend SDK objects stay inside adapters.
-   HIR/CIR contracts do not import IDA/angr runtime modules.
-   Analysis algorithms consume normalized contracts.
-   Storage does not own analysis semantics.
-   Cache reuses results but does not define semantic truth.
-   CLI orchestrates application services.
-   Debugging is read-only by default.
-   Avoid circular imports.

## 4. Semantic correctness

Distinguish confirmed, recovered, inferred, conservative, unknown,
incomplete, unsupported, timeout and error. Never equate MayAlias with
MustAlias, candidate taint path with confirmed vulnerability, decompiler
type with binary truth, missing provenance with no provenance, or
unsupported lowering with a no-op.

## 5. Identity and schema

-   Do not casually change identity semantics.
-   Version schemas and document migration.
-   Keep source-node IDs separate from canonical IR IDs.
-   Keep RVA, IDA EA/VA, runtime VA and file offset distinct.
-   Preserve many-to-many provenance and conflicts.
-   Never infer mappings from sequential IDs or nearby addresses.

## 6. Verification after reset

The requested cleanup removes legacy `tests/` and `scripts/`. This does
not make correctness optional. The owner must approve a new verification
policy. Recommended: discard legacy tests as architecture drivers, then
establish a fresh suite around approved contracts, representative
binary/decompiler fixtures, frontend differential checks and end-to-end
scenarios. Benchmarks should be separate from unit tests. Do not
disguise old tests under another folder name. If the project chooses to
remain testless, record that as an accepted engineering risk.

## 7. Review checklist

-   Clear contract and ownership?
-   Unsupported/partial paths explicit?
-   Provenance/confidence retained?
-   Schema/fingerprint/invalidation correct?
-   Persistence atomic and recoverable?
-   No frontend SDK dependency in analysis core?
-   No unrelated scope?
-   Documentation accurate?
-   Verification claims backed by actual commands/results?

## 8. Performance

Measure before optimizing. Prefer demand-driven alias refinement with
budgets. Cache immutable expensive frontend artifacts. Bound debug
traversal/event volume. Expose truncation, budget exhaustion and partial
results explicitly.
