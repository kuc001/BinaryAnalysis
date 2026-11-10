# Engineering Standards and Quality Policy

## 1. Design before implementation

For cross-cutting work: state outcome/non-goals, inspect consumers, draw
dependencies, define contracts/schema/identity, specify failure and
partial behavior, split into reviewable milestones, and obtain approval
for core IR changes. Do not create empty skeletons first.

Use the seven gates in `CODEX_WORKFLOW.md`: baseline, architecture,
data contracts, module boundaries, vertical slice, system verification,
and architecture compliance review. A proposed ADR is not a frozen
contract. Work on a dependent consumer waits for the owner to approve
the boundary or an explicitly scoped exception. Classify findings
P0/P1/P2 and use an Architecture Change Request for frozen contracts.

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
-   End-to-end input→artifact→analysis→result/evidence path checked?
-   No unsupported/unknown state converted to a successful negative result?
-   Task dependencies, scope and frozen-contract approvals recorded?

## 8. Definition of Done and system evidence

For a complex capability, all of the following must be present before
`VERIFIED`:

1.  Approved task goal, scope, non-goals, dependency list and acceptance
    witnesses; baseline and applicable freeze gates recorded.
2.  Typed contract and owner for each stage in its actual data path:
    input/acquisition, frontend, HIR/CIR/provenance, program/memory/
    analysis, persistent result/cache, evidence and consuming CLI/debug
    path as applicable. An explicitly narrower task names its endpoint
    and leaves downstream capability unclaimed.
3.  Supported, partial, unsupported, unknown, failure and budget paths
    handled without silent semantic loss; identity, schema compatibility
    and invalidation behavior documented.
4.  Relevant local, integration and representative system checks run
    with exact commands, exit codes and observations. Cross-frontend or
    persisted-reload checks are required when the slice crosses those
    boundaries. A passing local test alone is insufficient.
5.  Diff and architecture compliance review: dependency direction,
    provenance/confidence, artifact/result separation, scope and
    documentation checked; issues resolved or explicitly retained.
6.  `BUILD_LOG.md`, `BACKLOG.md` and `EXECUTION_PLAN.md` reflect
    evidence, remaining risks and the correct status.

`IMPLEMENTED` means scoped work exists, not that these checks passed.
`VERIFIED` and `REVIEWED` require their separate evidence. Only the
project owner may set `APPROVED`. A documentation-only task can record
static consistency and diff checks while stating that no runtime tests
were run. Codex defaults to leaving Git submission to the owner.

## 9. Performance

Measure before optimizing. Prefer demand-driven alias refinement with
budgets. Cache immutable expensive frontend artifacts. Bound debug
traversal/event volume. Expose truncation, budget exhaustion and partial
results explicitly.
