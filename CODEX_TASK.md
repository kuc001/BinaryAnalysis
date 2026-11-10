# CODEX_TASK.md --- Product goals and scope

## Product goal

Build a Python-first, multi-representation binary static analysis
framework with reproducible acquisition, shared analysis engines,
incremental artifacts, and explainable evidence.

## Required capabilities

1.  Binary frontend inputs: machine code, IDA disassembly/CFG, VEX; IDA
    Microcode as a planned complementary frontend.
2.  Decompiler input: structured Hex-Rays CTree, not text parsing.
3.  Frontend-independent HIR if required by the audit; serializable and
    free of Hex-Rays runtime objects.
4.  A canonical analysis representation (CIR is a candidate, not a
    foregone conclusion).
5.  Shared Dataflow, Def-Use/Use-Def, Alias/APG, Memory,
    interprocedural, Taint and Vulnerability algorithms.
6.  Many-to-many provenance across
    CTree/HIR/CIR/VEX/Microcode/instructions.
7.  Confidence/provenance labels distinguishing binary evidence,
    decompiler recovery/inference, user annotation and analysis-derived
    facts.
8.  Project-level Acquisition and separate Artifact, Cache, Analysis
    Result and Debug/Evidence lifecycles.

## Non-goals

-   Do not continue P1--P7 as architecture.
-   No Rust migration during initial redesign.
-   angr is optional, not the system architecture.
-   No independent CTree-only Alias/Taint engine.
-   No primary semantics from parsing pseudocode text.
-   No silent fallback for unsupported CTree nodes.
-   No full rewrite before audit and contracts approval.

## Repository reset

The requested reset targets legacy `tests/`, `scripts/`, P1--P7 docs and
generated artifacts. First identify imports, CLI/CI/docs references and
reusable production functionality. Remove only after an approved impact
plan. Do not disguise old tests by moving them elsewhere.

The owner must explicitly decide the post-reset verification strategy.
Recommendation: remove historical tests, then build a fresh verification
suite around the approved contracts and representative
binaries/decompiler cases. A complex analysis framework should not
permanently operate without repeatable verification unless the owner
accepts that risk.

## Decision policy

When existing code conflicts with requirements: inspect evidence,
explain consequences, propose alternatives, record the decision, and
wait for approval when core IR/identity/schema behavior changes.

## Definition of done

A capability is complete only when its contract, ownership,
error/partial behavior, provenance, persistence/invalidation,
documentation, and verification evidence are clear.
