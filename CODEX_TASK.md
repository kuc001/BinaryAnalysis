# CODEX_TASK.md --- Product goals and scope

## Product goal

Build a Python-first, multi-representation binary static analysis
framework with reproducible acquisition, shared analysis engines,
incremental artifacts, and explainable evidence.

## Required capabilities

1.  Binary frontend inputs: machine code, IDA disassembly/CFG, VEX; IDA
    Microcode as a planned complementary frontend.
2.  Decompiler input: structured Hex-Rays CTree, not text parsing.
3.  An independent, frontend-neutral HIR for structured CTree input,
    serializable and free of Hex-Rays runtime objects; CTree → HIR → CIR.
4.  CIR as the common analysis input: VEX → CIR and future Microcode →
    CIR. Exact HIR/CIR schemas and identities still require approval.
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

The current architecture-reset worktree has already removed the old
`tests/` and `scripts/` trees. They are historical reset subjects, not
F0 prerequisites. ADR-005 permits new contract-based verification with
representative binary and decompiler inputs; do not restore the P1--P7
test architecture or disguise old tests under another directory.

## Decision policy

When existing code conflicts with requirements: inspect evidence,
explain consequences, propose alternatives, record the decision, and
wait for approval when core IR/identity/schema behavior changes.

## Definition of done

A capability is complete only when its contract, ownership,
error/partial behavior, provenance, persistence/invalidation,
documentation, and verification evidence are clear.
