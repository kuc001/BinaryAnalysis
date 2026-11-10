# Architecture Decision Records

Record decisions that affect contracts, architecture, persistence or
migration.

## Template

\### ADR-XXX:
```{=html}
<title>
```
-   Status: Proposed / Accepted / Rejected / Superseded
-   Date / Owner:
-   Context:
-   Decision:
-   Alternatives:
-   Consequences:
-   Migration impact:
-   Evidence:
-   Follow-up:

------------------------------------------------------------------------

## Initial decisions to resolve

-   ADR-001: Keep/evolve/replace current CIR?
-   ADR-002: Is HIR required for all inputs or only
    high-level/decompiler inputs?
-   ADR-003: Should Hex-Rays extraction run inside IDA and export a
    stable interchange artifact?
-   ADR-004: What artifact granularity supports incremental
    function-level rebuild?
-   ADR-005: Is tests/ deletion a one-time historical reset or a
    permanent no-tests policy?
-   ADR-006: Retain `emtaint` import package name during the reset?
-   ADR-007: When should IDA Microcode become an implemented frontend?
