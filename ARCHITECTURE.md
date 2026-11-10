# BinaryAnalysis Architecture --- Proposed target

> Proposed design based on TASK_1/TASK_2 requirements. Not a claim about
> the current repository implementation; actual audit evidence must be
> added to REPOSITORY_AUDIT.md.

## 1. Direction

BinaryAnalysis becomes a multi-representation binary program analysis
framework.

``` text
Project / Input Manifest
        |
Acquisition Orchestrator
        |
  +-----+-------------------+
  |                         |
Binary Frontends       Decompiler Frontends
  |                         |
Instruction/CFG         Hex-Rays CTree
VEX / Microcode              |
  |                          v
  |                     Frontend HIR
  |                          |
  +--------------------------+
                 |
       Canonical Analysis IR
                 |
       Program + Memory Model
                 |
      +----------+----------+
      |          |          |
   Dataflow    Alias       Solver
      |          |          |
      +----------+----------+
                 |
        Interprocedural Analysis
                 |
       Taint / Vulnerability / Evidence
                 |
       Result Store + Debug/Provenance
```

## 2. Layers and responsibilities

### Project/Input Management

Owns project identity, binary and metadata inputs, hashes,
architecture/load configuration, frontend selection and user display
settings. No analysis algorithms.

### Frontends

-   Binary: IDA disassembly/CFG, IDA Microcode (planned), angr/VEX
    (optional).
-   Decompiler: IDA Hex-Rays CTree first.
-   A frontend exports serializable source artifacts and normalized
    contracts. The main analysis process must not depend on live
    IDA/Hex-Rays objects.

### HIR

A frontend-independent high-level representation for: -
Functions/parameters/local/global variables. - Variable storage
metadata. - Arrays, structures, members, pointers, dereferences. - Calls
and indirect call target expressions. - Arithmetic, casts,
comparisons. - If/switch/loops/returns. - Strings/constants. - Types,
type origin/confidence. - Original source node identity and location.

HIR must not contain `cexpr_t`, `cinsn_t`, `lvar_t` or other live
Hex-Rays objects. It is versioned and serializable. Preserve raw
pseudocode for display, not as primary semantic input.

### Canonical Analysis IR

CIR may remain canonical only if audit confirms it can represent
variable definitions, memory effects, access paths, calls, guards,
confidence, partial semantics and source-origin sets. If not, evolve
contracts/schema deliberately. Do not create a second analysis engine
around HIR.

Proposed lowering:

``` text
Hex-Rays CTree -> HIR -> CIR
IDA Microcode  ----------> CIR adapter
VEX            ----------> CIR adapter
angr VEX       ----------> CIR adapter
```

Keep source artifacts even after lowering.

### Program model

Owns module/function/block/instruction identity, CFG, callsites, CG/ICFG
and interprocedural references. Must not depend on IDA or angr runtime
objects.

### Memory model

Owns stack/global/heap/unknown objects, access paths, field/index/offset
segments, memory versions, read/write ranges, guards, alias contracts
and evidence. CTree `v2[3]` and a low-level stack-relative access may
map to a common candidate object while retaining separate source
evidence/confidence.

### Shared analysis engines

Dataflow, Def-Use/Use-Def, demand-driven Alias/APG, Memory,
symbolic/solver, summaries, Taint and Vulnerability consume common
contracts. No per-frontend duplicate engines.

### Provenance and Evidence

Many-to-many mappings:
`CTree Node ↔ HIR Node ↔ CIR Definition/Value ↔ VEX/Microcode ↔ Machine Instruction`

Support partial/ambiguous mappings, synthetic nodes, conflicts and no-EA
nodes. Record mapping method, frontend/version, confidence and
completeness.

## 3. Confidence model

Recommended labels: - `BINARY_CONFIRMED` - `DECOMPILER_RECOVERED` -
`DECOMPILER_INFERRED` - `USER_ANNOTATED` - `ANALYSIS_DERIVED` -
`UNKNOWN`

Keep confidence separate from semantic value. Do not treat inferred
local-variable types or structure layouts as binary truth. Conflicts
must remain visible.

## 4. CTree extraction

Use actual Hex-Rays structured APIs such as `cfunc_t`, `cinsn_t`,
`cexpr_t`, `lvar_t`, `tinfo_t`, subject to the supported IDA SDK
version. Export stable node IDs, node kinds/opcodes, operands/children,
EA if available, local-variable identity, type serialization, call
target expression, arguments, array/member/pointer details and
extraction completeness.

Unsupported nodes must be preserved as typed partial/opaque records. Do
not silently drop them.

## 5. Example: sub_117F8

Given a decompiler view with: - `v2[0] = "ca_manage"` - `v2[1] = "-n"` -
`v2[2] = "new"` - `v2[3] = unk_A0178` -
`eval(v2, ">/dev/console", 0, 0)`

HIR should represent separate local-variable definitions, array-element
stores, a global read, and a call through the full casted
function-pointer target expression.

The potential path:

``` text
ReadGlobal(unk_A0178)
 -> Store(ArrayElement(v2, 3))
 -> AddressOf(v2) passed to eval argument 0
 -> possible callee read of v2[3]
 -> possible sensitive operation
```

is a candidate only. It is not a confirmed taint flow or vulnerability
until the callee behavior and relevant conditions are established.

Array byte offsets must derive from recorded type/layout and/or machine
evidence; never hardcode an assumed element size.

## 6. IDA Microcode

Plan Microcode as complementary to CTree: - CTree: high-level control
and data semantics. - Microcode: lower-level operations, memory/register
effects and instruction mapping. - Both retain independent artifacts and
provenance. - Both lower to shared contracts/CIR where sound. -
Conflicts are explicit.

## 7. Proposed package structure

``` text
emtaint/
  application/          # use-case orchestration
  project/              # manifest, identity, configuration
  acquisition/          # service, artifacts, fingerprints, cache
  frontends/
    contracts.py
    ida/
      disassembly/
      hexrays/
      microcode/        # planned
    angr/vex/
  representations/
    hir/
    cir/
    provenance/
  program/              # functions, blocks, CFG, CG, callsites
  memory/               # objects, APG, versions, alias
  analysis/
    dataflow/
    symbolic/
    interprocedural/
    taint/
    vulnerability/
  solver/
  storage/              # artifact/result storage
  debugging/            # inspectors, traces, address mapping
  cli/
```

This is a target map, not a mandate to create every directory
immediately. Retain/merge existing packages until the audit proves a
boundary is needed.

## 8. Decisions before implementation

-   Keep/evolve/replace CIR?
-   Is HIR needed for all inputs or only decompiler inputs?
-   What lowers directly to CIR?
-   How are inferred types and conflicts represented?
-   Which raw frontend artifacts are retained?
-   What is the artifact granularity?
-   How is IDA-side extraction invoked?
-   Is `emtaint` package naming retained temporarily?
-   What is the post-reset verification policy?
