# F1-INTEROP-0 · Same-function translation validation

## F1-INTEROP-1A · Local machine evidence (2026-11-20)

The local batch run now supplies the genuine IDA witness for this function. The sections below record the earlier F1-INTEROP-0 baseline and pending state at that time. This section records the current results.

**Environment.** Clean starting branch `codex/architecture-reset`, HEAD `1db5dca0ac19556490a820943d83e043f5bdbbf9`. IDA installation `D:\Softwares\IDA Professional 9.3`, executable file version `9.3.25.1224`. The successful process reported kernel 9.3, ARM and IDAPython 3.15.2. The firmware directory had IDA sidecars, with no standalone `httpd.i64` or `httpd.idb`. The historical CTree and F0/F1 generations loaded by their unchanged pins. The input ELF copy was separately SHA-256 verified before starting IDA.

**Automation and isolation.** Non-elevated `idat.exe` and bundled `idalib` each exited 2 with no script receipt in the current host session. The hidden `ida.exe` route ran with its own workspace IDAUSR, TEMP and TMP. It created a fresh IDB from a pinned copy of the ELF. The first GUI run exited 0 and exposed an exporter classification error at `0x6333C`: the ordinary `MOV` was labeled indirect because the processor's block-end predicate was treated as an instruction transfer. The fixed exporter requires explicit transfer evidence for that classification. A second hidden run exited 0 with a separate script receipt and no exporter diagnostics. Copies into the readable evidence directory were checked byte-for-byte against the original run. All original inputs and prior runs were retained. [IDA autonomous command options](https://docs.hex-rays.com/9.1/user-guide/configuration/command-line-switches)

```powershell
.venv\Scripts\python.exe -B -m tools.interop.run_ida --ida-exe 'D:\Softwares\IDA Professional 9.3\ida.exe' --binary 'D:\Codes\firmware-binaries\rv130_v44\httpd' --output .f0-runtime/local-ida-632f8
```

The recorded child argv for the successful run was:

```text
"D:\Softwares\IDA Professional 9.3\ida.exe" -A -LD:\Codes\architecture-reset\.f0-runtime\local-ida-632f8\run-4e42kcny\ida.log -SD:\Codes\architecture-reset\tools\interop\ida_batch.py D:\Codes\architecture-reset\.f0-runtime\local-ida-632f8\run-4e42kcny\httpd
```

The accepted original machine JSON SHA-256 is `f6a75c05733b96f0d545c1d71df98edd1583b3d31a9eb260e5fb6a5320786586`. The nine-file local bundle is `.f0-runtime/local-ida-632f8/validation-54pem1hq/`, manifest pin `c4d92abdc36154ccd17be12696a097f246b11768cd8741c9c1f8aa60e8a5eab6`. It contains the original machine JSON, environment and command receipts, independent ELF rows, both source mappings, graph, control/effect matrices, and level report. The archived machine file carries its original bytes. The bundle is outside Git and is tied to this local environment.

| Level | Current result | Evidence |
| --- | --- | --- |
| 0 · INPUT_IDENTITY | PASS | The three artifact streams bind the pinned BinaryId and FunctionId RVA `0x5B2F8`. IDA and ELF confirm one ARM chunk at `[0x632F8,0x6339C)`. All address domains are recorded |
| 1 · INSTRUCTION_COVERAGE | PASS | 41/41 IDA instructions match ELF bytes, sizes, ARM mode and executable segment file offsets. Zero missing, overlapping or unmatched rows. 333 byte-context VEX Origin/InstructionHint rows cover 41 distinct instruction addresses, with 619 SourceHints and 498 CIR v1 effect occurrences. 21 instruction addresses have CTree location claims. Twelve CTree nodes have no machine address |
| 2 · CONTROL_FLOW | PARTIAL | IDA machine CFG has five blocks, six edges and no unresolved successor diagnostics. Its edges match the encoded transfers and angr after splitting call continuations (two EXACT, four NORMALIZED). Saved CIR v1 still includes four unknown edges. The 12-block/14-edge F1 structured graph has two machine-witnessed candidate edges and 12 edges without direct machine correspondence |
| 3 · EFFECT_MAPPING | PARTIAL | Four physical call targets and one byte-load width align. The graph keeps producer-provenance, byte matches and source-location claims separate across 1,150 edges. It retains typed v1 register slices and value-use occurrences, but does not prove reaching architectural state, source ABI, memory object or guard equivalence. Call clobber and memory summaries remain partial |
| 4 · SEMANTIC_TRANSLATION | BLOCKED | Local evidence identifies the 8-bit load, the return path's `mov r0,#0` and the loop back edge. Complete validation of observable states needs the approved shared semantics and conversion implementation |

| Site | Machine result | Cross-representation disposition |
| --- | --- | --- |
| `0x63320` | BL `0xFFF4`, IDA marks target thunk | Physical target matches VEX. CTree helper `strcpy` versus the machine call and audited memcpy presentation remains an unresolved conflict |
| `0x63354` | BL `0x10390`, IDA marks target thunk | Physical target matches VEX. CTree has five source arguments, while v1 records four ABI register operands. The stack argument and call side effects remain to be validated |
| `0x6335C` | BL `0x1D170` | Physical target matches VEX. One CTree argument and source result usage do not certify ABI/register behavior |
| `0x63394` | BL `0x62B30` | Physical target matches VEX. CTree records two arguments. IDA/ELF continuation at `0x63398` returns control to `0x63374` |
| `0x63370` / `0x6337C` | Conditional target `0x6338C` / back edge `0x63340` | Raw targets and recorded control agree locally. HIR conditional and loop-carried definitions require guard and state correspondence |
| `0x63368` / `0x63388` | LDRB and register restore/return | One byte agrees across the encoded load, v1 LoadEffect and v2 read_memory. Memory object equivalence and return state across representations remain open |

**Replay and negative check.** The validator saved the bundle at exit 0. `python -B -m tools.interop.validate --verify <bundle> --pin <manifest-pin>` independently reloaded nine files at exit 0. A copied bundle with one changed payload failed with exit 1. Source-only mode returned exit 2 and produced its partial report. The existing formal `unittest discover -s tests/f1 -v` suite passed all 30 tests.

**Next stage.** Obtain an owner decision on [ACR-F1-INTEROP-001](ACR-F1-INTEROP-001.md). For the adapter stage, pin the accepted machine witness and both saved CIR inputs. Validate the two normalized CFGs with the four unresolved v1 edges retained, all four call sites and the fifth source argument at `0x63354`, register-slice/reaching state, the byte load and endian/guard behavior, then the return value and loop merges. The new representation must reload independently and preserve explicit unknown effects. C1 remains a separate authorization and witness gate.

## F1-INTEROP-0 historical record

Baseline `20dce43967f6d9ccc3055cf52edd212c413315ae` on `codex/architecture-reset`. The supplied baseline `b5348b7528281aa76cb2aeaf8a5878bb6a74cc1e` is its immediate parent. This record documents readiness before the IDA export. The `_start` generation remains a separate v1 regression input.

## Identity and pinned inputs

All present same-function inputs bind BinaryId `334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787`, image base `0x8000`, entry `0x632F8`, logical FunctionId RVA `0x5B2F8` (token `92a963e574da6ef3c862b0494270b52f05905229f893914bb748f6a2c2754238`). The file-backed executable LOAD maps linked VA `[0x8000,0x98130)` to file offsets `[0,0x90130)`. For this segment `file_offset = linked_va - 0x8000`. Bounds are half-open. EA, RVA and file offset remain typed as distinct domains.

| Source | Verified evidence |
| --- | --- |
| ELF | Exact raw range `[0x632F8,0x6339C)`, file offsets `[0x5B2F8,0x5B39C)`. A32 instruction decoding at the selected entry produced 41 words in range. Range SHA-256 `58fa9f91e021e000f46994c1084b38041f95b3d8d0b6d3d38fcdf372c07f60a3` |
| IDA CTree/HIR | `.f1-input/ctree/ctree_632f8_39ebd8aca9.json` SHA-256 `209e40012ce07ae79ce95847b5a3792a687536951772877fbd5847ebd06c4c3e`. Entry/end `0x632F8/0x6339C`. Prior F1 generation `generation-b1a47a88525e47449a2550c939e0e265` loads with pin `7a7f459d62053e5c1bcc3be954efaa0e71fb3d1111172ffd83094f719d933b6d`. HIR SHA-256 `08ee0ad271fc8e558240dbf4fdc4553c448bebe302a5bc1a6a21f4e999192f24`. Common CIR v2 body digest `481aa9ec96597e0ebf6cddf311ce2c1cff97f25b619e786d7cac8ce9abc4d0ca` |
| angr/VEX/CIR v1 | `.f0-runtime/interop-632f8/artifacts/generation-cae3fc8730c44d2ba68ded371c342134`. Manifest pin `c5e46865575c00737c761ae269b2e8e47b5c664e7f936062f9e2bd9359a1e968`. CIR body SHA-256 `ef7df72a249feb9e75d720b106e61b54ce082017d25a6580d12ae7ddc81a4d10`. Native discovery returned exact selected VA and default (ARM) mode. All nine extents are within `[0x632F8,0x6339C)`. Independent F0 reader returned `VALID/PARTIAL` with no angr/pyvex/cle/archinfo imported |
| IDA Machine Validation | No JSON was present at `.f1-input/machine-validation/` during execution. Exporter source exists. IDA runtime export remains `BLOCKED` |

The legacy `generation-a7470d49744a41d99fc673785fb76f73` has its original manifest pin `6dce3efbdf607764bb9a9ffb8652d9204f9508a0952327e97525a2c64be7147c` and FunctionId RVA `0x8E58` (token `b56792ae1d6a11084168a31e5a26020d5e7c4c17d4cd574b022b4b11f8c5d172`). Its function and pin were checked by the existing detached reader. The generation remains the original v1 regression fixture.

### Local generation identification

The manifest scan classified 75 named generation manifests, including copied and deliberately malformed regression specimens. The following five are the primary generation paths in the historical and current artifact roots. A computed digest alone does not establish an external pin.

| Primary generation | Manifest schema / declared RVA | Computed digest and pin disposition |
| --- | --- | --- |
| `artifacts/generation-a7470d49744a41d99fc673785fb76f73` | F0 v1 / `0x8E58` | Fixed original pin above. Verified reader success |
| `artifacts/generation-21f8f0436bfa43639a1faaf5f75b99ca` | F0 v1 / `0x8E58` | `45f5a357880089da2b31914278d4c96a0b2418b18153ab64317cbe2401b7bbff` computed only in this task. Not selected |
| `f1-verification/artifacts/generation-b1a47a88525e47449a2550c939e0e265` | F1 v1 / `0x5B2F8` | Fixed historical pin above. Verified reader success |
| `f1-verification/artifacts/generation-4ddebe7b495e44b6bbc977f3ef9740f0` | F1 v1 / `0x5B2F8` | `7e998f6b93e1731f39821cb2403cba2bd66d6de297ac29bcbbf41633dbdff06c` computed only in this task. Not selected |
| `interop-632f8/artifacts/generation-cae3fc8730c44d2ba68ded371c342134` | F0 v1 / `0x5B2F8` | Current acquisition receipt pin above. Verified reader success |

Paths are relative to `.f0-runtime/`. Repeated manifest bytes in test copies were not treated as separate trusted acquisitions.

## Source-local evidence prepared for validation

These inventories are recorded independently. The three-way comparison requires a genuine machine export accepted against the same FunctionId and original ELF. Observations below do not assign three-way per-instruction or CFG verdicts.

| Area | Evidence available now | Full comparison |
| --- | --- | --- |
| Instruction coverage | ELF A32 byte table below. VEX has 41 distinct non-null instruction RVAs, 333 Origins, 619 SourceHints and 333 InstructionHints. CTree has 53 nodes, 21 distinct non-null EAs and 12 nodes without EA. CTree/HIR permits many-to-many and synthetic nodes | BLOCKED on authentic machine export |
| CFG | angr source selection has 9 blocks and 10 declared edges. The saved v1 CIR CFG has 11 blocks, 12 edges, including 4 `unknown` edges, and is incomplete. Native report has 4 `Ijk_Call`, 6 `Ijk_Boring` including 2 conditional exits, and 1 `Ijk_Ret`. F1 has 12 structured CFG blocks and 14 edges | BLOCKED |
| Calls | ELF has four BL instructions. The v1 report saves four `Ijk_Call` expressions with `Iex_RdTmp` targets and no literal in that field. v1 CIR has four DirectTarget records with AAPCS32:ELF register-shaped operands (4 each), one output each and `CallMemoryEffects` in unsupported ops. These are frontend observations and do not establish source-level arity or actual call memory behavior. CTree arities are 2/5/1/2. Existing F1 conflict at `0x63320` preserves helper `strcpy` and machine `BL 0xFFF4`. F1 keeps unknown ABI and wildcard effects | BLOCKED |
| Register/definition/use | v1 reports 80 reads, 99 writes and 281 computes. Width, slot and Origin are available. HIR preserves six lvar identities and IDA storage evidence. Reused micro-register 8 does not identify a single variable or lifetime | BLOCKED |
| Memory | v1 contains 14 Load and 9 Store effects. At `0x63368` the saved effect is 8-bit, little endian, default address space, alignment unspecified, nonvolatile. Other recorded accesses are 32-bit, including push/pop and stack write at `0x63350`. F1 has one width-qualified byte load and symbolic layout/objects. Address-only indexing in HIR remains address computation | BLOCKED |
| Semantic translation | v1 acquisition and F1 v2 body are available independently. The v1→v2 adapter and shared state contract are pending | BLOCKED |

The VEX blocks start at linked VAs `0x632F8, 0x63324, 0x63340, 0x63358, 0x63360, 0x63374, 0x63380, 0x6338C, 0x63398`. Their end boundaries are the successive listed starts and final `0x6339C`. Intra-function source edges and effects remain in the immutable generation. Preserve the machine back edge to `0x63340`, conditional guard evidence, return, and call continuations when checking their relationship to split v1 blocks and synthetic structured control.

The saved v1 call records independently expose the following machine-domain sites and frontend target identities. Each carries AAPCS32 caller-saved clobbers and wildcard memory reads/writes. Confirm these against exported IDA call evidence after the input gate.

| v1 callsite linked VA / RVA | Saved target FunctionId RVA | Saved operands/results |
| --- | --- | --- |
| `0x63320 / 0x5B320` | `0x7FF4` | 4 / 1 |
| `0x63354 / 0x5B354` | `0x8390` | 4 / 1 |
| `0x6335C / 0x5B35C` | `0x15170` | 4 / 1 |
| `0x63394 / 0x5B394` | `0x5AB30` | 4 / 1 |

### Independent ELF byte inventory

This offline Capstone decoding reads the original mapped ELF range. It does not establish IDA code heads or a Machine CFG.

| Linked VA | RVA | Little-endian bytes | Instruction display |
| --- | --- | --- | --- |
| `0x632f8` | `0x5b2f8` | `f0472de9` | `push {r4, r5, r6, r7, r8, sb, sl, lr}` |
| `0x632fc` | `0x5b2fc` | `18d04de2` | `sub sp, sp, #0x18` |
| `0x63300` | `0x5b300` | `94409fe5` | `ldr r4, [pc, #0x94]` |
| `0x63304` | `0x5b304` | `94109fe5` | `ldr r1, [pc, #0x94]` |
| `0x63308` | `0x5b308` | `04408fe0` | `add r4, pc, r4` |
| `0x6330c` | `0x5b30c` | `0a608de2` | `add r6, sp, #0xa` |
| `0x63310` | `0x5b310` | `0e20a0e3` | `mov r2, #0xe` |
| `0x63314` | `0x5b314` | `0090a0e1` | `mov sb, r0` |
| `0x63318` | `0x5b318` | `011084e0` | `add r1, r4, r1` |
| `0x6331c` | `0x5b31c` | `0600a0e1` | `mov r0, r6` |
| `0x63320` | `0x5b320` | `33b3feeb` | `bl #0xfff4` |
| `0x63324` | `0x5b324` | `78309fe5` | `ldr r3, [pc, #0x78]` |
| `0x63328` | `0x5b328` | `78209fe5` | `ldr r2, [pc, #0x78]` |
| `0x6332c` | `0x5b32c` | `03a084e0` | `add sl, r4, r3` |
| `0x63330` | `0x5b330` | `74309fe5` | `ldr r3, [pc, #0x74]` |
| `0x63334` | `0x5b334` | `027084e0` | `add r7, r4, r2` |
| `0x63338` | `0x5b338` | `038084e0` | `add r8, r4, r3` |
| `0x6333c` | `0x5b33c` | `0150a0e3` | `mov r5, #1` |
| `0x63340` | `0x5b340` | `0830a0e1` | `mov r3, r8` |
| `0x63344` | `0x5b344` | `0e10a0e3` | `mov r1, #0xe` |
| `0x63348` | `0x5b348` | `0a20a0e1` | `mov r2, sl` |
| `0x6334c` | `0x5b34c` | `0600a0e1` | `mov r0, r6` |
| `0x63350` | `0x5b350` | `00508de5` | `str r5, [sp]` |
| `0x63354` | `0x5b354` | `0db4feeb` | `bl #0x10390` |
| `0x63358` | `0x5b358` | `0600a0e1` | `mov r0, r6` |
| `0x6335c` | `0x5b35c` | `83e7feeb` | `bl #0x1d170` |
| `0x63360` | `0x5b360` | `000050e3` | `cmp r0, #0` |
| `0x63364` | `0x5b364` | `0700a001` | `moveq r0, r7` |
| `0x63368` | `0x5b368` | `0030d0e5` | `ldrb r3, [r0]` |
| `0x6336c` | `0x5b36c` | `000053e3` | `cmp r3, #0` |
| `0x63370` | `0x5b370` | `0500001a` | `bne #0x6338c` |
| `0x63374` | `0x5b374` | `015085e2` | `add r5, r5, #1` |
| `0x63378` | `0x5b378` | `050055e3` | `cmp r5, #5` |
| `0x6337c` | `0x5b37c` | `efffff1a` | `bne #0x63340` |
| `0x63380` | `0x5b380` | `0000a0e3` | `mov r0, #0` |
| `0x63384` | `0x5b384` | `18d08de2` | `add sp, sp, #0x18` |
| `0x63388` | `0x5b388` | `f087bde8` | `pop {r4, r5, r6, r7, r8, sb, sl, pc}` |
| `0x6338c` | `0x5b38c` | `0510a0e1` | `mov r1, r5` |
| `0x63390` | `0x5b390` | `0900a0e1` | `mov r0, sb` |
| `0x63394` | `0x5b394` | `e5fdffeb` | `bl #0x62b30` |
| `0x63398` | `0x5b398` | `f5ffffea` | `b #0x63374` |

## IDA export and verification gates

Open the database for that exact ELF in **IDA 9.3**, confirm the entry and run [ida93_export_machine_validation.py](../../emtaint/plugins/ida93_export_machine_validation.py) via File → Script file. The exporter checks both the IDB's recorded binary digest and the input file digest, processor and image base. It writes a fresh `IDA-Machine-Validation-v1` JSON under `.f1-input/machine-validation/`. Verify its diagnostics, file offsets and raw bytes before accepting it. A database import, patched byte, undecoded head, absent instruction mode or unresolved successor can leave the respective validation incomplete.

The API surface was checked against the installed 9.3 wrappers and official documentation. The existing CTree exporter has no complete instruction list or Machine CFG. The separate exporter uses IDA code heads, `decode_insn`, a function FlowChart with predecessor/successor lists, native xrefs, ARM operand/type facts and the loader file offset. Structured HIR blocks are never used as IDA Machine CFG evidence. [IDA FlowChart](https://python.docs.hex-rays.com/ida_gdl/index.html) · [IDA instruction decoder](https://python.docs.hex-rays.com/ida_ua/index.html) · [IDA file-offset API](https://python.docs.hex-rays.com/ida_loader/index.html)

| Level | Status | Remaining acceptance |
| --- | --- | --- |
| 0 · INPUT_IDENTITY | PARTIAL | Present ELF/CTree/VEX identity and range pass. Check authentic machine JSON SHA, FunctionId, ranges, mode and mapped bytes before opening the full comparison |
| 1 · INSTRUCTION_COVERAGE | BLOCKED | Check each IDA instruction's file offset/bytes against ELF. Compare saved origins and CTree/HIR EAs. Record `LIFTED`, `STRUCTURED_SOURCE`, `REPRESENTED_BY_EFFECTS`, `CONTROL_ONLY`, `DATA_ONLY`, `UNSUPPORTED` or `UNMAPPED` as applicable. Record reasoned one-to-many evidence and missing coverage |
| 2 · CONTROL_FLOW | BLOCKED | Compare observed machine blocks, angr source blocks, native VEX exits and both CIR graphs. Mark blocks and edges `EXACT/NORMALIZED/PARTIAL/CONFLICT/UNAVAILABLE`. Preserve distinct identities, call continuations, entry/exit, indirect edges and back edges |
| 3 · EFFECT_MAPPING | BLOCKED | Bind each call, register/state and memory record to the corresponding instruction and typed effects where justified. Separate raw targets, candidates and resolved IDs, ABI argument positions/results, and call clobber/footprints. Verify width, endian, alignment, pointer space, access guards, base/index/scale and reaching operands. Preserve conflicts |
| 4 · SEMANTIC_TRANSLATION | BLOCKED | Requires approved v1→v2 contract and adapter plus accepted machine evidence. Compare observable register/memory states, branch guards, calls, return and loop-carried definitions. Preserve unknown and conflicting behavior |

Each level has its own PASS/PARTIAL/FAIL/BLOCKED verdict and digest-bound evidence. A validation failure must remain observable. The `0x1BD70` and `0x367A4` C1 candidates remain separate static candidates, with no new C1 fixture designation.
