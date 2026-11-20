# F1 VEX/CIR v2 interoperability audit

Baseline `de6e0decaeac2976d1294b2e13774583e6216882` on `codex/architecture-reset`. Audit and ACR proposal only. Interoperability remains `PLANNED`.

## Real F0 v1 witness

The existing `emtaint.artifacts.load(AcquisitionRef, FunctionId)` loaded the saved `.f0-runtime/artifacts/generation-a7470d49744a41d99fc673785fb76f73` with external pin `6dce3efbdf607764bb9a9ffb8652d9204f9508a0952327e97525a2c64be7147c`. Binary SHA-256 `334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787`. CIR body SHA-256 `3884c16926009db2ca00d504254e07b638e21c7dbee6bcf681b2ff06b95f61df`. Integrity `VALID`, semantic assessment `PARTIAL`, module completeness and precision `incomplete`. Empty unsupported-op and precision-loss lists coexist with the bounded lifting diagnostic.

- Function `_start` has linked VA `0x10E58`, image base `0x8000`, function RVA `0x8E58`. One `BlockId(function,0x8E58,index=0,mode=default)` without a CIR byte extent. This ARM witness uses the manifest's default instruction mode. CFG entry is that block, stored exits and edges are empty, and CFG status is incomplete. The final jump is computed. The CFG boundary must stay open in a conversion.
- Architecture `ARMEL`, 32-bit address and pointer widths, 8-bit bytes, little-endian. ABI `AAPCS32:ELF`, argument `r0..r3`, return `r0`, SP `sp`, alignment 8. Caller-saved `r0..r3,r12,lr,cc_op,cc_dep1,cc_dep2,cc_ndep`; callee-saved `r4..r11,sp`. Register catalogue and native offsets are supplied by `architecture.json`, including architectural and condition/state registers.
- 95 effects: 52 Compute, 13 ReadRegister, 22 WriteRegister, 4 LoadEffect, 3 StoreEffect, 1 JumpEffect. Other effect kinds count 0 in this witness. 74 Origin entries, 119 SourceHints, 74 InstructionHints. All seven memory effects are 32-bit little-endian, guard true, address space `default`, alignment unknown and nonvolatile.
- 69 declared ValueRefs: 61 BV32 with unspecified signedness, 8 unsigned pointer32 in `default`. 63 constant operand occurrences: 26 BV32, 29 Boolean1, 8 pointer32. There are 18 distinct typed literal values. Occurrences include the per-effect guards.
- Compute operations in this artifact: COPY 37, ADD 12, SUB 3. MUL, AND, OR, XOR, EQ, ULT, SLT, NOT, EXTRACT, ZERO_EXTEND, SIGN_EXTEND, CONCAT and IF each occur 0 times here. The matrix derives broader v1 support from the canonical effect and scalar rules and checks the VEX emitter separately.

### Ordered effect inventory

All rows below belong to block `0x8E58/index=0/default`. Input columns include guard, address and computed target occurrences. Origin columns list stable Origin ID, instruction RVA, v1 statement index and recorded source opcode. Linked instruction VA follows the pinned ELF mapping. The register column preserves slice offset, width, full register width, and write policy.

| Ordinal | Effect | Input roles and operands | Value outputs | Origin / instruction RVA / statement / source opcode | Operation or state semantics |
| ---: | --- | --- | --- | --- | --- |
| 0 | Compute | args[0] `0x0:BV/32/unspecified` | `f8e58:t0` | `f8e58:o1` / `0x8e58` / 1 / `Ist_WrTmp` | `copy` |
| 1 | Compute | args[0] `f8e58:t0` | `f8e58:t1` | `f8e58:o2` / `0x8e58` / 2 / `Ist_WrTmp` | `copy` |
| 2 | WriteRegister | value `f8e58:t1`, guard `true:bool/1/unspecified` | — | `f8e58:o3` / `0x8e58` / 3 / `Ist_Put` | r11[0+32]/32 full |
| 3 | WriteRegister | value `0x10e5c:BV/32/unspecified`, guard `true:bool/1/unspecified` | — | `f8e58:o4` / `0x8e58` / 4 / `Ist_Put` | pc[0+32]/32 full |
| 4 | Compute | args[0] `0x0:BV/32/unspecified` | `f8e58:t2` | `f8e58:o6` / `0x8e5c` / 6 / `Ist_WrTmp` | `copy` |
| 5 | Compute | args[0] `f8e58:t2` | `f8e58:t3` | `f8e58:o7` / `0x8e5c` / 7 / `Ist_WrTmp` | `copy` |
| 6 | WriteRegister | value `f8e58:t3`, guard `true:bool/1/unspecified` | — | `f8e58:o8` / `0x8e5c` / 8 / `Ist_Put` | lr[0+32]/32 full |
| 7 | WriteRegister | value `0x10e60:BV/32/unspecified`, guard `true:bool/1/unspecified` | — | `f8e58:o9` / `0x8e5c` / 9 / `Ist_Put` | pc[0+32]/32 full |
| 8 | ReadRegister | — | `f8e58:v4` | `f8e58:o11` / `0x8e60` / 11 / `Ist_WrTmp` | sp[0+32]/32 |
| 9 | Compute | args[0] `f8e58:v4` | `f8e58:t5` | `f8e58:o11` / `0x8e60` / 11 / `Ist_WrTmp` | `copy` |
| 10 | Compute | args[0] `f8e58:t5`, args[1] `0x4:BV/32/unspecified` | `f8e58:v6` | `f8e58:o12` / `0x8e60` / 12 / `Ist_WrTmp` | `add` |
| 11 | Compute | args[0] `f8e58:v6` | `f8e58:t7` | `f8e58:o12` / `0x8e60` / 12 / `Ist_WrTmp` | `copy` |
| 12 | Compute | args[0] `f8e58:t7` | `f8e58:t8` | `f8e58:o13` / `0x8e60` / 13 / `Ist_WrTmp` | `copy` |
| 13 | ReadRegister | — | `f8e58:v9` | `f8e58:o14` / `0x8e60` / 14 / `Ist_WrTmp` | sp[0+32]/32 |
| 14 | Compute | args[0] `f8e58:v9` | `f8e58:t10` | `f8e58:o14` / `0x8e60` / 14 / `Ist_WrTmp` | `copy` |
| 15 | Compute | args[0] `0x0:pointer/32/unsigned/default`, args[1] `f8e58:t10` | `f8e58:v11` | `f8e58:o15` / `0x8e60` / 15 / `Ist_WrTmp` | `add` |
| 16 | LoadEffect | address `f8e58:v11`, guard `true:bool/1/unspecified` | `f8e58:v12` | `f8e58:o15` / `0x8e60` / 15 / `Ist_WrTmp` | 32b little, AS=default, alignment=unknown, volatile=false |
| 17 | Compute | args[0] `f8e58:v12` | `f8e58:t13` | `f8e58:o15` / `0x8e60` / 15 / `Ist_WrTmp` | `copy` |
| 18 | WriteRegister | value `f8e58:t13`, guard `true:bool/1/unspecified` | — | `f8e58:o16` / `0x8e60` / 16 / `Ist_Put` | r1[0+32]/32 full |
| 19 | WriteRegister | value `f8e58:t8`, guard `true:bool/1/unspecified` | — | `f8e58:o17` / `0x8e60` / 17 / `Ist_Put` | sp[0+32]/32 full |
| 20 | WriteRegister | value `0x10e64:BV/32/unspecified`, guard `true:bool/1/unspecified` | — | `f8e58:o18` / `0x8e60` / 18 / `Ist_Put` | pc[0+32]/32 full |
| 21 | ReadRegister | — | `f8e58:v14` | `f8e58:o20` / `0x8e64` / 20 / `Ist_WrTmp` | sp[0+32]/32 |
| 22 | Compute | args[0] `f8e58:v14` | `f8e58:t15` | `f8e58:o20` / `0x8e64` / 20 / `Ist_WrTmp` | `copy` |
| 23 | Compute | args[0] `f8e58:t15` | `f8e58:t16` | `f8e58:o21` / `0x8e64` / 21 / `Ist_WrTmp` | `copy` |
| 24 | Compute | args[0] `f8e58:t16` | `f8e58:t17` | `f8e58:o22` / `0x8e64` / 22 / `Ist_WrTmp` | `copy` |
| 25 | WriteRegister | value `f8e58:t17`, guard `true:bool/1/unspecified` | — | `f8e58:o23` / `0x8e64` / 23 / `Ist_Put` | r2[0+32]/32 full |
| 26 | WriteRegister | value `0x10e68:BV/32/unspecified`, guard `true:bool/1/unspecified` | — | `f8e58:o24` / `0x8e64` / 24 / `Ist_Put` | pc[0+32]/32 full |
| 27 | ReadRegister | — | `f8e58:v18` | `f8e58:o26` / `0x8e68` / 26 / `Ist_WrTmp` | sp[0+32]/32 |
| 28 | Compute | args[0] `f8e58:v18` | `f8e58:t19` | `f8e58:o26` / `0x8e68` / 26 / `Ist_WrTmp` | `copy` |
| 29 | Compute | args[0] `f8e58:t19`, args[1] `0x4:BV/32/unspecified` | `f8e58:v20` | `f8e58:o27` / `0x8e68` / 27 / `Ist_WrTmp` | `sub` |
| 30 | Compute | args[0] `f8e58:v20` | `f8e58:t21` | `f8e58:o27` / `0x8e68` / 27 / `Ist_WrTmp` | `copy` |
| 31 | Compute | args[0] `f8e58:t21` | `f8e58:t22` | `f8e58:o28` / `0x8e68` / 28 / `Ist_WrTmp` | `copy` |
| 32 | ReadRegister | — | `f8e58:v23` | `f8e58:o29` / `0x8e68` / 29 / `Ist_WrTmp` | sp[0+32]/32 |
| 33 | Compute | args[0] `f8e58:v23` | `f8e58:t24` | `f8e58:o29` / `0x8e68` / 29 / `Ist_WrTmp` | `copy` |
| 34 | ReadRegister | — | `f8e58:v25` | `f8e58:o30` / `0x8e68` / 30 / `Ist_WrTmp` | r2[0+32]/32 |
| 35 | Compute | args[0] `f8e58:v25` | `f8e58:t26` | `f8e58:o30` / `0x8e68` / 30 / `Ist_WrTmp` | `copy` |
| 36 | WriteRegister | value `f8e58:t22`, guard `true:bool/1/unspecified` | — | `f8e58:o31` / `0x8e68` / 31 / `Ist_Put` | sp[0+32]/32 full |
| 37 | Compute | args[0] `0x0:pointer/32/unsigned/default`, args[1] `f8e58:t22` | `f8e58:v27` | `f8e58:o32` / `0x8e68` / 32 / `Ist_Store` | `add` |
| 38 | StoreEffect | address `f8e58:v27`, value `f8e58:t26`, guard `true:bool/1/unspecified` | — | `f8e58:o32` / `0x8e68` / 32 / `Ist_Store` | 32b little, AS=default, alignment=unknown, volatile=false |
| 39 | WriteRegister | value `0x10e6c:BV/32/unspecified`, guard `true:bool/1/unspecified` | — | `f8e58:o33` / `0x8e68` / 33 / `Ist_Put` | pc[0+32]/32 full |
| 40 | ReadRegister | — | `f8e58:v28` | `f8e58:o35` / `0x8e6c` / 35 / `Ist_WrTmp` | sp[0+32]/32 |
| 41 | Compute | args[0] `f8e58:v28` | `f8e58:t29` | `f8e58:o35` / `0x8e6c` / 35 / `Ist_WrTmp` | `copy` |
| 42 | Compute | args[0] `f8e58:t29`, args[1] `0x4:BV/32/unspecified` | `f8e58:v30` | `f8e58:o36` / `0x8e6c` / 36 / `Ist_WrTmp` | `sub` |
| 43 | Compute | args[0] `f8e58:v30` | `f8e58:t31` | `f8e58:o36` / `0x8e6c` / 36 / `Ist_WrTmp` | `copy` |
| 44 | Compute | args[0] `f8e58:t31` | `f8e58:t32` | `f8e58:o37` / `0x8e6c` / 37 / `Ist_WrTmp` | `copy` |
| 45 | ReadRegister | — | `f8e58:v33` | `f8e58:o38` / `0x8e6c` / 38 / `Ist_WrTmp` | sp[0+32]/32 |
| 46 | Compute | args[0] `f8e58:v33` | `f8e58:t34` | `f8e58:o38` / `0x8e6c` / 38 / `Ist_WrTmp` | `copy` |
| 47 | ReadRegister | — | `f8e58:v35` | `f8e58:o39` / `0x8e6c` / 39 / `Ist_WrTmp` | r0[0+32]/32 |
| 48 | Compute | args[0] `f8e58:v35` | `f8e58:t36` | `f8e58:o39` / `0x8e6c` / 39 / `Ist_WrTmp` | `copy` |
| 49 | WriteRegister | value `f8e58:t32`, guard `true:bool/1/unspecified` | — | `f8e58:o40` / `0x8e6c` / 40 / `Ist_Put` | sp[0+32]/32 full |
| 50 | Compute | args[0] `0x0:pointer/32/unsigned/default`, args[1] `f8e58:t32` | `f8e58:v37` | `f8e58:o41` / `0x8e6c` / 41 / `Ist_Store` | `add` |
| 51 | StoreEffect | address `f8e58:v37`, value `f8e58:t36`, guard `true:bool/1/unspecified` | — | `f8e58:o41` / `0x8e6c` / 41 / `Ist_Store` | 32b little, AS=default, alignment=unknown, volatile=false |
| 52 | WriteRegister | value `0x10e70:BV/32/unspecified`, guard `true:bool/1/unspecified` | — | `f8e58:o42` / `0x8e6c` / 42 / `Ist_Put` | pc[0+32]/32 full |
| 53 | Compute | args[0] `0x10e78:BV/32/unspecified`, args[1] `0x10:BV/32/unspecified` | `f8e58:v38` | `f8e58:o44` / `0x8e70` / 44 / `Ist_WrTmp` | `add` |
| 54 | Compute | args[0] `f8e58:v38` | `f8e58:t39` | `f8e58:o44` / `0x8e70` / 44 / `Ist_WrTmp` | `copy` |
| 55 | Compute | args[0] `0x10e78:BV/32/unspecified` | `f8e58:t40` | `f8e58:o45` / `0x8e70` / 45 / `Ist_WrTmp` | `copy` |
| 56 | Compute | args[0] `0x0:pointer/32/unsigned/default`, args[1] `f8e58:t39` | `f8e58:v41` | `f8e58:o46` / `0x8e70` / 46 / `Ist_WrTmp` | `add` |
| 57 | LoadEffect | address `f8e58:v41`, guard `true:bool/1/unspecified` | `f8e58:v42` | `f8e58:o46` / `0x8e70` / 46 / `Ist_WrTmp` | 32b little, AS=default, alignment=unknown, volatile=false |
| 58 | Compute | args[0] `f8e58:v42` | `f8e58:t43` | `f8e58:o46` / `0x8e70` / 46 / `Ist_WrTmp` | `copy` |
| 59 | WriteRegister | value `f8e58:t43`, guard `true:bool/1/unspecified` | — | `f8e58:o47` / `0x8e70` / 47 / `Ist_Put` | r12[0+32]/32 full |
| 60 | WriteRegister | value `0x10e74:BV/32/unspecified`, guard `true:bool/1/unspecified` | — | `f8e58:o48` / `0x8e70` / 48 / `Ist_Put` | pc[0+32]/32 full |
| 61 | ReadRegister | — | `f8e58:v44` | `f8e58:o50` / `0x8e74` / 50 / `Ist_WrTmp` | sp[0+32]/32 |
| 62 | Compute | args[0] `f8e58:v44` | `f8e58:t45` | `f8e58:o50` / `0x8e74` / 50 / `Ist_WrTmp` | `copy` |
| 63 | Compute | args[0] `f8e58:t45`, args[1] `0x4:BV/32/unspecified` | `f8e58:v46` | `f8e58:o51` / `0x8e74` / 51 / `Ist_WrTmp` | `sub` |
| 64 | Compute | args[0] `f8e58:v46` | `f8e58:t47` | `f8e58:o51` / `0x8e74` / 51 / `Ist_WrTmp` | `copy` |
| 65 | Compute | args[0] `f8e58:t47` | `f8e58:t48` | `f8e58:o52` / `0x8e74` / 52 / `Ist_WrTmp` | `copy` |
| 66 | ReadRegister | — | `f8e58:v49` | `f8e58:o53` / `0x8e74` / 53 / `Ist_WrTmp` | sp[0+32]/32 |
| 67 | Compute | args[0] `f8e58:v49` | `f8e58:t50` | `f8e58:o53` / `0x8e74` / 53 / `Ist_WrTmp` | `copy` |
| 68 | ReadRegister | — | `f8e58:v51` | `f8e58:o54` / `0x8e74` / 54 / `Ist_WrTmp` | r12[0+32]/32 |
| 69 | Compute | args[0] `f8e58:v51` | `f8e58:t52` | `f8e58:o54` / `0x8e74` / 54 / `Ist_WrTmp` | `copy` |
| 70 | WriteRegister | value `f8e58:t48`, guard `true:bool/1/unspecified` | — | `f8e58:o55` / `0x8e74` / 55 / `Ist_Put` | sp[0+32]/32 full |
| 71 | Compute | args[0] `0x0:pointer/32/unsigned/default`, args[1] `f8e58:t48` | `f8e58:v53` | `f8e58:o56` / `0x8e74` / 56 / `Ist_Store` | `add` |
| 72 | StoreEffect | address `f8e58:v53`, value `f8e58:t52`, guard `true:bool/1/unspecified` | — | `f8e58:o56` / `0x8e74` / 56 / `Ist_Store` | 32b little, AS=default, alignment=unknown, volatile=false |
| 73 | WriteRegister | value `0x10e78:BV/32/unspecified`, guard `true:bool/1/unspecified` | — | `f8e58:o57` / `0x8e74` / 57 / `Ist_Put` | pc[0+32]/32 full |
| 74 | Compute | args[0] `0x10e80:BV/32/unspecified`, args[1] `0xc:BV/32/unspecified` | `f8e58:v54` | `f8e58:o59` / `0x8e78` / 59 / `Ist_WrTmp` | `add` |
| 75 | Compute | args[0] `f8e58:v54` | `f8e58:t55` | `f8e58:o59` / `0x8e78` / 59 / `Ist_WrTmp` | `copy` |
| 76 | Compute | args[0] `0x10e80:BV/32/unspecified` | `f8e58:t56` | `f8e58:o60` / `0x8e78` / 60 / `Ist_WrTmp` | `copy` |
| 77 | Compute | args[0] `0x0:pointer/32/unsigned/default`, args[1] `f8e58:t55` | `f8e58:v57` | `f8e58:o61` / `0x8e78` / 61 / `Ist_WrTmp` | `add` |
| 78 | LoadEffect | address `f8e58:v57`, guard `true:bool/1/unspecified` | `f8e58:v58` | `f8e58:o61` / `0x8e78` / 61 / `Ist_WrTmp` | 32b little, AS=default, alignment=unknown, volatile=false |
| 79 | Compute | args[0] `f8e58:v58` | `f8e58:t59` | `f8e58:o61` / `0x8e78` / 61 / `Ist_WrTmp` | `copy` |
| 80 | WriteRegister | value `f8e58:t59`, guard `true:bool/1/unspecified` | — | `f8e58:o62` / `0x8e78` / 62 / `Ist_Put` | r0[0+32]/32 full |
| 81 | WriteRegister | value `0x10e7c:BV/32/unspecified`, guard `true:bool/1/unspecified` | — | `f8e58:o63` / `0x8e78` / 63 / `Ist_Put` | pc[0+32]/32 full |
| 82 | Compute | args[0] `0x10e84:BV/32/unspecified`, args[1] `0xc:BV/32/unspecified` | `f8e58:v60` | `f8e58:o65` / `0x8e7c` / 65 / `Ist_WrTmp` | `add` |
| 83 | Compute | args[0] `f8e58:v60` | `f8e58:t61` | `f8e58:o65` / `0x8e7c` / 65 / `Ist_WrTmp` | `copy` |
| 84 | Compute | args[0] `0x10e84:BV/32/unspecified` | `f8e58:t62` | `f8e58:o66` / `0x8e7c` / 66 / `Ist_WrTmp` | `copy` |
| 85 | Compute | args[0] `0x0:pointer/32/unsigned/default`, args[1] `f8e58:t61` | `f8e58:v63` | `f8e58:o67` / `0x8e7c` / 67 / `Ist_WrTmp` | `add` |
| 86 | LoadEffect | address `f8e58:v63`, guard `true:bool/1/unspecified` | `f8e58:v64` | `f8e58:o67` / `0x8e7c` / 67 / `Ist_WrTmp` | 32b little, AS=default, alignment=unknown, volatile=false |
| 87 | Compute | args[0] `f8e58:v64` | `f8e58:t65` | `f8e58:o67` / `0x8e7c` / 67 / `Ist_WrTmp` | `copy` |
| 88 | WriteRegister | value `f8e58:t65`, guard `true:bool/1/unspecified` | — | `f8e58:o68` / `0x8e7c` / 68 / `Ist_Put` | r3[0+32]/32 full |
| 89 | WriteRegister | value `0x10e80:BV/32/unspecified`, guard `true:bool/1/unspecified` | — | `f8e58:o69` / `0x8e7c` / 69 / `Ist_Put` | pc[0+32]/32 full |
| 90 | WriteRegister | value `0x10270:BV/32/unspecified`, guard `true:bool/1/unspecified` | — | `f8e58:o71` / `0x8e80` / 71 / `Ist_Put` | pc[0+32]/32 full |
| 91 | ReadRegister | — | `f8e58:v66` | `f8e58:o72` / `0x8e80` / 72 / `Ist_WrTmp` | pc[0+32]/32 |
| 92 | Compute | args[0] `f8e58:v66` | `f8e58:t67` | `f8e58:o72` / `0x8e80` / 72 / `Ist_WrTmp` | `copy` |
| 93 | Compute | args[0] `0x0:pointer/32/unsigned/default`, args[1] `f8e58:t67` | `f8e58:v68` | `f8e58:o73` / `0x8e80` / 73 / `Next:Ijk_Boring` | `add` |
| 94 | JumpEffect | target `f8e58:v68` | — | `f8e58:o73` / `0x8e80` / 73 / `Next:Ijk_Boring` | Computed pointer target, no persisted successor |

### Value producer/consumer inventory

Producer and consumer numbers reference the effect ordinal above. A role ordinal is retained where applicable. Literal inputs and guards are listed in the effect table.

| ValueRef | Kind / bits / signedness / pointer space | Producer | Consumers |
| --- | --- | --- | --- |
| `f8e58:t0` | BV/32/unspecified | 0 | 1:args[0] |
| `f8e58:t1` | BV/32/unspecified | 1 | 2:value |
| `f8e58:t2` | BV/32/unspecified | 4 | 5:args[0] |
| `f8e58:t3` | BV/32/unspecified | 5 | 6:value |
| `f8e58:v4` | BV/32/unspecified | 8 | 9:args[0] |
| `f8e58:t5` | BV/32/unspecified | 9 | 10:args[0] |
| `f8e58:v6` | BV/32/unspecified | 10 | 11:args[0] |
| `f8e58:t7` | BV/32/unspecified | 11 | 12:args[0] |
| `f8e58:t8` | BV/32/unspecified | 12 | 19:value |
| `f8e58:v9` | BV/32/unspecified | 13 | 14:args[0] |
| `f8e58:t10` | BV/32/unspecified | 14 | 15:args[1] |
| `f8e58:v11` | pointer/32/unsigned/default | 15 | 16:address |
| `f8e58:v12` | BV/32/unspecified | 16 | 17:args[0] |
| `f8e58:t13` | BV/32/unspecified | 17 | 18:value |
| `f8e58:v14` | BV/32/unspecified | 21 | 22:args[0] |
| `f8e58:t15` | BV/32/unspecified | 22 | 23:args[0] |
| `f8e58:t16` | BV/32/unspecified | 23 | 24:args[0] |
| `f8e58:t17` | BV/32/unspecified | 24 | 25:value |
| `f8e58:v18` | BV/32/unspecified | 27 | 28:args[0] |
| `f8e58:t19` | BV/32/unspecified | 28 | 29:args[0] |
| `f8e58:v20` | BV/32/unspecified | 29 | 30:args[0] |
| `f8e58:t21` | BV/32/unspecified | 30 | 31:args[0] |
| `f8e58:t22` | BV/32/unspecified | 31 | 36:value, 37:args[1] |
| `f8e58:v23` | BV/32/unspecified | 32 | 33:args[0] |
| `f8e58:t24` | BV/32/unspecified | 33 | — |
| `f8e58:v25` | BV/32/unspecified | 34 | 35:args[0] |
| `f8e58:t26` | BV/32/unspecified | 35 | 38:value |
| `f8e58:v27` | pointer/32/unsigned/default | 37 | 38:address |
| `f8e58:v28` | BV/32/unspecified | 40 | 41:args[0] |
| `f8e58:t29` | BV/32/unspecified | 41 | 42:args[0] |
| `f8e58:v30` | BV/32/unspecified | 42 | 43:args[0] |
| `f8e58:t31` | BV/32/unspecified | 43 | 44:args[0] |
| `f8e58:t32` | BV/32/unspecified | 44 | 49:value, 50:args[1] |
| `f8e58:v33` | BV/32/unspecified | 45 | 46:args[0] |
| `f8e58:t34` | BV/32/unspecified | 46 | — |
| `f8e58:v35` | BV/32/unspecified | 47 | 48:args[0] |
| `f8e58:t36` | BV/32/unspecified | 48 | 51:value |
| `f8e58:v37` | pointer/32/unsigned/default | 50 | 51:address |
| `f8e58:v38` | BV/32/unspecified | 53 | 54:args[0] |
| `f8e58:t39` | BV/32/unspecified | 54 | 56:args[1] |
| `f8e58:t40` | BV/32/unspecified | 55 | — |
| `f8e58:v41` | pointer/32/unsigned/default | 56 | 57:address |
| `f8e58:v42` | BV/32/unspecified | 57 | 58:args[0] |
| `f8e58:t43` | BV/32/unspecified | 58 | 59:value |
| `f8e58:v44` | BV/32/unspecified | 61 | 62:args[0] |
| `f8e58:t45` | BV/32/unspecified | 62 | 63:args[0] |
| `f8e58:v46` | BV/32/unspecified | 63 | 64:args[0] |
| `f8e58:t47` | BV/32/unspecified | 64 | 65:args[0] |
| `f8e58:t48` | BV/32/unspecified | 65 | 70:value, 71:args[1] |
| `f8e58:v49` | BV/32/unspecified | 66 | 67:args[0] |
| `f8e58:t50` | BV/32/unspecified | 67 | — |
| `f8e58:v51` | BV/32/unspecified | 68 | 69:args[0] |
| `f8e58:t52` | BV/32/unspecified | 69 | 72:value |
| `f8e58:v53` | pointer/32/unsigned/default | 71 | 72:address |
| `f8e58:v54` | BV/32/unspecified | 74 | 75:args[0] |
| `f8e58:t55` | BV/32/unspecified | 75 | 77:args[1] |
| `f8e58:t56` | BV/32/unspecified | 76 | — |
| `f8e58:v57` | pointer/32/unsigned/default | 77 | 78:address |
| `f8e58:v58` | BV/32/unspecified | 78 | 79:args[0] |
| `f8e58:t59` | BV/32/unspecified | 79 | 80:value |
| `f8e58:v60` | BV/32/unspecified | 82 | 83:args[0] |
| `f8e58:t61` | BV/32/unspecified | 83 | 85:args[1] |
| `f8e58:t62` | BV/32/unspecified | 84 | — |
| `f8e58:v63` | pointer/32/unsigned/default | 85 | 86:address |
| `f8e58:v64` | BV/32/unspecified | 86 | 87:args[0] |
| `f8e58:t65` | BV/32/unspecified | 87 | 88:value |
| `f8e58:v66` | BV/32/unspecified | 91 | 92:args[0] |
| `f8e58:t67` | BV/32/unspecified | 92 | 93:args[1] |
| `f8e58:v68` | pointer/32/unsigned/default | 93 | 94:target |

## Compatibility matrix

**Assessment is for the current frozen v2.** Exact rows apply only to the stated constraints. A conversion remains at least as partial as its source. Conservative rows preserve positive evidence with explicit unknowns. A dependent query requiring the lost fact must return incomplete or be rejected. Unsupported rows have no C1-suitable representation in the current validated core.

**Shared requirements for every row.** Source identity is the pinned v1 manifest/body plus BinaryId, FunctionId and full v1 BlockId. Assign deterministic target block IDs from source identity, and effect IDs from block and slot. Record v1 value and producer occurrence separately. A v1 ValueRef can be defined more than once, including guarded load initialization, so create separate SSA definitions, predecessor merges or explicit guarded old/new values as applicable. Preserve every input role and occurrence as a Use ID. Scope target IDs with target CIR digest. Map each v1 origin and every SourceHint/InstructionHint to zero or more outputs with explicit reason and confidence, preserving instruction RVA, statement, opcode and ordered block slot. Bind linked VA, file offsets and ARM/Thumb mode via the pinned address map. Synthetic merges carry no machine entry. Shared descriptors retain partial assessments and unknown graph boundaries. Each converted effect carries a source relation or derivation evidence. Any CTree and VEX facts with measurable disagreement remain parallel facts and can produce a conflict record.

### Effects

| v1 effect and semantics | Current v2 operation / rating | Identity, type and memory requirements | Origin and CFG requirements | Loss / completeness / C1 effect |
| --- | --- | --- | --- | --- |
| Compute, typed pure scalar result | Operation-dependent, see below | Input ordinals and output def. Keep bitvector versus pointer, width, signedness, space and operation parameters | Original block/slot and statement, possibly multiple translated effects | Scalar gaps interrupt demand and pointer offset transfer |
| ReadRegister, selected architectural slice | Unsupported | Reaching register version with architectural register identity, offset, slice width and whole width. Fresh input only at a justified boundary | Per-read origin and context. Thread state across predecessor edges | Unknown per read loses dependence on prior writes, including SP |
| WriteRegister, conditional slice write | Unsupported | Register version update, guard, FULL/PRESERVE_OTHERS/ZERO_UPPER. Keep untouched bits and explicit clobbers | Same block order, joins on reachable predecessors | Dropping writes breaks pointer roots and value flow |
| LoadEffect, guarded byte read | read_memory, Conservative shape only | Byte width exists. Endian, Boolean guard operand, alignment, volatile, address space and reaching memory are not validated together | Origin and guard source at effect slot. Conditional read closure | PARTIAL. Current shape can change decoded bytes or read on false path if used as exact |
| StoreEffect, guarded byte write | write_memory, Conservative shape only | Preserve value, guard, width, endian, byte range, alignment, volatile, pointer space and resulting memory version | Preserve statement and effect order within source block | PARTIAL. No strong update or proof of byte dependence on omitted facts |
| CallEffect, guarded target/ABI/results | call, Conservative | Preserve CallSiteId and categories internal direct, indirect operand, external symbol, unknown. Keep arguments, returns, guard, ABI, may-read/write and clobber; current guard is block reachability | Preserve callsite origin and unknown return/continuation boundaries | PARTIAL. Existing target categories and wildcard summary lose some v1 evidence and precise kill sets |
| BranchEffect, Boolean two-way branch | branch, Exact for known internal edges and mapped Boolean | Use ID for guard. Same-target true/false labels retained | Both successors must exist. Preserve available v1 edge evidence and disagreements | Local shape exact, input CFG still may be PARTIAL |
| JumpEffect, explicit block or computed pointer | jump, Exact for explicit internal block; computed target Conservative to unknown_exit | Computed operand requires preserved Use and unresolved-transfer semantics, absent from current unknown_exit shape | Keep outgoing boundary and original instruction origin | Computed target cannot be certified as a known edge. Value flow to target requires ACR |
| ReturnEffect, guarded return values | return, Exact for true guard and complete value mapping, otherwise Conservative | Preserve ordered value uses and guard. Guarded continuation needs explicit representation | Return/unknown exits distinct, origin retained | PARTIAL if false/unknown guard behavior cannot be preserved |
| HavocEffect, guarded writes/clobbers | havoc, Conservative | Preserve regions, registers, guard, reason and relevant old/new state | Respect effect order and source guard. Does not imply unknown control by itself | PARTIAL. Unconditional widening is conservative but can destroy useful dependency precision |
| UnknownEffect, explicit unsupported behavior | unknown / unknown_exit, Conservative | Retain original opcode/reason and possible memory/register/control effects. Preserve known uses/effect footprint | Mark unknown continuation as incomplete. Preserve source origin | PARTIAL. A relevant unknown prevents sound negative dependence claims |

### Scalar operations

Rows inherit the identity, ordered operands, origin and CFG policy above. Pure scalar operations have no direct memory access. Pointer operations affect downstream memory addresses.

| v1 operation | v1 semantics | Current v2 and mapping | Type/params, loss and C1 impact |
| --- | --- | --- | --- |
| COPY (37) | Typed value identity | copy, Exact for matched Boolean or representable unqualified BV value | Width and sort match. Pointer space and explicit signedness need binding to avoid PARTIAL |
| ADD (12) | Modular BV sum or pointer+BV | add, Exact for matching unqualified BV when modular rule is preserved. Pointer form Unsupported | Preserve bit width and overflow semantics. Pointer result retains base space |
| SUB (3) | Modular subtraction, pointer adjustment or pointer distance | Unsupported | Preserve differing pointer/BV sorts and width. Missing SP adjustment disconnects stack offsets |
| MUL (0) | Width-limited product | Unsupported | Preserve width and signedness facts. Missing stride multiplication disconnects offsets |
| AND (0) | Per-bit intersection | Unsupported | Bitvector width, address masks. Boolean short-circuit lowering is a different v1 operation |
| OR (0) | Per-bit union | Unsupported | Bitvector width and tag bits |
| XOR (0) | Per-bit exclusive OR | Unsupported | Bitvector width, including v1 bitwise-not encodings |
| EQ (0) | Equal typed operands, Boolean result | Conservative via compare_ne then is_zero if operand types/scopes already exact | Preserve typed equivalence. Extra derived effect requires provenance and result-ID binding |
| ULT (0) | Unsigned bitvector ordering | Unsupported | Width and unsigned interpretation drive guards and bounds |
| SLT (0) | Signed bitvector ordering | Unsupported | Width and signed interpretation drive guards and bounds |
| NOT (0) | Boolean inversion | is_zero, Exact where Boolean operand and result are established | Boolean1 only. v1 bitwise inversion when emitted via XOR is covered by XOR row |
| EXTRACT (0) | Extract inclusive high/low bit interval | Unsupported | Retain exact high/low and result width. Needed for slices and partial byte dependencies |
| ZERO_EXTEND (0) | Extend with zero fill | Unsupported | Preserve extension amount and output width |
| SIGN_EXTEND (0) | Extend with replicated sign bit | Unsupported | Preserve extension amount, width and sign interpretation |
| CONCAT (0) | Ordered bitvector concatenation | Unsupported | Preserve part widths and order. Needed for register/memory fragment reconstruction |
| IF (0) | Guarded choice of two typed operands | Unsupported as a scalar op. Proposed explicit branch/join with typed parameters can be exact if both inputs and original ordering remain valid | Preserve condition, alternatives and type. Avoid speculative side effects and never substitute an unproven path |

## ACR-F1-INTEROP-001 · Common CIR VEX semantics

**Status `PROPOSED`. Owner decision pending.** Linked task `F1-VEX-CIR-V2-INTEROPERABILITY`. Relevant directions ADR-001/004/008/010/011/012. P1 readiness blocker with P0 semantic risk if unsupported memory/register behavior is advertised as complete.

**Trigger.** The pinned F0 witness includes pointer address formation, 35 architectural register effects, SUB and a computed exit that cannot be retained exactly by the current v2. The preserved v1 endian, guard, alignment and volatility metadata lack a common validated transport to C1. Free-form v2 effect data alone supplies neither a contract nor shared-consumer semantics. The revision also needs signedness/address space, Architecture/ABI, CallSiteId, target categories and guarded memory/register footprint. Reuse `core/contracts.py` and `core/program.py` types where semantically equivalent.

1. **Recommend a separately versioned shared semantic profile.** Introduce a required versioned descriptor of architecture/ABI and address spaces, typed signedness, register slice/version semantics, parameterized scalar ops, guarded memory with endian/alignment/volatile, callsite evidence, guarded footprints, and explicit unresolved exits. Register/memory state must have definition/use links. Specify schema dispatch that reads existing F1 Common CIR-Wire-v2 bytes with their original semantics. Put new normalized inputs in a distinct generation and pin the new schema. Existing F1 outputs remain readable and can later opt into a versioned normalization step.
2. **Alternative: keep the v2 body and add a mandatory versioned semantic annex plus checked common view.** Bind the annex to the body/CFG hash. Carry original operations, register versions, memory access descriptors, guards, ABI and callsite in the annex. Consumers receive one typed view assembled only after validating both parts. Ordinary v2-only clients must reject the capability for C1 use. This preserves body compatibility but has more cross-artifact validation and a greater risk of consumers ignoring required facts.

**Plan and rollback.** Freeze exact operator, state and identity contracts first. Populate exact records for the observed F0 witness and positive/unknown register, guarded load/store, endian, bit slicing, join and computed-exit cases. Compare source and target dependency operands, block edges, bytes and evidence before allowing C1 consumption. Persist and detached-reload converted output with typed completeness. Reject sidecar/hash or identity mismatch and unsupported operations affecting required dependencies. Retain the original F0 and F1 generations byte-for-byte. Disable the new adapter or stop after audit if the proposed profile cannot preserve required semantics. Old readers continue using the saved v1/v2 code paths.

**Conservative policy.** An unsupported operation can emit explicit partial descriptors with original input/output slots only when those slots remain reachable in the evidence graph and dependent analysis treats the operation as unknown. Register clobber, unknown address space, guard/endian or unknown reaching definition on the selected Store→Load chain blocks exact C1 acceptance. A wildcard or orphan UnknownDef cannot establish alias, kill, byte equality or absence of flows.

## C1 witness screening

| Input | Store/Load and address evidence | CFG and suitability |
| --- | --- | --- |
| F0 `_start`, VA `0x10E58`, RVA `0x8E58` | 3 stack stores, 4 loads. Stack load precedes the stores. Subsequent loads are PC-relative literal reads. SP register and arithmetic origins are available | Saved one-block CFG with no edges and a computed exit. Suitable for interoperability and register/byte preservation. No verified forward Store→Load dependence |
| F1 `sub_632F8`, EA `0x632F8`, RVA `0x5B2F8` | One explicit byte read, zero explicit stores in CIR. Symbolic address and unknown call footprints. Saved origins for the read and relevant branch | Structured 12-block/14-edge CFG with joins. A possible call write is insufficient for a Store→Load acceptance dependency |
| Candidate `0x1BD70` / RVA `0x13D70` | A32 prologue entry candidate. `0x1BD8C` STR word to `[sp,#0x10]` (bytes `10308de5`), then `0x1BD9C` LDR word from the same slot (`10309de5`). Between them, another-slot load, MOV and ADD leave SP/slot unchanged. Bounded direct-flow walk covered 7 STR-family and 41 LDR-family instructions | 23 recovered blocks under the bounded walk. Entry block ends at conditional `0x1BDAC` with successors `0x1BDD0/0x1BDB0` and early join at `0x1BDD0`. Candidate only, function boundary and all transfers need confirmation |
| Candidate `0x367A4` / RVA `0x2E7A4` | A32 prologue entry candidate. Adjacent word store/load at `0x367B4/0x367B8` to `[sp,#0x18]`, bytes `18308de5/18c09de5`. Bounded walk covered 52 STR-family and 52 LDR-family instructions | 30 recovered blocks before declared bounds. Entry branch at `0x36838` to `0x36860/0x3683C`, with convergence at `0x36860`. Three out-of-window successors remain. Lower priority due to unresolved boundaries |

Candidate counts describe reachable decoded machine instructions in a bounded direct-branch scan, excluding PUSH/LDM-style effects and treating calls as continuation. The scan is not a published CFG or CIR artifact. A later authorized acquisition should confirm the exact function extent, mode, source CFG, guards, all reaching stores and instruction-local provenance. For optional IDA comparison, confirm the selected EA is a function entry in the same binary/database mapping and that the store/load remains explicit in structured output. Hex-Rays may fold a temporary stack round trip, so use the ELF bytes and VEX witness for acceptance. F0/F1 main fixture identities stay fixed.
