# P4：angr / IDA metadata 两条 VEX→CIR 前端

2026-10-28。**P4 Gate：PASS，限有界输入、已支持标量/guarded 访存、明确保守 unsupported 与前端对照。** 实现新 `frontends/angr_vex` 与 `frontends/ida_vex`，共用 VEX→CIR lowerer，消费冻结 P3 v1。真实产物为 **incomplete**，不能据此宣称全 opcode 或全程序语义完整。未进入 P5，未开发 Rust。

入口、支持矩阵和输入限制见 [P4_FRONTENDS.md](../P4_FRONTENDS.md)。新代码未改写旧 `frontend/`、VexIR、P3 schema 或内存契约。

## 真实源码与实现

旧 `frontend/angr/angr_builder.py` 只支持原型 Project→旧 Converter/IRBuilder；`frontend/ida/__init__.py` 没有实际输入路径。旧 `block_ir_builder.py` 的未支持分支曾使用 continue/exit(0)，本轮保留该参考路径并另建显式诊断的前端，不将其当作新 CIR 的成功覆盖。

实际 IDA `httpd_cfg.json` 有 **881 个函数**；其中 **80 个函数包含零长度 block**，如 `3f524` 的 `[221100,221100]` 调用边界。新 parser 保留 boundary、原始 jump/call/name；非法或歧义输入报错。零长度节点不是普通代码 block，不读空字节或假报成功 IRSB。

angr 路径使用真实 Project loader 和 block.vex，每片字节与绑定 ELF 校验；可用 CFGFast 发现所选函数的有界 block。IDA 路径按 ELF PT_LOAD 虚拟地址只读文件字节，再用实际 pyvex.IRSB，未调用 IDA 宿主。两个路径固定 opt_level=0、cross_insn_opt=False、strict_block_end=True，逐 IRSB 推进原始 block。

共享 lowerer 精确表达已支持的标量、整数类型转换、寄存器 slice、Load/Store/LoadG/StoreG；保留位宽、端序、guard、alternate、Origin、byte SHA、instruction mode/IMark delta。VEX 中途 Exit 拆成分支和续接块；未知 guard 的已知目标仍出现在 CFG 的 unknown 边中。每条源语句必须是 lowered、metadata 或 unsupported，有逐条证据。

CAS/LLSC/Dirty/MBE 等未提供精确原子/helper 语义时使用 UnknownEffect，保守影响全部潜在状态，不把 SC 当普通 Store。未知表达式与依赖 temp 不会被替换成 0；局部半成品撤回。未知 CCall、ABI 参数/结果和未覆盖 opcode 继续标 Incomplete。P3 v1 的表示和后续分析边界没有被暗中扩展。

## 真实固件双前端对照

仅 lifting 只读 `EmTaint/firmware-binaries/rv130_v44/httpd`，不执行旧分析 CLI 或 guest 仿真。ELF 为 ARMEL / ELF32 / little-endian / image_base=`0x8000`。为比较两条字节输入，使用同一组明确 IDA bounds；不是宣称两套独立 CFG 算法自动恢复了相同全程序。

| 项目 | 实测 |
|---|---|
| 选定函数 | `0x25b6c`、`0x260c0`、`0x729e4`、`0x73ef4` |
| 原始 source blocks | 10（含 1 个 boundary） |
| 实际成功 IRSB | 11；boundary 单列，不计为成功 IRSB |
| 生成 CIR/CFG nodes | 12 |
| native control 记录 | 14（含 side exits 与 default next） |
| CFG edges | 7，其中 3 条 unknown guard 边 |
| 源 VEX statements | 287：34 metadata、226 lowered、27 unsupported |
| 核心 effect 描述 | 8 Load、3 Store、78 WriteRegister、71 ReadRegister、4 Call、4 Return、7 Jump、28 UnknownEffect、191 Compute |
| 对照结果 | 除 Producer.frontend 外 CIR 完全相同；block mapping、CFG 完全相同；wire roundtrip 通过 |

28 个 UnknownEffect 包含 27 条源语句的 unsupported 及 1 个独立 InputBoundary。CallMemoryEffects 另以 Call footprint 和模块 assessment 记录。源句统计不是“完整语义覆盖率”，也不是运行时 facts。

源语句 histogram：IMark=34、WrTmp=167、Put=80、Store=3、Exit=3。表达式 histogram 单独保留，例如 Iop_Add32=15、Iop_Sub32=7、Iex_Load=8、Iex_CCall=7；这里统计语句表达式出现次数，不含所有 default-next 表达式，不冒充全程序统计。

实测 unsupported 类别为 `Iex_CCall`、依赖其未知值的 `UndefinedTmp`、`InputBoundary` 与 `CallMemoryEffects`。真实选样的三条 side-exit guard 仍未精确转换，已保留目标和 unknown CFG 边。没有把名字 hint 当作 external/direct 调用证明，没有执行 iCall recovery。

固件 SHA256：`334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787`。IDA CFG SHA256：`e5ed02f0654e31df1837c9541e2d4b3fee9e6988293406b96ca0e3719f31ea1e`。

## 测试与证据

**141/141** 回归通过（原有 135 + 本轮 6 项无第三方输入测试）；另有 **14/14 隔离原生测试**。原生测试不混入常规 discover，以免在未设写 guard 时导入 native 前端。

原生测试覆盖：实际 AMD64 bytes 的双路径 Load/Store/roundtrip；一个源 block 拆成多个 IRSB；side Exit 后续 store 的控制边界；LoadG false-path 不读取且保留 alternate、U/S 转换；StoreG guard 与 BE 位宽；CAS/LLSC load-linked/store-conditional/Dirty/barrier 的保守 unknown；未知 temp 不生成假 Store；NoDecode 的显式有界失败；CFGFast 选择；ARM Thumb bytes/mode/IMark delta；call name 不改变间接 target；unknown guard 目标保留；boolean sort。

小型独立 oracle 仅验证这些合成 guarded scalar 例子的预期读/写事件和数值，不是新 heap 引擎或完整 VEX interpreter。两真实前端共享 lowerer，因此输出一致不能单独证明 lowerer 没有共同错误。

从 BinaryAnalysis，明确使用目标解释器：

| 命令 | 结果 |
|---|---|
| `.venv/Scripts/python.exe -B -S -m unittest discover -s tests -p test_p4_inputs.py -v` | 退出 0，6/6 |
| `.venv/Scripts/python.exe -B -m unittest discover -s tests -v` | 退出 0，141/141 |
| `.venv/Scripts/python.exe -B scripts/p4_probe.py --folder <fresh .p4-work folder> --firmware` | 退出 0，14/14、两输入对照通过、零 guard 越界 |
| `git --no-optional-locks diff --check -- . ':!.venv'` | 退出 0 |
| `.venv/Scripts/python.exe -B scripts/p4_validate.py .p4-work/20261028T120656Z-ef8a592c` | 退出 0，P4 GATE=PASS |

最终证据目录：`.p4-work/20261028T120656Z-ef8a592c/validation-20261028T132544Z-1d7a49c9/`。`validation-p4.json` 汇总 Gate；`native/` 保存两个 CIR JSON、逐语句/表达式/映射/CFG 报表、native fixture inputs 与测试输出。首份发现 9.3.4 Function 无 thumb 属性的失败 probe，以及后续成功 probe 均保留，没有改标或覆盖。

## 版本、完整性与性能

实际 Python 3.12.9 / angr、pyvex、cle、archinfo、claripy 9.3.4；遵循用户 TARGET_RUNTIME 决策，没有安装或降/升级依赖。未导入旧 native 环境。angr loader 关于两个导入符号大小未知的 stderr 保留；本轮不执行 guest 仿真，不据此声称仿真可用。

前后完整 SHA256/size/mtime_ns 一致：旧 EmTaint **13461** 文件，目标 .venv **13044** 文件，baselines **351** 文件，P1/P2/P3 证据 **214/55/78** 文件，旧 frontend **7** 文件，既有 IR **49** 文件。P3 既有 Python/schema 源码与冻结快照一致；三份用户 v5 规划文件内容一致。没有修改旧 IDA JSON、历史结果或 Golden。

Git base：目标 `6cb026767db005e48b36b994ee8542962b6df627`，旧 `72a9e3081632b2f9d1881141bc7b0d43c7158033`。保留用户与前阶段已有 dirty 状态，没有 reset、clean、提交或 push。

最终纯输入测试 wall 约 1.359 秒、回归 10.125 秒、native probe（含启动、imports、14 测试、两条真实路径）21.563 秒。这不是单独 lifting 或 E2E 性能对比，未采 RSS/CPU/FFI，不作加速结论。

APG/Heap/MemoryVersion/SSE DAG/facts/Worklist/SMT 分析指标均为 null / 未执行；上文 counts 是源 VEX 与输出 CIR 描述，不冒充分析状态。P0 Golden 本轮仅校验未变，未重跑 iCall/taint 或比较漏洞结果。

## 变更、限制与下一步

新增 8 个 `frontends/` Python 文件、2 个输入/native 测试文件、2 个验证脚本；`.gitignore` 追加 `.p4-work/`；新增接口说明与本报告。现有业务链和 schema 没有切换默认路径。

当前主要边界：ET_EXEC 文件映射、有界选择、部分标量 opcode；完整 ABI、CCall、浮点/向量、原子与异常 effect 尚未精确实现，PIE/重定位、实时 IDA 宿主与完整函数覆盖未验收。遇到这些情况显式 Unsupported/Incomplete 或 InputError，不能用“无发现”代替。

下一阶段建议 **P5**：按蓝图分步实现 Python AccessPath/APG、Heap/MemoryVersion、Alias 与强弱更新、共享 SSE/按需 lowering，并对照旧 Load/Store 及 M-01…M-12 runtime。现有 frontend unsupported 必须继续传播完整性；如要保证相关路径精确语义，需补前端覆盖，不能借 Gate M 隐藏。**本轮停在 P4，Gate M / Gate A 未验收，Rust 未开发。**
