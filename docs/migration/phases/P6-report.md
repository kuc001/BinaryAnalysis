# P6 首次实现的历史报告：partial

本页保留首次实现的原始未达标结论与证据。后续持续修复及当前验收状态见 [P6-continuation-report.md](P6-continuation-report.md)；不得将以下历史计数当作当前结果。此前封存的所有失败与成功归档均未改写。

2026-10-29，Stage S1。上一阶段 P5 Gate M 在其限定内存语义范围通过。**本轮结果：QUALITY=PASS；P6 PHASE=NOT_PASSED，状态 partial。** 已交付并测试 CIR 数据流子集与图失效/重分析接口；真实 rv130 间接目标保真未达到要求，不能宣布完整 P6 迁移完成。未进入 P7，未验收 Gate A，未开发 Rust。

## 已实施内容与原算法边界

三份 v5 文档完整重读，继续采用用户确认的 Python 3.12.9 / angr 9.3.4。仅新增 P6 模块、测试/脚本/报告和 `.gitignore` 的 `.p6-work/` 条目；没有改动此前的业务源码或 frozen Schema。接口详见 [P6_DATAFLOW.md](../P6_DATAFLOW.md)。

| 原源码/符号 | P6 接入 | 已核实与仍未移植 |
|---|---|---|
| `fast_data_flow.py:32 FastDataFlow`、`:102 process_block_in_backward` | `analysis/dataflow/fast.py` | 旧 w/p/wo/wu、寄存器/直接内存 def-use 家族的 CIR 子集；未迁完整循环标签、全 CFG 反向 trace |
| `accurate_data_flow.py:471 _get_load_action_ast`、`:2581 _forward_execute_stmt`、`:2804 _backward_execute_stmt2` | `analysis/dataflow/accurate.py` + `compat/memory_runtime.py` | typed Compute/寄存器/访存/guard/Unknown/Call；旧全部 alias/SSE 替换规则、双向传播未完成 |
| `data_trace.py:484 _execute_function` | `orchestration/fast_search.py`、`program_search.py` | 有界前向 CFG、图更新后重新执行受影响 caller；不声称等同旧交替 forward/backward FastSearch |
| `data_trace.py:609 _initial_stack_in_function_start`、`_initialize_callsite_arguments`、`_update_expr_from_callees` | 尚未完整接入 | 入口栈/参数 Root、跨过程 use/def/return alias 与真实内存输入是下一项优先工作 |
| `data_collector.py:241 read_data_by_expr`、`:277 add_icall_target`、`:287 add_switch_target`、`:413 calculate_icall_targets` | `TargetFact`、`analysis/controlflow/targets.py` | 根据新 CIR/byte defs 提取数值候选并提交图；旧递归表读取、store-alias 恢复、启发式与摘要尚未完整移植 |
| P2 AnalysisSession / P5 MemoryQueryPort | `analysis/framework/runtime.py`、`memory/image.py` | CFG/CG epoch、memory-version cache key、stale state、readonly image byte defs；旧库及新 caller 子图的完整 points-to 尚未接通 |

旧原生 VEX/Claripy 只在只读 characterization 与前端子进程中使用；analysis/memory/orchestration 没有直接原生 import。没有为了让结果数量相等而引入替代算法或 Golden seed。

## 测试与实际旧方法对照

最终 **209/209** 项回归通过，其中原 184 项和 P6 25 项。P6 的 25 项也在目标解释器 `-S` 下通过：无需 angr/Claripy 运行核心测试。

覆盖：scalar copy/binop、寄存器 full/partial/zero-upper、pointer provenance 丢失规则、guard false、MemoryQueryPort 的真实 read/write/alias 计数、MemoryVersion、unknown helper havoc、局部 identity summary 与 opaque call、CFG 分支、返回/循环/预算、Switch/间接目标、CG unknown remainder、重复边不抖动版本、反向 caller closure、受影响函数 fresh-scope 重分析、stale memory/port/纯 Compute 拒绝、MemoryVersion 自动 cache key，以及 clobber 前后寄存器符号分离。

旧 Python 3.7.2 通过 fresh `.p6-work` cache、PLY write_tables=false 和 write guard 执行真实 `FastDataFlow.process_block_in_backward`、`AccurateDataFlow._get_load_action_ast`、Collector 去重方法。未构造旧 Project 或运行旧 CLI。

原 scalar 链 `r1 → t0 → t1=t0+8 → r0` 的输入均为 `reg:r1`，旧 internal DDG edges `(0,1),(1,2)` 与新 CIR slice 相同。旧额外 `(2,3)` 是调用方输出 anchor，新 slice 将它表达为 outputs 参数，报告明确分开。旧 Load 真实结果为 `Load(0x2008,32)`、单个 address arg；本轮不把它当作可求解内存操作，也不声称旧 AST 已有端序/版本语义。上述只是已支持子集的 characterization，不代表全部 Accurate/FastSearch 等价。

旧模块 hash、PLY 调用、解释器、stdout/stderr 和新旧比较均保留。此前首次测试的缺模块预期失败、开发 probes、初次统计口径问题也全部保留，没有覆盖或改标。

## 真实 rv130 验证：未通过

选择完全来自只读 `httpd_block_info.json` 的 **17 个 iCall 站点 / 13 个调用者函数**，不来自 Golden targets。读取原 ELF 和 IDA CFG，经 P4 IDA→VEX→CIR；逐函数保存 CIR、opcode/unsupported、目标事实、CFG/CG 证据和 pending。其他 868 个函数仅有 IDA 元数据身份，没有本轮已分析的函数体/摘要。

| 项目 | 最终实际结果 |
|---|---|
| 原 source blocks | 774 |
| CIR blocks（含 VEX 切分及合成节点） | 1407 |
| VEX statements | 38879 = 5127 metadata + 30194 lowered + 3558 unsupported |
| 重分析 | 2 轮、24 次函数分析调用 |
| 最终 CG version / edges | 1 / 705（caller 子图，含 unknown remainder；非全程序 CG） |
| 最后每函数结果合计 visited blocks | 112；不能视作完整覆盖 1407 个 blocks |
| 最后结果的函数内 pending | 58；必须继续报告 Incomplete |
| 图变更重分析队列 | 最终为空；这不意味着函数内传播已完成 |
| 原 17 站点的观测 | 3 个到达后 unknown，14 个未到达，均非 exhaustive |
| Golden | 14 站点有目标、合计 535 条归档记录 |
| 新路径在原 iCall universe 的具体目标 | 0 |
| 具体记录差分 | missing=535、extra=0；未知集合没有被当作空集证明 |

到达但目标未知的 3 个站点：`0x10f1c`、`0x23f50`、`0x6eeb8`。完整 17 站点记录在 `native/site-coverage.json`，逐站点旧/新目标列表与 missing/extra 在 `native/native-report.json:differential`。归档目标是旧启发式结果/历史参考，不等于每条都已被 SMT 证实。

全部最终 raw target facts 中 154 条为 may、7 条为 unknown，confirmed=0。它们包含普通调用和 computed jump 的中间事实，不是 161 个原 iCall 目标。VEX 将部分常量调用写成 IndirectTarget，首个开发 probe 曾把普通调用混入 iCall 差分；最终结果已经按原 IDA 17 站点过滤，旧 probe 原样保留，不能以其 extra=126 作为当前结论。

实际 unsupported：`CallMemoryEffects`、`Iex_CCall`、`Iop_Clz32`、`Iop_Sar32`、`Iop_Shl32`、`Iop_Shr32`、`UndefinedTmp`。旧 ARM helper、递归表、入口状态和跨函数摘要等尚未贯通；未知定义/调用会保守扩大内存影响。原函数体字节均已 lifting，但内存/状态/控制语义没有完整覆盖，不能据“成功 lifting”宣称 `-i` 已复现。

函数每次最多 3 秒、2000 个 block-state 步、4096 states，最多两轮。主机负载和 wall 预算影响实际访问路径；此处绝不把预算限额当作收敛或安全结论。真实 Switch/ijmp 输入 JSON 都为空，本轮 Switch 仅通过人工可解释 fixtures，没有真实固件 Switch 等价结论。

## 图失效、状态与原始内存

读写/alias 通过 MemoryRuntimePort→P3 MemoryQueryPort→P5 memory engine；状态引用 ProgramPoint/Context/MemoryVersion/SSE/APG/Guard，不跨层保存原生 AST。clobber epoch 已加入状态 key，避免 unknown call 之后错误复用旧寄存器符号。

新增 CG/CFG 候选边后删除已知受影响函数的 heap/alias/SSE/APG/summary cache 与 owned port；按已导入 CG 的 reverse caller closure 重排。重分析使用新的 AnalysisScope 和 arena，不复用旧 global graph stamp 的 raw refs。无关纯 metadata cache 可保留。未导入的 callers/summary dependencies 仍不完整，不能说全程序 invalidation 已验收。

readonly ELF 初始数据按内存定义链读取；write/havoc 不被绕过。writable/BSS 在函数入口不假定未被调用者修改。入口 stack/argument 的真实 points-to 尚未完整迁移；APG 字段闭包和旧递归结构 trace 还没有全面接入本轮传播。以上情况被保守 unknown/Incomplete 表达。

## 指标与性能

以下为每个函数最后一次结果的 arena 合计；重复 image objects 按函数各自计数，不能当作全程序 unique objects：

| 指标 | 实际值 |
|---|---|
| SSE DAG unique nodes | 15712 |
| Heap objects / 写入字节 cells / memory versions | 26 / 456 / 853 |
| 内存定义/执行计数 / alias queries | 16367 / 2680 |
| APG nodes / edges / summaries | 0 / 0 / 0，未在真实传播中构造新的字段图 |
| taint facts / SMT queries | 0 / 0；未执行 P7 或 SMT 路径精化 |
| 两轮 block-state steps 合计 | 779 |

完整 per-invocation metrics、memory port calls、状态步数和墙钟在 `native/function-results.json`。P5 原测试中的 APG 指标不被复制来冒充 P6 的真实传播指标。

| 最终命令 | 退出码 | wall 秒 | 100ms 采样 launcher+child RSS bytes |
|---|---|---|---|
| P6 pure tests（25） | 0 | 1.859 | 29208576 |
| 全部 tests（209） | 0 | 24.328 | 82259968 |
| 真实旧方法 characterization | 0 | 29.453 | 118849536 |
| 真实 native dataflow / compare | 0（采集成功，不表示阶段通过） | 125.407 | 212934656 |
| diff --check | 0 | 0.953 | 18161664 |

native 内部 wall≈123.203 秒，其中 lift≈21.641 秒。RSS 为采样和，不是精确峰值或各内核独占内存；CPU 分项、纯 SMT/FFI、完整 firmware E2E 未采集/未执行。未做统计性性能对比，不能声称加速。

## 输入、环境与保护证据

最终 validation：`.p6-work/20261029T015236Z-8436ab4c/validation-20261029T023635Z-b8118fed/validation-p6.json`。其中 `quality_gate=PASS`、`phase_gate=NOT_PASSED`、`state=partial`。外层验证命令为非零退出（工具记录 1）；所有子命令如上为 0。脚本为 partial 定义了返回 2，不能将非零入口状态改写成 P6 Gate passed。

```powershell
./.venv/Scripts/python.exe -B -S -m unittest discover -s tests -p 'test_p6*.py' -v
./.venv/Scripts/python.exe -B -m unittest discover -s tests -v
../EmTaint/.venv/Scripts/python.exe -B scripts/p6_legacy_probe.py --folder <fresh P6 folder>
./.venv/Scripts/python.exe -B scripts/p6_probe.py --folder <fresh P6 folder> --legacy-report <same run legacy-report.json>
git --no-optional-locks diff --check -- . ':!.venv'
./.venv/Scripts/python.exe -B scripts/p6_validate.py .p6-work/20261029T015236Z-8436ab4c
```

输入 SHA256：固件 `334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787`；IDA CFG `e5ed02f0654e31df1837c9541e2d4b3fee9e6988293406b96ca0e3719f31ea1e`；block_info `843215d3a71d41844baf230d532e587e0599943f8f3d246a50d40ba64e2f3e62`；归档 icall-targets `3ce126b46a43e6563277a7ecf7f309c075602a240ddb46990c1f4ddb71de1a6c`。Golden 在分析结束后才打开；未种入 registers/heap/target graph。

目标解释器为 `BinaryAnalysis/.venv/Scripts/python.exe`，Python 3.12.9；angr/claripy/pyvex/cle/archinfo 9.3.4；z3-solver 4.13.0.0、psutil 7.2.2。旧解释器为 `EmTaint/.venv/Scripts/python.exe`，Python 3.7.2 / 原 9.0.9792 环境。没有安装或修改依赖。

SHA256/size/mtime_ns 全树前后一致：旧仓库 13461 文件、目标 `.venv` 13044、Golden 351、P1/P2/P3/P4/P5 证据 214/55/78/80/140。目标原业务源码 135 文件全部未变，新增 13 个 P6 源文件后共 148。三份用户规划文档字节不变；新代码静态检查无禁止的核心原生 import；运行源码 hash 与 probe hash 相符，进程 write guard 零越界。

Git base：target=`6cb026767db005e48b36b994ee8542962b6df627`，legacy=`72a9e3081632b2f9d1881141bc7b0d43c7158033`。旧已有 dirty/未跟踪结果原样保留；没有提交、reset/clean、清理旧证据、覆盖原 IDA JSON 或推送。最终 21 个交付文件快照与哈希封存在本轮 `final-source/`、`final-source-manifest.json`、`artifact-index.json`。

## 回退、剩余工作与继续 P6 的计划

既有入口、旧 reference 和 P5 SDK 的 legacy 默认保持原样；本轮新 CIR 路径未切成默认。**未自动执行新的 legacy `-i/-t`，也没有声称已实现完整目标 CLI 的运行时 failover。** 若缺少 legacy 实例，SDK 仍明确报错；不能将读取 Golden 算作旧算法重新执行。P0-B 的已有成功基线继续保留。

P6 仍需完成：

1. 移植并对照旧入口栈/参数状态和 `_initialize_callsite_arguments`，先找到 3 个已到达 unknown 站点的最早定义分歧；对 14 个未到达站点分别消除前端/控制/预算障碍。
2. 从原 AccurateDataFlow 的 load/store alias、反向需求和 use/def 传播逐例移植，通过 MemoryQueryPort 接入稳定 Root、APG 和 MemoryVersion，不能用不经验证的新算法替换。
3. 迁移 `_update_expr_from_callees`、参数/返回 alias 与实际 ProcedureSummary；从 caller 子图扩大到真实依赖图，验证真实 reanalysis/invalidation。
4. 对 ARM helpers/shift/纯值 unsupported 的 lowering 语义补充独立 tests；保持 Schema 不变或按规则单独审查版本变化，不靠全状态 havoc 冒称精确支持。
5. 在同一 CIR、预算与输入下重新比较原 17 个 iCall 站点、CG 与证据；只有差异可解释且达到保真要求，才将 P6 标为通过，再考虑 P7。

**本轮停在 P6 的 partial checkpoint；P6 尚未完成验收，不推进 P7、Gate A 或 Rust。**
