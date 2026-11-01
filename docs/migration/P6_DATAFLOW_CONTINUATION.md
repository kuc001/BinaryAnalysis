# P6 当前接口：CIR 需求传播、旧规则与版本化内存

本轮仍采用 Python 3.12.9 / angr 9.3.4，P3 CIR/Memory wire v1 不变。验收与已知边界见 [阶段报告](phases/P6-continuation-report.md)。此前的 [接口说明](P6_DATAFLOW.md) 是首次 partial 实现的历史记录。

| 原方法 / 问题 | 当前接口 | 语义与验证 |
|---|---|---|
| `_initial_stack_in_function_start` | `analysis/dataflow/entry.py:legacy_entry` | 旧 SP 哨兵 `0x7fffffff`；frame 根由 function/context 身份确定；4 个寄存器参数及 4 个入口栈参数。参数 pointee 不假定互不别名 |
| `_initialize_callsite_arguments` | `LegacyDemand.register/stack_argument`、`ProcedureRecipe.evaluate` | 反向定位实际调用处寄存器定义；栈参数使用调用时 SP 和 reaching store，不能拿 callee 的 SP 直接当 caller 的地址 |
| FastDataFlow backward use/def | `analysis/dataflow/fast.py`、`LegacyDemand.reaching/register/value` | 有界需求 worklist；先匹配最新定义再展开值；保留分支合流与循环入口可能性 |
| `_find_wrtmp_load_def_v1` / `_do_store_define` | `LegacyDemand.read/memory_definitions` | Load 成为版本化 ReadMemory 与单独地址需求；完整 MustAlias store 可替换值，May/partial/guarded 定义保留 unknown |
| `label_inc_flag_in_loop` / `_summary_variable_in_loop` | `LegacyDemand.increments/induction` | 由真实 def-use 环识别单一 stride，旧 `base + i*stride` 摘要保留零次迭代；不凭任意循环猜递增 |
| `_update_expr_from_callees` | `analysis/framework/summaries.py:compile_recipe/ProcedureRecipe` | 从实际 CIR 返回、参数与 store 生成 detached recipe；通过 caller 的 MemoryQueryPort 实例化，禁止传递 callee 的 scoped SSE/APG/MemoryVersion ID |
| 旧 Collector 表恢复 | `analysis/controlflow/legacy_tables.py` | 最大索引 4096；内部数据表与外部函数表独立枚举；保留旧非代码终止、零值与站点边界策略；结果均为 MAY |
| 全依赖图 | `frontends/program_index.py:build_program_index` | 881 个内部函数元数据和 337 个外部名称节点；P6 只 lifting 19 个相关函数体，不宣称分析了所有函数体 |
| 图与摘要改变 | `AnalysisRuntime`、`CIRProgramSearch`、`TargetGraphUpdater` | reverse CG caller closure；删除相关 cache/recipe/ports；新 scope 重分析；可撤回过期 derived targets，保留静态证据及 unknown remainder |
| ARM pure helpers / shifts | `frontends/arm_scalar.py`、`VEXLowerer` | 使用已有 CIR 标量操作展开，不增加 Schema；AAPCS 调用区分 caller-saved 与 nonvolatile，外部写内存仍显式未知 |

## 内存与入口

`MemoryRuntimePort` 的 read/write/resolve_alias/resolve_definition 调用 P5 引擎及 P3 MemoryQueryPort。Root、位置、APG、版本与 SSE 分开保存。APG 只表达可能的地址路径，不能凭路径相同推出 MustAlias。

`ImageMemoryEngine` 默认 `readonly-at-entry`。为复现旧 Collector，需要显式选择 `legacy-loader-snapshot`：输入来自实际 CLE 重定位后的不可变映像，而非 raw ELF 或 Golden。后续 store/havoc 仍经过 MemoryVersion；此策略不证明 writable memory 在真实运行中一直保持初值。

入口栈参数在 InitialMemory 上按字节/端序提供，后续写入可覆盖输入。需求层只对完整、对齐的入口字读取建立参数符号。Frame NoAlias 快速路径额外验证 CFG 中 SP 位移及访存地址：逃逸到 ELF 映射、回绕或无界 SP 循环会关闭该路径，不能仅凭 frame 标签排除别名。

## 跨过程摘要与失效

`ProcedureRecipe` 是分析私有的 frozen metadata，不是新 wire Schema。它含本地整数边、类型、参数槽、读地址、返回候选及带 guard 的 store；携带真实函数体 hash/provenance。含未知外部写入时保留 `unknown_effects/write_regions`，不能把返回候选当成纯函数证明。

参数 store 的替换先证明地址对应，再展开 stored value；地址未证明对应时产生未知内存影响，不能把无关 callee store 的值强行代入 caller。旧的 eager 展开曾造成 SSE 超预算及候选多报，失败证据已保留。

session 的 state revision 与函数 epoch 分开处理。全局 revision 使所有旧 scoped handles 过期；无 scoped ID 的 detached recipes 才可在无关函数改变时按 epoch 存活。summary 内容变化会使 callee 及反向调用者相关 heap/alias/SSE/APG/summary/facts/result 失效；相同摘要不抖动版本。图中只有元数据、没有既有分析结果的函数记录 invalidation，不虚构重新分析。

## 固定点、预算与证据

真实 CIR 回放固定每函数 demand steps=250000、alternatives=256、depth=500；P5 SSE nodes=200000、memory/worklist iterations=2000000，表索引=4096，图重分析最多 4 轮。超限保留 partial targets、pending 和 Incomplete，不转换为空目标证明。

`CIRLegacySearch.run` 返回目标、17 站点的分类/CFG 可达性、规则证据、pending、assessment、snapshot、metrics 与用于旧 Collector 差分的 detached 需求表达式。候选不证明 guard 可满足或运行可达；`cfg_reachable` 仅指所用静态 CFG。

`p6_memory_archive.py` 将完整 arena 流式存为原 P3 wire 记录及 count/hash manifest，以避开单个巨型 JSON 的诊断编码限额。没有截断 arena，也没有改变 Schema。原 CIR/loader 文件是重放输入；JSONL 是诊断容器。

旧 Collector 对同一 CIR 派生需求、相同 relocated bytes、4096 索引及原站点边界执行。适配只删除已证明等值的同宽零加法地址 cast；否则旧自定义 Load 的简化会残留外层 Add，改变 Collector 的 opcode 分派。报告保留这次失败及修复，不把该边界差分伪称第二套独立 FastSearch。

## 原生边界与回退

迁移后的 core、canonical IR、graph、memory、dataflow/framework/controlflow/SSE/taint 与 orchestration 不直接导入 angr/VEX/Claripy/Z3/IDA。原目标工程保留的旧 native IR/PAG wrappers 仍是兼容代码；本轮核对其内容未变，并单独记录 import，不声称整个仓库均无 native import。

`run_with_legacy_fallback(apg_runner, legacy_runner)` 调用实际提供的 reference runner，保留失败的 primary attempt；没有 runner 时明确报错。Golden 只用于分析后的比对，不能作为 fallback 执行结果。既有默认入口仍保留；完整新 `-i/-t` CLI、taint 和 Gate A 属于 P7，本轮未开始。
