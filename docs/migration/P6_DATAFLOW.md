# P6 首次接口说明（历史版本）

当前接口、真实旧方法迁移及边界见 [P6_DATAFLOW_CONTINUATION.md](P6_DATAFLOW_CONTINUATION.md)，阶段结果见 [P6-continuation-report.md](phases/P6-continuation-report.md)。以下保留首次 partial 实现的说明，不代表当前覆盖范围。

本轮是 Python 渐进迁移。**组件回归通过，完整 P6 目标保真验收未通过。** 不能将本实现作为旧 FastSearch/FastDataFlow/AccurateDataFlow 的完整替代，也不能据此进入 P7 或宣布 Gate A。实际差分与继续计划见 [P6-report.md](phases/P6-report.md)。

## 模块与接口

| 模块 | 接口 | 当前覆盖 |
|---|---|---|
| `analysis/dataflow/fast.py` | `CIRFastDataFlow.slice` | 反向 scalar def-use，寄存器/值依赖，基于 MemoryQueryPort alias 的内存需求；未迁全 CFG 反向 trace |
| `analysis/dataflow/accurate.py` | `CIRAccurateDataFlow.initial/transfer` | CIR Compute、寄存器 slice/partial/zero-upper、guard、Load/Store、Unknown/Havoc/Call |
| 同上 | `ProcedureSummary.identity` | 显式声明、附 proof 的局部 identity 摘要；未自动移植原摘要库、参数/返回 alias |
| `compat/memory_runtime.py` | `MemoryRuntimePort` | descriptor/value/location 适配；实际 read/write/alias/defs 经 P3 MemoryQueryPort 调用 P5 实现 |
| `memory/image.py` | `ImageMemoryEngine` | immutable ET_EXEC segment 初始字节；readonly 数据可按内存版本解析；writable/BSS 在任意函数入口不假定仍是文件初值 |
| `analysis/framework/state.py` | `FlowState/TargetFact` | ProgramPoint、Context、MemoryVersion、SSE/Guard/APG refs、精度、寄存器 clobber epoch |
| `orchestration/fast_search.py` | `CIRFastSearch.run` | 有界、路径敏感的前向 CFG worklist，目标事实、返回、fixed-point 或显式 pending |
| `analysis/framework/runtime.py` | `AnalysisRuntime` | session-owned 版本、cache namespace、跨 MemoryVersion key、stale handle/port 检查、受影响 caller closure |
| `analysis/controlflow/targets.py` | `TargetGraphUpdater.apply` | may/confirmed/unknown 区分；batch CG 和 Switch CFG 变更；不以 may 候选删除 unknown remainder |
| `orchestration/program_search.py` | `CIRProgramSearch.run` | 图变更后仅重排受影响的已导入函数，用新 scope/port 重新执行；轮数不足时保留 pending |

核心不导入 angr、pyvex、Claripy、Z3 或 IDA；跨层没有原生 AST。P3 CIR/Memory Schema 与 P5 旧接口均未修改。

## 状态与内存

Value/寄存器/APG/guard 引用必须与 MemoryVersion 同 scope/context。寄存器中的地址 provenance 与存储对象 Root 分开保存；部分寄存器读取不能继续携带整个指针的 Root/offset。只有完整、无条件定义保留该指针绑定。

UnknownEffect、未建模调用和显式 havoc 按 footprint 处理内存与寄存器。寄存器 clobber 后使用独立 epoch 的符号，不能错误地与入口值相关。未知 guard 保留 true/false 分支；未知 side exit 在对应 origin 处分叉，避免将退出后的 store 带入退出路径。没有描述的控制流、未定义值、超限与无法解析的目标均显式 Incomplete。

ImageMemoryEngine 的 readonly 初始字节仍受后续 store/join/havoc 定义链影响；它不绕过 MemoryVersion 直接从文件返回值。writable globals 和 BSS 不假定在函数入口仍是 loader 初值。重定位、跨函数实际内存输入及运行时初始化尚未完整建模；实际分析的输入与输出均保持 Incomplete。

## 版本、失效与重分析

缓存 family 为 heap/alias/SSE/APG/summary/facts/result。`memory_put/get` 自动把 MemoryVersion 加入 key，并检查 session/context/scope；不允许把 M0 的 alias 结果用作 M1 的结果。

CG 新增边或 CFG 改变后，按已导入 CG 的反向 caller closure 递增受影响函数 epoch，删除其缓存和 owned ports，将函数排入 pending。P2 的全局 revision 仍使旧 P3 raw handles 失效；旧 port 的读取、候选查询及纯 transfer 都会拒绝 stale 状态。没有重基准/证明的旧 rich state 不会悄悄复用。

无关函数的纯 metadata cache 可以保留；这里不是在新 graph stamp 下无条件复用旧的堆/表达式 arena。CIRProgramSearch 按批执行，再提交图更新；重分析 callback 必须新建 current-scoped port。重复相同边不抖动版本。真实 CG 只导入了本轮 caller 子图，未知反向调用关系仍需完整迁移，不能据此声称全程序失效已经覆盖。

## 固定点与预算

worklist 按 block、memory、values、registers、address bindings、guards、APG refs、assessment 和 register epoch 区分状态。相同状态可固定点终止；无法收敛时按 states/steps/wall/内存域预算显式停止。pending 是诊断 frontier，不是已实现的可从语句中间安全续跑的 checkpoint；本轮重分析从函数入口开始。

真实 probe 固定每函数 3 秒、2000 block-state 步、4096 states，最多两轮图重分析。wall 预算使 coverage 随主机负载变化，因此保留每次独立 run，不以不同 coverage 的耗时宣称性能收益。所有零计数必须结合 unknown/not_reached/pending 解读。

## 目标与回退

目标值从 CIR 和版本化内存定义推导。无法穷尽时 exhaustive=false；may 只代表候选；未知绝不作为“没有调用目标”。静态目标确认只表示到达该调用时的固定目标值，不证明漏洞或真实执行可达性。

原 IDA iCall 站点是本轮差分 universe。VEX 会把某些常量调用的临时值表示成 IndirectTarget；这些普通调用仍保留为 call/CG 证据，但不混入原 17 个 iCall 站点的新增目标计数。Golden 在分析结束后才打开，既不输入寄存器/Heap，也不作为目标种子。

既有入口、原 reference 与 P5 `memory_engine=legacy` 默认选择器保持原样；新路径是显式实验接口。本轮没有实现完整目标仓库的 legacy `-i` CLI，也未自动重跑旧 `-i/-t`。缺少 reference 实例时仍报错，不能把读取 Golden 伪称实际 fallback 执行。
