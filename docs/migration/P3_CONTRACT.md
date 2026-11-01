# P3：CIR 与内存契约 v1

实现目录：`emtaint/core/contracts.py`、`emtaint/ir/canonical/`、`emtaint/memory/`、`emtaint/solver/lowering.py`。这些模块只依赖标准库与纯 Python DTO，不导入原生前端。决策见 [ADR-015](ADR-015-P3-contracts.md)，验收见 [P3-report.md](phases/P3-report.md)。

## CIR effects

`CIRModule` 携带 schema_version、memory_semantics_version、producer、architecture、endian、binary_sha256、functions、origin_map、capabilities、assessment 及可选 memory_snapshots。`CIRFunction` 携带 function_id、ABI、变量声明、块和入口。`Origin` 保留 Producer 的工具/版本/前端、ProgramPoint 和 source_opcode。每个 effect 必须绑定已声明的同块 origin；未使用的 origin 也不能悬空。

| 表示 | 语义与校验 |
|---|---|
| ValueType / Constant / ValueRef | bool、BV、pointer 明确分开；保留位宽、signedness、地址空间；常数必须已按位宽截断 |
| Compute | COPY、ADD/SUB/MUL、位运算、EQ/ULT/SLT、NOT、Extract、Zero/SignExt、Concat、If；按位向量模语义解释，P3 仅做类型校验 |
| Read/WriteRegister | 显式 bit_offset、片段宽度与完整寄存器宽度；写策略为 full/preserve_others/zero_upper，不猜测子寄存器行为 |
| LoadEffect / StoreEffect | 有序 effect，地址必须是匹配地址空间的 pointer，宽度/端序/guard/origin/alignment/volatile 保留；不是 MemoryVersion 或 SMT Array |
| CallEffect | direct/indirect/external/unknown target，参数、结果、ABI、guard 和 footprint；未知外部副作用默认写所有区域并 clobber 所有寄存器 |
| Branch / Jump / Return | typed condition / pointer 或块引用；显式控制转移在块末尾，分支目标须已声明 |
| UnknownEffect / HavocEffect | 保存原 opcode、原因、可能写入范围/寄存器/控制影响；未知效果不能静默成为 no-op |

CIR 是有顺序的非 SSA effect 表示；所有 ValueRef 在函数中声明，P3 不检查完整 use-def/支配或执行这些变量。guard=false 的 Load 不赋值，Store 不写；VEX LoadG 的 alternate 应由前端显式赋值/条件逻辑编码，不能丢弃。P4 尚未实现这种转换。

Origin、callsite、块变体与架构位宽有交叉检查。UnknownEffect 或未知 CallMemoryEffects 必须在 module assessment 的 unsupported_ops 中保留且 status=incomplete，不能只把未知指令从 effects 中移除后声称完整。

## 访问路径、APG 与对象

`AccessRoot` 引用 P2 稳定 MemoryObjectId，携带 region/address_space/origin；寄存器名不充当对象根。`AccessSegment` 是 Offset、Deref、Index、UnknownOffset 的 tagged union。Offset 是字节地址加法，Deref 保留 pointer/value bits、endian/address_space；Index 保留表达式、stride 和范围；未知偏移保留 interval/top 与 reason。

`AccessPath` 另有作用域 ID、width/endian/origin/assessment。`p+8` 和 `*(p+8)` 的 segment 类型与 deref_count 不同。modular_offset 只提供偏移表示的模运算，不读内存或推断 alias。

`AccessGraph` 的节点/边/summary 是路径语言描述。summary 的循环端点可以相同，但它不证明 heap 对象自环。节点可带稳定 root；summary 保存触发点、字段 pattern、重复范围、覆盖论据、精度损失和 soundness 声明。缺少 precision_loss 或未验证 summary 被标 complete 时校验失败。P3 不验证该论据的数学正确性，也不构建或执行摘要。

`MemoryObject` 复用 P2 的身份/来源/大小/地址空间描述；`HeapObject` 另声明 region、singleton/summary/unknown cardinality、lifetime、分配 origin 和 provenance。`HeapCell` 绑定 location/value/defined_in。它们是 wire 中的对象事实，不是已实现的 AbstractHeap。

## 内存版本、SSE 与 taint

`MemoryLocation` 保留对象或 unknown、字节 offset interval/top、访问位宽、端序、地址空间和诊断。它的 byte_interval 仅在精确偏移时返回半开区间；区间重叠不代替地址别名判定。

`MemoryVersion` 的定义区分 InitialMemory、WriteMemory、JoinMemory、HavocMemory。Write 明列 parent、location、value、guard、强弱更新与 alias 证据；Join 保留每个 predecessor 的 guard；Havoc 保留 parent、guard、范围与原因。ReadMemory 单独引用读取版本、location、result 与 guard；memory guard=None 表示无条件，不表示未知 guard。未知 guard 必须是带原因的 boolean SSE 引用。

`SymbolicNode` 用 ID 引用标量子值或 MemoryRead(state,location)；不保存原生 AST，不支持自定义 Load/Store op。它与 CIR 共用标量类型规则，但与 APG 是独立的图。MemoryVersion/SSE 的联合依赖校验会拒绝自引用与循环，例如“写入 M1 的值读取 M1 自身”；这只是定义一致性，不能当作循环数据流已经收敛。

AliasKind 为 Must/May/No/Unknown。Must/No 需要显式 exact/complete 证据；bool(alias_result) 禁用。强写必须额外有 unique_target、exact_coverage、精确 location 和 singleton 对象事实；summary/unknown 对象不允许仅凭一个抽象 ID 做强更新。P3 只检查证据字段的一致性，不产生 alias 或 cardinality 证明。

TaintFact 必须引用 root + path/APG 二选一、context、MemoryVersion、guard、kind、origin、provenance 和 assessment；引用路径或 APG 的入口 root 必须匹配。没有“may-alias 即已确认漏洞”的转换。Source→Sink 判定与实际传播留到 P5/P7。

AnalysisScope 包含 session、function、context、CFG/CG 版本和 state_revision。在线调用使用 `AnalysisScope.from_session` / `assert_current` 检查引用是否过期；wire 中的自包含快照只检查内部 scope 一致性，不能替代对活跃 Session 的检查。

## Ports、预算与状态

`MemoryQueryPort` 定义 read/write/resolve_alias/points_to/resolve_definition；`AbstractHeap` 定义 snapshot/object_info。缺省对象全部抛 UnsupportedSemantics，不能用 unchanged-state、空定义或 NoAlias 代替缺失实现。

`SolverLowering` 接受版本化 MemorySnapshot、focus expression、guards、operation=check/eval/min/max、limit 和 QueryBudget。bool focus 用 check，BV/pointer 用 eval/min/max，类型或限额不符即拒绝。READY 必须有经过 P1 validate 的纯 BV SolverQuery；缺省 lowerer 返回 UNSUPPORTED、query=None 和来源/诊断，不调用 solver。SAT/UNSAT 等是执行 SolverPort 后的状态，不能从 LoweringStatus 推断。

P3 的已声明输出 profile 是 P1 纯 BV/ITE；SMT byte-array Select/Store 尚无实现，未定义的内存 lowering 保留 UNSUPPORTED/Incomplete，禁止绕过 P1 memory-op 拒绝机制。

SemanticBudgets 分别声明 APG nodes/edges/summaries、SSE、heap objects/cells、worklist states/iterations、contexts、alias、SMT 次数/超时；QueryBudget 限制局部查询。exhausted() 生成 Incomplete 诊断；P3 没有执行预算计数或收敛算法，不能因预算字段存在就声称分析能在预算内结束。

## Wire 与测试

公开结构 schema：

- [CIR-Wire-v1](schemas/cir-wire-v1.json)
- [Memory-Semantics-v1](schemas/memory-semantics-v1.json)

`wire.dumps/loads` 同时提供受限的 DTO fragment 编解码。完整 CIR 包以 CIRModule 为根，完整内存包以 MemorySnapshot 为根；单独 AccessPath 等 fragment 不能冒充完整包。decoder 只接受注册类型，字段没有省略/默认填充。默认最大 16 MiB、100000 nodes、64 层、整数 4096 bits；重复 JSON key、浮点/NaN、未知字段/类型/版本/capability 均拒绝。

Schema 使用 Draft 2020-12 结构关键字。Python 验证器在结构之外检查 scope、引用、位宽、依赖图与完整性。当前环境没有 jsonschema 包，本轮未安装；测试使用独立的已用关键字 shape evaluator，未宣称经过完整第三方 Draft validator。

`tests/conformance/memory/fixtures.py` 的 M-01…M-12 同时输出 contract_status、runtime_gate_m、预期运行行为、descriptor counts 与 runtime metrics。P3 合同检查可以 PASS；所有 runtime_gate_m 仍为 NOT_IMPLEMENTED。手工构造的 next* APG、10/100/1000 长路径和字节区间不证明真实 heap 更新、摘要覆盖或收敛。后续 P5 必须提供实际引擎并逐项替换这些运行缺口，不能改标历史输出。
