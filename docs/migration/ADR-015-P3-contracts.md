# ADR-015：P3 Typed CIR 与 Memory-Semantics-v1

状态：本轮 P3 决定；Python 表示、验证和 wire schema 已实现，P5 执行语义未实现。承接蓝图 ADR-001/003/010…014，三份用户 v5 规划文件保持原样。目标环境仍遵循 TARGET_RUNTIME.md 的 angr/Claripy 9.3.4 决策。

## 决定

1. 新 CIR 放在 `emtaint/ir/canonical/`，使用 frozen typed effects，不继承 pyvex/IRSB，不覆盖旧 `ir/vex_ir.py` 或旧表达式类。非 SSA 的 ValueRef 表示函数内有类型变量，effect 顺序保留；SSA、支配关系和实际表达式执行均留给后续阶段。
2. CIR `LoadEffect/StoreEffect` 表示程序访存；AccessRoot/Path/APG 描述位置或 may-path 集合；MemoryVersion/HeapObject/HeapCell 描述状态与定义；SymbolicNode 描述共享值关系。MemoryRead 必须引用独立版本和位置，不将自定义 Claripy Load/Store 搬进任何一层。
3. 重用 P2 BinaryId/FunctionId/BlockId/ProgramPoint/ContextId/MemoryObjectId。SymbolicExprId、MemoryVersionId、Location/Path/Graph ID 另有 AnalysisScope，保存 session、函数、上下文、CFG/CG 版本和 session state revision。使用 from_session/assert_current 检查活跃会话，禁止复用过期引用。
4. `CIR-Wire-v1` 与 `Memory-Semantics-v1` 使用白名单 tagged JSON：record `$type`、enum `$enum`，tuple 编码为 array，所有字段显式传输；不同类型、None、0、false 不合并。未知版本、字段、类型或 capability 直接拒绝，不用 pickle/eval，不动态 import 线上的类型名。
5. Wire 字节/节点/深度与整数位数有界。JSON Schema 描述结构，Python 构造器另验证关联位宽、引用、scope、图拓扑、强更新前提与完整性；schema 校验本身不证明别名、摘要 soundness 或漏洞可触发。
6. APG summary 必须携带 trigger、pattern、重复范围、覆盖论据与 precision_loss。默认 soundness=unknown；声明 summary 不能自动得到 MustAlias、NoAlias、数据流收敛或已确认漏洞。
7. 强更新描述要求 must-alias 证据、唯一目标、精确覆盖和 singleton 对象事实；缺少这些前提只能声明 weak。证据是生产者提供的声明，P3 不执行别名证明或 heap 更新。不同对象 ID/栈帧/context 本身不是 NoAlias 证据。
8. MemoryQueryPort/AbstractHeap 的缺省对象抛 UnsupportedSemantics；缺省 SolverLowering 返回 UNSUPPORTED 且没有 SolverQuery，不执行求解、自动 fallback 或把未知当空事实。P1 SolverPort 状态继续区分 SAT/UNSAT/UNKNOWN/TIMEOUT/UNSUPPORTED/ERROR/CRASH。

## v1 的明确边界

- 支持 8-bit byte 的架构；访存宽度为整字节，标量/指针位宽上限 4096。非字节访存、浮点、向量、架构专有副作用未定义时必须保留 UnknownEffect/Unsupported，不猜测语义。
- MemoryVersion 与 SSE 的联合定义依赖为 DAG；APG 可以有环。循环 MemorySSA phi/递归内存定义不能假装成已支持的 DAG，后续需独立摘要契约或版本升级。CFG 环、APG 环和对象自环分开。
- P3 只声明内存读写/别名/定义解析的接口，未实现 APG 构造、heap、widening、Worklist、真实 taint 或内存 lowering。手工 next* descriptor 不视为算法从 1000 层链表归纳出了摘要。
- LoweringRequest 显式含 check/eval/min/max、limit、guards 和 query budget；LoweringResult.READY 只能包含已验证的 P1 纯 BV SolverQuery。P5 可先实现局部定义 + BV/ITE lowering；SMT byte-array Select/Store 尚无后端契约实现，需要独立明确扩展，不能直接塞进 P1 不支持的 memory op。
- M-01…M-12 同时记录 contract_status 与 runtime_gate_m；P3 契约通过不将 runtime_gate_m 改标为 PASS。Gate M 仍属于 P5，Gate A 仍属于 P7。

## 版本与后果

v1 的字段、标签、枚举和语义在本轮完成后固定。额外字段也会被旧消费者拒绝；新增不兼容字段/操作或改变内存语义必须定义新版本和显式迁移，保留历史 fixture。后续 Rust 只能读取相同版本及规则，P3 不创建 Rust 代码。

优点是可在无 angr/IDA 环境中构造、验证和保存同一份输入，未知语义可见，旧算法路径可保留。代价是 v1 明确限制了可表示的原语和定义拓扑；这比隐式替换旧 Load/Store 为自由符号或空结果更容易审查。P4 负责真实前端 lowering 和 Origin，P5 负责执行、保守性证据和 Gate M；没有这些证据不会把 v1 描述为完整分析引擎。
