# P5 Python 内存核心接口与支持边界

运行版本遵循 `TARGET_RUNTIME.md`：目标 Python 3.12.9、angr/Claripy 9.3.4，使用目标 `.venv/Scripts/python.exe -B`。不安装依赖、不调用旧分析 CLI、不引入 Rust。P3 的 CIR-Wire-v1、Memory-Semantics-v1 及已有 DTO/Schema 保持原样。

## 层次与入口

| 层 | 入口 | 含义 |
|---|---|---|
| 稳定身份/路径 | P3 `MemoryObjectId`、`AccessRoot`、`Offset/Deref/Index/UnknownOffset`；`PythonMemoryEngine.path/location_from_path` | 地址加法不读取内存；Deref 未解析时返回 unknown location，不能猜成原 Root |
| APG | `memory.access_graph.AccessGraphArena.intern/field_closure`、`accepts` | 有限自动机表示 may-path 语言；不是精确对象图或别名证明 |
| Heap/版本 | `memory.engine.PythonMemoryEngine` | 实现 P3 `AbstractHeap` 与 `MemoryQueryPort`；持久 `Initial/Write/Join/Havoc` 定义 |
| 定义追溯 | `memory.memory_version.DefinitionResolver` | 按字节、按需解析；保留版本、guard 和 MayAlias 候选 |
| SSE | `analysis.sse.SymbolicExprDAG` | typed hash-consing、常量模运算、迭代 lazy substitution/memo；MemoryRead 是状态/位置引用叶子 |
| 原语义兼容 | `compat.sse.LegacySSEAdapter/LegacyAstPacket/LegacySSEView` | 只在兼容层访问原生 AST；明确绑定稳定 Root、状态、端序与 origin |
| CIR 测试执行 | `memory.cir.MemoryEffectInterpreter` | 有界顺序 Compute/Load/Store/Call/Havoc/Unknown effects；不执行 CFG 或跨函数分析 |
| Solver | `solver.memory_lowering.MemorySolverLowering.lower/solve` | 局部字节定义 → 纯 BV/Extract/Concat/ITE → P1 SolverPort；不将旧 Load/Store 送入 SMT |
| 污点事实 | `analysis.taint.MemoryTaintTracker` | 显式 Source 绑定经值/内存定义到 Sink 参数的 may-flow；记录 guards/版本/来源，永不自行确认漏洞 |
| 预算 | `memory.policies.Accounting/BudgetedWorklist/BudgetExceeded` | 各域单独预算；失败携带 Incomplete，工作队列保留 frontier |

## 使用约束

`PythonMemoryEngine(scope, architecture, origins, budgets)` 是每会话独立的 arena。先用 `add_object` 注册 P3 MemoryObject 与 AccessRoot；默认 cardinality/lifetime 为 unknown。声明 SINGLETON、区分具体存储或外部副作用范围时，调用方须提供真实 provenance。`prove_disjoint(a,b,evidence)` 是显式输入的存储不相交证明，不是根据两个 ID 不同就推导 NoAlias；证据保存在 object provenance 中并随 v1 快照往返。

`location(root, offset, width, endian, origin)` 用于已规范化的对象相对位置；路径偏移经 `location_from_path` 按指针位宽取模。Index 的有限范围被保留；无法规范化、跨模数的范围或有 Deref 而无 points-to 证据时返回 unknown。不同 root、栈帧或上下文不会自动产生 NoAlias。`points_to` 当前只提供“所有已知对象 + 未枚举未知存储”的保守结果，必须检查 assessment，不能把已知列表当作封闭集合。

`store(parent,location,value,guard,origin)` 接受显式位置并推导安全更新策略。P3 `write(WriteMemory,QueryBudget)` 同时保留调用方的 alias、unique-target 和 exact-coverage 限制；不能将调用方弱更新升级。唯一 singleton、MustAlias、精确覆盖齐备才允许强更新；其余情况保留旧/新值及不确定条件。支持未对齐、多字节覆盖、大小端和模地址字节访问。对象 size 是元数据，尚未实现完整越界/生命周期验证；FREED 访问明确 Incomplete。

`load` 返回引用叶子，不递归展开 Load AST；`resolve_definition` 返回实际可能到达的版本。`guarded_load` 必须提供 alternate，false guard 不产生读取；原始 guarded read 的未执行结果是未指定值，不能当作 0。不同 guarded read 使用独立定义。字节身份跨读取宽度/端序保持一致。旧状态不可变，重写 next 或普通字段后新状态不会复用旧定义。

`join` 保留前驱 guard；不假定 guards 互斥或穷尽。未约束的 fallback 和弱写目标/别名条件是明确的上近似，会引入额外候选。未知调用与 UnknownEffect 对声明区域 havoc；不知道范围时为 `*`。快照会保留 Incomplete。原子操作、helper 精确语义和完整 ABI 尚未支持。

## APG 与收敛的证明范围

`intern` 对识别到的连续重复词执行 `prefix.word^k.suffix ⊆ prefix.word*.suffix`。有限词的完全相同判定是摘要前提；保留 trigger、pattern、coverage_argument 和 precision_loss。它不会把不同字段、解引用宽度、端序或 address space 合并为相同标签。

`field_closure(root,patterns,trigger)` 表示 `(word1|...|wordN)*`，覆盖调用方提供的全部字段词的任意有限组合，可描述树的 left/right、双向链表 next/prev。允许不可行组合，因此是 may-path 上近似。调用方仍需确认字段词集合覆盖其输入，不能以它宣称整份程序的精确堆模型。

不规则路径无法摘要或预算耗尽时抛出 BudgetExceeded；不存在“截掉路径后返回无目标”的行为。链表 10/100/1000 的图有界不等于程序状态/上下文必然收敛。通用 worklist 对有限 equality-key 状态固定点终止；无限递归状态明确 Incomplete 并保留待处理项。完整 Fast/AccurateDataFlow 的格、上下文策略和 CFG/CG invalidation 属于 P6。

为了可复核，测试同时保留了输入 AccessPath；其 segment 数仍随 10/100/1000 增长。不能将有限 APG 节点数或单个 MemoryRead 叶子误报为整个进程恒定内存、精确完成 1000 次真实堆解引用，或固件 E2E 加速。

## Solver 与事实解释

Lowering 先解析相关 MemoryVersion 的 byte defs；已确定的值直接成为 BVV。可能别名、weak update、join 使用保守 ITE，initial/havoc bytes 使用稳定的未约束符号。这是局部 byte-select/store 的等价定义编码，不是已实现完整 SMT Array 内存后端。

`lower(LoweringRequest)` 返回 P3 LoweringResult；只在 READY 时有可送给 P1 SolverPort 的 query。Unsupported、局部查询步数/递归预算耗尽单独返回 UNSUPPORTED/INCOMPLETE，不生成 UNSAT。解析无关写入使用迭代跳过；仍需展开的相关定义/表达式有 64 层保护和独立步数预算。

`solve(request,port)` 保留 SAT/UNSAT/UNKNOWN/TIMEOUT/UNSUPPORTED/ERROR/CRASH；求解次数耗尽返回 UNKNOWN。必须同时读取 `last_lowering.assessment` 的 precision_loss 与完整性。MayAlias 的 SAT 只证明抽象公式有候选，不证明真实指针别名或漏洞可触发。本轮实际 UNKNOWN 为通过真实后端异常路径的故障注入；实际 1ms TIMEOUT 有独立压力查询。

旧 `Store(address,width)` 无写入值、顺序、端序、guard 等数据，不能独自还原一次写入。适配器明确拒绝；旧 Load 只有在调用方补齐状态/端序/origin/Root 绑定后才能导入。未支持表达式、VSA/strided/带注解 AST 均显式拒绝。本轮没有替换所有 VarExpr/TraceExpr/RecursiveExpr/SimAction 方法或旧启发式别名算法。

TaintTracker 在显式 Source 输入上追踪 SSE/byte-definition 依赖；strong overwrite 可以切断旧数据依赖，false guard 排除该路径，havoc/未知内存产生 unknown 候选。它不是 Source/Sink 自动发现、完整 sanitizer 模型或漏洞规则。快照保存 TaintFact；Source→value 的绑定是显式分析输入，回放时须传回同一绑定。

## 选择、回退与快照

```python
from emtaint.memory.engine import select_memory_engine

active = select_memory_engine(legacy=validated_reference)       # 默认 legacy
active = select_memory_engine('apg', apg=python_memory_engine)  # 显式实验路径
```

选择器只选择提供的实例；缺失 reference 时抛错，不伪造一个旧模型实现。旧 CLI、VexIR 和原 frontend 均保持原样；尚无已完成的目标 `-i/-t` 兼容 CLI 开关。Rust/hybrid 组合未实现。

`snapshot(state)` 导出会话保留的全部定义/表达式 arena，参数 state 用于确认所需版本存在；读取使用的版本仍由 ReadMemory 指明。它不把其他分支状态合并进该读。`from_snapshot` 验证 v1 引用、预算、对象事实并重建 arena。快照不是调度器 checkpoint；工作队列 frontier、累计执行计数和显式 Source 绑定由调用方另行保存。

最终测试、边界和指标见 [P5-report.md](phases/P5-report.md)。P5 后停止；P6 需要另外进入，不自动推进。
