你遇到的这两个问题，已经不是简单的 Python 命名规范、代码注释不充分，而是 BinaryAnalysis 当前架构缺少面向人工调试的可观测性（Analysis Observability）、来源可追溯性（Provenance）和算法执行解释能力（Explainability）。

这会直接影响后续 P7 的开发效率、正确性验证，以及 BinaryAnalysis 是否能够成为一个长期可维护的程序分析框架。

尤其是：

```
roots = demand.value(operand)
```

当 `operand` 是：

```
ValueRef(id='f15330:v2877', type=...)
```

而 `roots` 返回：

```
(    SymbolicExprId(..., key="sse-242"),    SymbolicExprId(..., key="sse-243"),    ...)
```

开发人员实际上无法回答几个最基本的问题：

1. `v2877` 是哪条机器指令产生的？
2. 它对应 VEX IR 中哪一条语句、哪个临时变量或哪个寄存器？
3. 如果是内存值，地址来自哪里，Load/Store 对应什么？
4. 为什么 `v2877` 关联到了七个 SSE 表达式？
5. 每个 `sse-242` 代表什么数学表达式和内存语义？
6. 这些表达式是通过哪些 Def-Use、Use-Def、别名或跨函数传播规则生成的？
7. 如何直接跳转到 IDA Pro 中对应的机器指令，并人工复核分析结果？

我的建议是将这次修改定义为 BinaryAnalysis 的一项独立基础能力建设：Analysis Debugging & Provenance Infrastructure（分析调试与来源追踪基础设施）。

它应该覆盖 CIR → VEX/IDA → SSE → APG/MemoryVersion → Alias/Taint → Solver 的完整分析过程，而不仅仅给当前 `evaluate()` 加几个 `print()`。

但也不建议为了解决可读性问题，把现有 `ValueRef`、`SymbolicExprId` 全部改成包含复杂调试信息的对象。正确做法是保持内部 ID 稳定和轻量，同时建立独立的来源索引、表达式解释器和分析事件追踪机制。

下面给出架构设计、接口方案、代码重构建议、IDA 对齐方法、验收测试和 Codex 执行计划。

# 一、先建立统一的内部值追踪机制

## 1. 内部 ID 不应该直接承担人工解释职责

先分析你提供的两个对象。

### ValueRef

```
ValueRef(    id="f15330:v2877",    type=ValueType(        kind=TypeKind.POINTER,        bits=32,        signedness=Signedness.UNSIGNED,        address_space="default",    ),)
```

目前能确定的信息只有：

| 字段             | 含义          |
| -------------- | ----------- |
| `f15330:v2877` | 内部 Value ID |
| `POINTER`      | 指针类型        |
| `32`           | 位宽为 32 bit  |
| `UNSIGNED`     | 无符号         |
| `default`      | 地址空间        |

其中 `f15330` 看起来与函数 RVA `0x15330` 对应。你提供的 `SymbolicExprId` 中 `function.rva=86832`，十六进制正好是 `0x15330`。

但必须注意：`v2877` 是内部值编号，不一定对应 VEX 的 `t2877`，也不一定对应一个确定的机器寄存器。

一个 CIR Value 可能来自寄存器读取、VEX 临时变量、Memory Load、PHI 合并、函数参数甚至多条指令的组合。

不能仅根据 ID 猜测它与某个寄存器的对应关系。

### SymbolicExprId

```
SymbolicExprId(    scope=...,    key="sse-242",)
```

这里的 `sse-242` 同样只是表达式标识符。

它不是表达式本身。

真正有意义的信息应该从对应的 SSE DAG 节点中获取，例如：

```
node = engine.dag.nodes[expr_id]
```

然后提取：

```
node.opnode.operandsnode.typenode.value
```

此外，还需要关联表达式的定义来源、传播过程和路径约束。

## 2. 建立 Value → CIR → VEX → Machine Instruction 映射

我建议实现下面这条完整的双向映射链：

ValueRef

f15330:v2877

CIR Definition / Effect

定义位置、运算类型、输入 ValueRef、结果 ValueRef

VEX IRSB / Statement

IRSB 地址、Stmt Index、WrTmp/Get/Put/Load/Store

机器指令

Instruction RVA、指令字节、反汇编、寄存器

IDA Pro

计算 IDA EA，跳转到对应指令，人工检查

反方向也必须支持：

`Instruction RVA → VEX Statement → CIR Value → SSE Expression → Analysis Results`

原因是人工调试有两种实际场景：

一种是 Python 调试器中看到 `v2877`，希望找到对应的 IDA 指令。

另一种是 IDA 中发现某条 Load 指令可疑，希望知道 BinaryAnalysis 如何处理这条指令、传播了哪些值、产生了哪些别名关系。

只有建立双向映射，才能同时支持这两种需求。

## 3. 在现有 OriginMap 基础上增加可查询索引

你现有 CIRModule 中已经有 `origin_map`，所以不应该再设计一套相互独立的地址系统。

应该先核查现有 `origin_map` 是否已经记录精确到 VEX Statement 的信息。如果没有，需要在 Lowering 阶段补充映射信息。

建议引入独立的来源记录：

```
from dataclasses import dataclass@dataclass(frozen=True, slots=True)class InstructionOrigin:    """Source location of a CIR value or effect."""    producer: str    function_rva: int    block_rva: int | None    instruction_rva: int | None    vex_statement_index: int | None = None    vex_temporary: int | None = None    register_offset: int | None = None    register_name: str | None = None    role: str = "definition"
```

这是一个示意结构，可以映射到现有的 Origin 类型，不要求你新增重复 Schema。

有两个重要设计要求：

第一，同一个 ValueRef 可以关联多个 Origin。

例如合并节点：

```
v100 = PHI(v40, v85)
```

它可能同时来自两条不同控制流路径。

不能强行给它指定唯一的机器指令。

第二，Origin 必须区分来源类型。

例如：

| 来源类型                | 含义         |
| ------------------- | ---------- |
| `INSTRUCTION`       | 真实机器指令     |
| `VEX_STATEMENT`     | VEX IR 语句  |
| `CIR_SYNTHETIC`     | CIR 创建的合成值 |
| `FUNCTION_ARGUMENT` | 函数入口参数     |
| `MEMORY_VERSION`    | 内存版本转换     |
| `SUMMARY`           | 跨函数摘要产生的值  |
| `MERGE`             | 控制流或状态合并   |

当值是合成结果时，应如实展示 `SYNTHETIC` 和其输入来源，而不是虚构一条指令地址。

# 二、如何准确对应 VEX IR 和机器寄存器？

VEX IR 本身已经提供了需要的基础信息。

例如 VEX 中的：

```
IMark(0x401000, ...)
t12 = GET:I32(offset=...)
t13 = Add32(t12, 0x4)
PUT(offset=...) = t13
```

这里的 `IMark` 标记机器指令的开始；后续 Statement 通常归属于该条指令，直到出现下一个 `IMark`。

PyVEX 官方文档明确提供了 `IMark`、`WrTmp`、`Put`、`IRSB.statements`、`IRSB.instruction_addresses` 等接口。

[image](https://www.google.com/s2/favicons?domain=https://api.angr.io\&sz=32)

pyvex documentation+1



## 1. 在 VEX Lowering 阶段收集来源

可以先增加一个工具函数：

```
import pyvexdef iter_vex_statement_origins(irsb):    """Yield the instruction and register origin of each VEX statement.    The caller must map each emitted record to the CIR value or    effect created when that statement is lowered.    """    current_instruction = None    for statement_index, statement in enumerate(irsb.statements or ()):        if isinstance(statement, pyvex.stmt.IMark):            current_instruction = statement.addr + statement.delta            continue        temporary = None        register_offset = None        if isinstance(statement, pyvex.stmt.WrTmp):            temporary = statement.tmp            if isinstance(statement.data, pyvex.expr.Get):                register_offset = statement.data.offset        elif isinstance(statement, pyvex.stmt.Put):            register_offset = statement.offset        yield {            "instruction_address": current_instruction,            "statement_index": statement_index,            "statement_kind": type(statement).__name__,            "vex_temporary": temporary,            "register_offset": register_offset,        }
```

这个函数可以拿到 VEX Statement 与指令的基本对应关系。

其中 `IMark.addr + IMark.delta` 是 PyVEX 使用的指令地址计算方式。

[image](https://www.google.com/s2/favicons?domain=https://docs.angr.io\&sz=32)

pyvex documentation+1



但这里有一个非常重要的细节：

仅仅建立 VEX Statement 索引，仍然无法知道 `v2877` 对应哪个 Statement。

真正的关联必须在 Lowering 创建 ValueRef 时记录：

```
# 示意：在创建 CIR Value 的同时登记其来源。value_ref = create_cir_value(...)provenance_index.record_value_definition(    value_ref=value_ref,    source_statement=statement_origin,)
```

不要在查询时尝试依靠 `v2877` 编号逆向猜测。

对于 VEX `Get` 和 `Put`，还应该通过 angr/archinfo 的寄存器信息转换 offset 到寄存器名称，并保留访问位宽和寄存器别名信息。

需要特别处理 ARM/Thumb、MIPS Delay Slot、寄存器部分读写以及多个 VEX Statement 对应一条机器指令等情况。

# 三、实现可以直接用于 VS Code 的 Debug Inspector

这是我认为对你当前开发效率提升最大的一项功能。

建议增加：

```
emtaint/
└── debugging/
    ├── provenance.py
    ├── provenance_index.py
    ├── value_inspector.py
    ├── symbolic_inspector.py
    ├── trace_events.py
    ├── trace_recorder.py
    ├── formatters.py
    └── ida_export.py
```

上述目录是建议结构，并非声称项目目前已有这些模块。

## 1. 给 ValueRef 提供 explain_value()

目标是让你在 VS Code Debug Console 直接执行：

```
print(self.debug.explain_value(operand))
```

而不是只能看到：

```
ValueRef(id='f15330:v2877', ...)
```

输出应该类似下面这种形式：

Value Inspector

示例输出

f15330:v2877

Function RVA: 0x15330 | Pointer32

| 定义指令   | `<实际 Instruction RVA>`    |
| ------ | ------------------------- |
| 汇编指令   | `<实际反汇编文本>`               |
| VEX 位置 | `<Block + Stmt Index>`    |
| VEX 运算 | `<WrTmp / Load / Get...>` |
| 来源寄存器  | `<若有，显示寄存器名称>`            |
| CIR 定义 | `<CIR Effect / Def ID>`   |
| 上游值    | `<实际 ValueRef 列表>`        |

这里只展示目标结构；具体地址、VEX 语句和寄存器必须由真实的 OriginMap 与 Lowering 结果填充。

对于没有直接寄存器来源的值，显示：

```
Register: N/A (synthetic merge)
Sources:
    v102
    v215
```

不能为了让信息看起来完整而随意关联一个寄存器。

## 2. 给 SymbolicExprId 提供 explain_expr()

你的第二个问题：

```
roots = demand.value(operand)
```

返回七个：

```
sse-242
sse-243
sse-244
sse-245
sse-246
sse-247
sse-248
```

当前最严重的缺陷，是只有 ID，没有表达式的可读内容。

应该支持：

```
for root in roots:    print(self.debug.explain_expr(root, max_depth=5))
```

例如，某个真实表达式如果是加法：

```
sse-242: Add32(sse-105, 0x10)
    ├── sse-105: RegisterValue(r0)
    │       Origin: <对应指令>
    └── Constant(0x10)
```

若表达式是 Memory Read：

```
sse-243: MemoryRead32
    Address: Add32(RegisterValue(sp), 0x20)
    Memory Version: M17
    Possible Object: StackObject(...)
    Origin: <对应 Load 指令>
```

还需要区分：

- 表达式节点本身的运算。
- 表达式来源及其定义链。
- 相关 MemoryVersion。
- 别名候选及其精化结果。
- 路径约束和求解状态。

最重要的是，输出表达式时不要默认展开整个 SSE DAG。

否则调试工具本身也会遇到表达式爆炸。

建议采用：

```
explain_expr(    expression_id,    max_depth=5,    max_nodes=100,    show_origins=True,    show_memory=True,)
```

采用 DAG 共享引用、深度限制和节点数量限制，已经输出过的节点使用引用 ID，而不是重复展开。

## 3. 解释 demand.value() 为什么返回多个 Root

仅仅把 SSE 表达式打印出来，仍不足以回答一个更重要的问题：

为什么这个 operand 最终产生了七个 symbolic roots？

所以应该增加：

```
print(self.debug.explain_demand_value(demand, operand))
```

对于每个 Root，输出：

| 字段             | 说明                   |
| -------------- | -------------------- |
| Root ID        | `sse-242` 等          |
| Expression     | 表达式结构                |
| Created by     | 创建它的分析规则             |
| Derived from   | 输入 Root 或 Value      |
| Origin         | 对应 CIR/VEX/指令位置      |
| Context        | 调用上下文和 AnalysisScope |
| Path condition | 传播时相关路径条件            |
| Completeness   | 分析结果是否完整             |

例如，假设某个 Root 是由跨函数传播产生的：

```
sse-244
    Created by: CALL_ARGUMENT_PROPAGATION
    Source: sse-198
    Callsite: <真实 Callsite RVA>
    Caller: <Caller Function>
    Callee: 0x15330
    Context: exact
```

如果是 Memory Load 精化产生的，则展示具体的 Load、MemoryVersion 和 Alias Query。

这里需要特别强调：你当前七个 Root 的实际形成原因，仅凭返回值无法判断。它们可能来自不同定义、状态合并、上下文传播或其他规则。必须在创建和关联 Root 的位置记录原因，不能事后根据数量推测。

# 四、还必须记录分析算法的执行过程

即使具备了完整的 Value → VEX → IDA 映射，也只能回答：

> 这个值来自哪里？

无法回答：

> 为什么算法将它传播到了这里？

这正是你目前 P7 中需要重点解决的问题。

我建议增加结构化 Analysis Trace。

例如，在分析执行时记录：

```
Event #1025
    Rule: DEMAND_VALUE_LOOKUP
    Operand: f15330:v2877
    Result: [sse-242, ..., sse-248]

Event #1026
    Rule: MEMORY_READ_RESOLUTION
    Expression: sse-243
    Address Expression: sse-107
    Memory Snapshot: M17
    Result: UNKNOWN
    Reason: unresolved address
```

这里的事件只用于说明格式，并不是对你当前真实执行结果的判断。

事件模型可以定义为：

```
@dataclass(frozen=True, slots=True)class AnalysisTraceEvent:    sequence: int    rule: str    function_rva: int    input_ids: tuple[str, ...]    output_ids: tuple[str, ...]    instruction_rva: int | None = None    reason: str | None = None
```

实际实现还应包含完整 `AnalysisScope`、上下文、状态版本、相关 Origin ID 和可选的约束引用。

尤其需要注意 SSE 的 `state_revision`、`cfg_version`、`cg_version`：不同状态版本下，即使表达式具有相同的短 ID，也不能随意认为其语义完全相同。

### 调试追踪必须是只读和可选的

我建议遵循：

```
Production Mode:
    不生成完整事件追踪
    只维护必要的语义来源

Debug Mode:
    按函数、指令或 Value ID 过滤事件
    记录 Rule → Input → Output → Reason
    允许导出 JSONL
```

事件记录不能额外触发 Alias Query、Memory Read、Solver Query，也不能消耗原分析所使用的 QueryBudget。

否则打开 Debug 模式后得到的分析结果可能与正常模式不一致，反而无法用于验证算法正确性。

# 五、重构 evaluate()：让代码能够逐行人工调试

你给出的 `evaluate()` 当前至少有三个方面的问题。

| 问题      | 当前表现                 | 建议         |
| ------- | -------------------- | ---------- |
| 可读性差    | `d`、`n`、`a`、`ref`    | 改为明确的语义变量名 |
| 多种算法混合  | Load、DAG 遍历、符号计算混在一起 | 按职责拆分函数    |
| 失败原因不可见 | 不同原因统一返回 `None`      | 增加可查询的失败原因 |

它当前的基本算法可以理解为：

使用非递归 DFS 对 Symbolic DAG 进行按依赖顺序求值；遇到特殊 Load 时解析地址并尝试查询初始内存；对已知操作数进行常量计算，对无法确定的结果返回 `None`。

这一点必须写进函数 Docstring。

而且重构时应当先保证语义等价，不应该趁机重写整个求值算法。

下面是一个保守的可读性重构示例，保留原有 `None` 表示无法求值的约定，以及原有 `IF`、整数截断和 Load 处理顺序。

```
def evaluate(self, root, index, overrides=None):    """Evaluate a symbolic DAG expression using concrete values.    Algorithm:        1. Traverse the DAG iteratively in post-order.        2. Resolve operand values before evaluating their parents.        3. Resolve registered memory loads against the initial snapshot.        4. Evaluate supported symbolic operations.        5. Truncate non-boolean results to the declared bit width.    A result of None means that concrete evaluation was not possible.    It does not distinguish individual failure reasons.    The traversal is iterative to avoid recursion-depth growth.    """    dag = self.port.engine.dag    evaluated_values = dict(overrides or {})    # (expression_id, operands_ready)    pending = [(root, False)]    while pending:        expression_id, operands_ready = pending.pop()        # Explicit overrides and previously evaluated nodes take priority.        if expression_id in evaluated_values:            continue        node = dag.nodes[expression_id]        # Memory loads require the address expression first.        if expression_id in self.demand.loads:            address_id, width, endian, origin = (                self.demand.loads[expression_id]            )            if not operands_ready:                pending.append((expression_id, True))                pending.append((address_id, False))                continue            address = evaluated_values[address_id]            evaluated_values[expression_id] = self._evaluate_load(                address=address,                width=width,                endian=endian,                origin=origin,            )            continue        # Schedule dependencies before evaluating the parent expression.        if not operands_ready and node.operands:            pending.append((expression_id, True))            pending.extend(                (operand_id, False)
```

这个版本主要改善了可读性，但有几个地方还需要进一步检查，而不能直接认为算法完全正确。

### 1. 当前算法对共享 DAG 和环的处理

原实现用 `pending` 遍历，依赖项可能被重复压栈。

对于正常无环 DAG，通常可以通过 `evaluated_values` 跳过已经求值的节点。但如果数据结构中意外引入环，则可能无限遍历。

建议补充 DAG 无环检查及相应的错误状态，而不是简单依赖 `RecursionError`。

### 2. `None` 无法反映失败原因

例如以下情况都可能返回 `None`：

```
Address unresolved
Memory binding unavailable
Symbolic operand
Unknown IF condition
Unsupported calculation
```

但这些情况的语义完全不同。

你已经在 Solver Lowering 中使用了 `READY / UNKNOWN / INCOMPLETE / TIMEOUT / ERROR` 等状态，我建议借鉴相同的显式状态思想，但不要直接复用不适合当前求值器的状态定义。

例如定义：

```
class EvaluationStatus(str, Enum):    CONCRETE = "concrete"    SYMBOLIC = "symbolic"    UNKNOWN = "unknown"    UNSUPPORTED = "unsupported"    INCOMPLETE = "incomplete"
```

更重要的是保存原因、对应的 Expression ID 和相关 Origin。

尤其要保证 `CONCRETE(0)` 与 `UNKNOWN` 能明确区分。

### 3. Memory Read 必须可以解释

原来的：

```
binding = self.port.engine.address(absolute)
```

会把一个地址表达式转换成 Memory Binding。

人工调试需要看到：

```
Address Expression
    ↓
Concrete Address
    ↓
Object / Region Binding
    ↓
Memory Location
    ↓
Memory Snapshot
    ↓
Read Result
```

还需要知道读取的是哪一个 MemoryVersion，是否涉及部分重叠读写，以及哪个步骤导致求值失败。

在确认这些字段能够从现有 MemoryQueryPort 获取之后，再加入调试输出。

### 4. 重构不能改变原算法的行为

特别要测试：

```
type(absolute) is int
```

与：

```
isinstance(absolute, int)
```

是不等价的，因为 Python 中 `bool` 是 `int` 的子类。

另外，原代码在 `IF` 的条件未知时，允许两个分支结果相同则返回该结果。这一规则也必须保留。

建议先对旧版和新版 `evaluate()` 做逐样本差分测试，再改进语义和错误分类。

# 六、与 IDA Pro 实现精确地址对应

建议在第一阶段优先实现通过 RVA 跳转到 IDA，不必一开始就开发完整的 IDA 插件。

例如 BinaryAnalysis 提供：

```
origin = self.debug.get_primary_origin(operand)print(hex(origin.instruction_rva))
```

然后通过 IDA Python：

```
import ida_naltimport ida_kernwininstruction_rva = 0x15330  # 替换成真实返回的指令 RVAida_ea = ida_nalt.get_imagebase() + instruction_rvaida_kernwin.jumpto(ida_ea)
```

Hex-Rays 官方提供了 `ida_nalt.get_imagebase()` 和 `ida_kernwin.jumpto()` 等接口。

[image](https://www.google.com/s2/favicons?domain=https://python.docs.hex-rays.com\&sz=32)

IDAPython references documentation+1



这里使用的公式：

\\[ \text{IDA EA}=\text{IDA ImageBase}+\text{Instruction RVA} \\]

前提是两个工具对同一二进制模块采用兼容的 RVA 定义。对于 ELF、重定位映射、不同模块及特殊地址模式，应先核验映射关系，不能盲目套用公式。

我建议未来还支持在 IDA 中选中一条指令后，反向查询该地址对应的：

```
CIR Values
SSE Expressions
Memory Versions
Alias Results
Taint States
```

但第一阶段先完成文件级双向索引即可，不需要复杂 GUI。

# 七、建议增加的命令和调试接口

这一部分是建议实现的新接口，并不是当前 BinaryAnalysis 已有的命令。

| 接口                                        | 作用                            |
| ----------------------------------------- | ----------------------------- |
| `explain_value(value_ref)`                | 查看 Value 的定义、使用、指令及寄存器来源      |
| `explain_expr(expr_id)`                   | 查看 SSE 运算 DAG                 |
| `explain_demand_value(demand, value_ref)` | 查看 Value 对应的 Roots 及形成原因      |
| `explain_memory(expr_id)`                 | 查看 Load/Store 与 MemoryVersion |
| `trace_instruction(rva)`                  | 查看某条指令产生的全部分析结果               |
| `trace_rule(rule_id)`                     | 查看算法规则的执行记录                   |
| `export_trace(path)`                      | 导出结构化 JSONL 调试事件              |

人工调试时应支持：

```
print(self.debug.explain_value(operand))print(self.debug.explain_demand_value(demand, operand))print(self.debug.explain_expr(roots[0], max_depth=4))
```

这样无需在 VS Code 的变量查看器中层层展开十几个嵌套 Dataclass。

# 八、如何组织 Codex 的修改计划？

这次我不建议让 Codex 一次性完成整个 Debugging Infrastructure。

因为你现在的 P7 重构尚未稳定，如果同时大面积修改 CIR、SSE、Memory 和 Solver，很容易破坏现有测试基线。

建议分四个连续阶段，每个阶段都能独立验收。

| 阶段 | 开发内容                           | 验收标准                                 |
| -- | ------------------------------ | ------------------------------------ |
| D1 | ValueRef → CIR/VEX/指令的来源索引     | `v2877` 可定位到真实来源或明确解释为何没有指令来源        |
| D2 | SSE DAG Pretty Printer、Root 解释 | 七个 Root 都能查看表达式结构和来源                 |
| D3 | 分析规则事件、求值调试及代码规范重构             | 可以追踪 `demand.value()` 的形成过程，求值回归保持一致 |
| D4 | IDA 双向地址映射、调试数据导出              | Python 值与 IDA 指令可以互相查询               |

阶段 D1 是最高优先级。

如果 D1 不能正确保存来源，D2、D3 只能打印越来越复杂的内部对象，仍然解决不了你最初的问题。

## 可以直接交给 Codex 的任务指令

# BinaryAnalysis — Analysis Debugging & Provenance 改进任务

## 背景

当前 BinaryAnalysis 人工调试存在严重可解释性问题。

`ValueRef`、`SymbolicExprId` 等内部对象只有不透明 ID，无法直接定位机器指令、VEX IR、CIR Definition、机器寄存器或分析传播规则。

例如：

```
roots = demand.value(operand)
```

其中：

```
operand = ValueRef(id="f15330:v2877", ...)
roots = (sse-242, sse-243, ..., sse-248)
```

开发人员无法确认这些值的来源、含义及传播过程。

## 目标

建设 Analysis Debugging & Provenance Infrastructure，使人工可以追踪：

Machine Instruction ↔ VEX Statement ↔ CIR Value ↔ SSE Expression ↔ Analysis Result

同时追踪分析规则、数据依赖、内存操作和跨函数传播。

## 约束

1. 先审查现有 CIRModule.origin_map、ValueRef、SymbolicExprId、DAG、Demand、MemoryQueryPort 和 Frontend Lowering 实现，禁止重复设计已有功能。
2. 不允许改变现有 ValueRef、SymbolicExprId 的语义和身份规则。
3. 优先使用现有 OriginMap；缺少的来源数据必须在创建 Value 或 Effect 时记录，不允许事后通过编号猜测。
4. 支持一个 Value 对应多个来源，以及没有直接机器指令来源的合成值。
5. Debug Inspector 必须是只读的，禁止触发新的别名查询、内存读取或求解。
6. 不能改变 CIR、SSE、污点传播或漏洞检测算法结果。
7. 如需要修改持久化 Schema，先提供兼容性设计和迁移方案；优先考虑独立调试 Sidecar。
8. 不允许修改既有测试预期来掩盖回归问题。
9. 修改代码必须使用语义清楚的变量名、类型标注、函数 Docstring，并对关键算法步骤编写解释性注释。

## 实施阶段

### D1：Provenance

建立 ValueRef → CIR Definition → VEX Statement → Instruction RVA 的双向索引。

需要支持寄存器 offset/name、VEX Temporary、Function RVA、Block RVA、Statement Index。

### D2：Inspectors

实现 explain_value、explain_expr、explain_demand_value。

支持 DAG 深度限制、共享节点、内存语义和来源查询。

### D3：Analysis Trace

在 Demand、SSE 传播、Memory Query 和关键判定处记录结构化规则事件。

重构难读的 evaluate 等函数，但先进行语义等价测试。

### D4：IDA Integration

支持按照 BinaryId + RVA 导出 IDA 地址映射，提供反向索引。

## 验收

必须能够在 VS Code 中对真实二进制分析对象执行：

```
print(self.debug.explain_value(operand))
print(self.debug.explain_demand_value(demand, operand))
print(self.debug.explain_expr(roots[0]))
```

并明确看到：

- 值的真实定义来源
- 关联的 VEX Statement
- 对应的机器指令 RVA
- 寄存器或内存对象
- 符号表达式的实际语义
- Root 产生与传播的规则
- 无法确定时的显式原因

必须对正常模式与 Debug 模式进行结果等价性测试。

按 D1 → D2 → D3 → D4 顺序实施，每阶段完成测试后提交独立 Commit，不得未经验收直接进入后续阶段。

# 九、最终验收重点

对于你提供的真实问题：

```
roots = demand.value(operand)
```

改造完成后，人工至少应能完成以下验证：

人工可调试性验收清单

0/7

从 f15330:v2877 定位到 CIR 定义点

定位到 VEX Statement 和机器指令，或明确说明它是合成值

确定是否涉及真实寄存器、VEX Temporary 或内存对象

输出 sse-242 到 sse-248 的实际表达式

解释每个 Root 是由哪条算法规则创建或关联的

在 IDA 中核对指令及其操作数

在 Debug 模式下复现并解释传播过程，且不改变分析结果

建议把以上内容作为 P7 继续开发之前的一项强制工程验收门槛。

你现在最需要的不是更多内部抽象，也不是单纯增加日志，而是让每个关键分析结果都有三种可追踪的证据：

来源证据（Origin） + 语义证据（Expression / Memory） + 推理过程证据（Derivation Trace）。

这三者建立起来之后，开发人员才真正能结合 VS Code、VEX IR 和 IDA Pro，对 BinaryAnalysis 的每一步程序分析进行人工验证，而不再只能通过最终测试是否通过来推测算法正确性。