# P2 模型作用域与兼容入口

这是 P2 的 Python 程序元数据与会话模型，尚未固定 P3 的 CIR / Memory-Semantics wire schema。运行环境继续沿用用户确认的 `.venv` / angr、Claripy 9.3.4；新 `core/` 和 `graph/` 只依赖标准库，在 `python -B -S` 下可测试。

## 身份与地址

| 类型 | 身份依据与作用域 |
|---|---|
| BinaryId | 完整镜像字节的 SHA256，不使用路径、文件名或 Python hash |
| FunctionId | BinaryId + RVA |
| BlockId | FunctionId + RVA + variant index + instruction mode，允许同地址的不同块表示 |
| ProgramPoint | BlockId + statement index / instruction RVA；None 与 0 区分 |
| CallSiteId | ProgramPoint + ordinal，允许同一位置多个调用记录 |
| ContextId | 显式不可变 call string + abstraction 标签，不自动裁剪或合并 |
| MemoryObjectId | kind + binary/function/context/site + 类型限定坐标，不依赖当前寄存器内容 |

ID 中的地址均为相对 Program.image_base 的 RVA。绝对地址由 `absolute_address/relative_address` 转换并检查架构位宽；重定位不改变同一镜像的身份。`token` 是确定性的结构 SHA256，可跨进程/哈希种子比较；Python 的 `hash()` 不充当持久 ID。

一个 Program 描述一个镜像和一次加载映射。相同镜像的多个同时加载实例、跨模块程序、链接器外部符号身份和 Thumb 地址规范化尚无前端实现；不得将它冒充完整多模块模型。真实前端须在 P4 明确镜像映射和调用覆盖。

Architecture 显式保存地址/指针/字节位宽、端序和寄存器描述；ABI 的参数/返回/保存寄存器、SP、栈对齐引用已声明寄存器。不会根据 `r0`、`a0` 等名称猜测架构或参数。Function 的 returning/syscall/simprocedure 可以为 None，保留未知状态。

## 内存对象身份

- stack：function + context + 调用方提供的 frame_id + slot offset，负栈偏移保持原值。
- global：binary + region + RVA，与调用上下文无关。
- heap：allocation ProgramPoint + context + instance 标识；默认是分配点摘要，不是具体运行时分配对象。
- argument / return：function + context + interface index，与承载它的寄存器分开。
- unknown：binary + region + reason + origin_key + 可选 context，必须保留未知来源。

`MemoryObject` 仅增加 provenance、可选 size 和 address_space；Session 的对象表是身份描述注册表，不是 AbstractHeap。不同 ID、不同 frame 或不同 context **不证明 NoAlias**；unknown 可以与其他区域产生尚未判定的影响。P2 不实现 AccessPath、读写、points-to、强弱更新或生命周期判断。

## 图与会话

Program、Function、BasicBlock、CallSite、所有 ID 和 CFG/CG 快照不可变。索引只读；新 Program 必须进入新 Session，不能就地改块集合绕过版本控制。CFG 不接受跨函数或悬空边，保留同端点的不同边种类；CG 区分 confirmed、may 和 unknown。Session 的 CG 必须覆盖每个已声明 callsite，未解析调用用带原因的 unknown edge 表示。

`AnalysisSession.replace_cfg/replace_cg` 是更新入口。CFG 每函数计版本，CG 单独计版本；图变化、目标确定性变化和对象集合变化会推进含 session UUID 的 RevisionStamp，并保守清空本会话缓存和摘要。相同快照重复提交不推进版本。P2 使用整会话失效，P6 再考虑有证据的依赖细化。

缓存/摘要目前仅接受不可变的 scalar/tuple 元数据和 ID token；不接受 list/dict、原生 AST 或任意前端对象。预算覆盖图节点/边、context 深度/数量、对象描述、缓存和摘要条数；超限抛 `BudgetExceeded`、记录诊断并标记 Incomplete，不吞掉事实或当作无目标。内存写版本、表达式仓库、分析 Worklist 和实际过程摘要仍待 P3/P5/P6，RevisionStamp 不冒充 MemoryVersion。

Session 是单 owner 的可变对象，未提供并发写入保证；其 Program 和图快照可只读共享。没有模块级“当前程序”或分析计数器。

## 保留旧入口

`from emtaint.program_builder import EmProgram` 仍可用，具体门面位于 `compat/program.py`。`build(binary)` 每次建立新门面；`get_em_program()` 现在是新实例工厂，调用方应保留返回对象。现有 main 已使用 build 返回值，不再依赖全局 getter 取回先前分析。functions 读取返回列表副本，修改使用 add_function 或 setter；重复地址拒绝。

`to_session(binary_id, architecture, abi, image_base=...)` 显式复制已有 Function/Block 元数据，不保留前端 graph/IR 引用。它将 Program 标为 Incomplete，并说明尚未导入 Callsite、CFG/CG 和 IR 覆盖，不以空边集暗示无调用。完整前端导入留到 P4。

旧 Function 修正标量 tuple 问题和地址 0 的块遗漏；未实现的 protobuf 接口继续明确抛 NotImplementedError，导入元数据不再触发 angr。

旧 PAG builder 默认遍历所有给定函数，可用 function_addrs 显式筛选；诊断遍历从所有已注册 block entry 开始，或由 entry_block_addrs 指定。不存在的显式入口报错，空图合法。这不是新的可达性或数据流算法。VarNode 分配改由图实例负责；其 ID 是图内句柄，独立构造的旧节点使用临时整数 UUID，均不充当稳定的 core ID。PAGVisitor 的 28 个构造点仅改分配入口，原分派 AST 有差分证据。

旧 PAG 的原生表达式 helper 移入 `compat/legacy_pag.py`，仅显式调用才导入 native 库。其表达式执行、其他旧 VEX/IR/PAG 分支仍未迁移，不能因这些门面修正而宣称完整分析已通过。

P3 应复用这些基础身份，定义 typed CIR effects、AccessRoot/AccessSegment/APG、Heap/MemoryVersion、SSE/Lowering 的契约和 schema；本轮没有创建这些实现或宣称 Gate M。
