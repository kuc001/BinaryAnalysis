# P1：旧 Load/Store 到内存契约的映射边界

这是 P1 证据与后续映射，不是 P3 schema 或 P5 内存核心实现。P1 的 `Term` 仅为有限纯 BV 求解消息协议，不能作为 CIR/Memory-Semantics 的既定格式。

当前目标为用户指定的 angr/Claripy 9.3.4，入口 `import claripy`。真实 marker/SolverPort 结果见 [当前 P1 报告](phases/P1-9.3.4-report.md)。以下缺失语义不因求解器恢复可用而自动补全。

| 旧来源/语义 | P1 已实现 | P3/P5 所需映射 | 尚不能证明/禁止事项 |
|---|---|---|---|
| `.venv/.../claripy/ast/bv.py:366-367`；`operations.py:59`，Load/Store 的 int 参数移入 length | 提取 op、地址表达式、地址位宽、结果位宽 | 保留宽度，结合原 Action 提取访存事件 | args 只有地址，不能推定完整内存语义 |
| `accurate_data_flow.py:471` `_get_load_action_ast` | 旧 AST 与新端缺失 API 的差分已归档 | CIR ReadEffect + stable AccessRoot/Offset/Deref + MemoryRead(version,location) | AST 没有 endian/version；需从前端事件和分析上下文补齐 |
| `accurate_data_flow.py:701` `_find_store_use_v1` 将 data 替换成 Store(addr,bits) | `LegacyMemoryMarker` 明列 stored_value/endian/version/guard/origin 缺失 | 从 Action.dst/src、代码位置和状态得到 StoreEffect 与新 MemoryVersion | marker 不是 `Store(M,addr,value)`；不能直接生成 SMT store |
| `SimAction` 的 live、def_locs、action_data | P1 仅描述，不改变 propagation | DefinitionRef/Origin/Context 与 memory state 分离 | def_locs 不等于 MemoryVersion；live 不能替代强/弱更新判定 |
| `VarExpr.replace:872` 隐式调整位宽、更新 sims/actions/base_ptr | adapter 要求替换 sort/width 一致；显式 Extract/Ext | P5 characterization 保留/解释旧行为与证据 | 不能声称已迁移完整 VarExpr/TraceExpr 状态 |
| `get_all_deref_info:654`、`extract_base_and_offset:685` | 遍历契约与 marker 地址描述 | 类型化 Offset/Deref/Index/UnknownOffset、未知地址诊断 | `(None,0)` 不能被解释为 NoAlias |
| `RecursiveExpr:1420` 的 base/offset/position/inc_records | 默认 occurrence 遍历与预算显式 | APG 摘要路径、稳定 ID 与递归上下文；单独 worklist 收敛 | APG 环不是对象自环、MustAlias 或漏洞证明 |
| `parse_ast.py:1486`、Collector 的 concrete memory load | 未改真实内存读取 | 由初始字节/端序构造 AbstractHeap 初态，版本化处理后续写入 | 固件初始内存不等于所有运行时版本 |
| `EngineVEX.judge_constraints_satisfiable:1835` | 新 SolverPort 显式状态和进程隔离，未接入旧算法 | 局部 defs/alias 精化后按需 BV/ITE/byte-array lowering | 旧自定义操作一律不直接求解；UNKNOWN 不等于 UNSAT |

P1 结构 key 仅对无 annotation、无 VSA bounds 的文档化纯 BV 子集提供跨版本归一化。它不是等价性求解、指针对象身份、别名证明或 APG 收敛证明。预算耗尽、未知 operation 和 annotation 不会被静默省略。

当前调用点证据位于 `.p1-work/20261028T081314Z-a53352b3/{legacy,target}-api-callsites.json`；旧 `.p1-work/20261028T062916Z-123a2aa6/` 仍保留。记录分类：

- native_import：直接导入本地 native 库。
- import_resolved_call：按文件级 import alias 解析的调用；仍需检查重绑定/动态分派。
- unresolved_call_candidate / attribute_candidate：如 `.replace/.solver/.args`，不能仅凭名称认定为 Claripy。
- syntax_error_text_candidate：不能按 Python 3 AST 解析的旧 IDA 文件中的文本线索。

旧源码共有 166 个 Python 文件进入清单，4 个旧 IDA exporter 文件解析失败并保留错误位置；不是声明所有外部 IDA API 已做运行测试。此次目标清单扫描 116 个 Python 文件（扫描后又增加验证工具）；P1 未修改已有 lifting、IR/PAG 或分析业务实现。
