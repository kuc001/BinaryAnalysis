# P2：Program / CFG / CG / Session 与对象身份

2026-10-28，**P2 Gate：PASS（纯 Python 模型、会话隔离和兼容门面范围）**。已按 `CODE_TASK.md` 的 P2 执行；本轮停止于 P2，未进入 P3、未开发 Rust、未安装依赖、未运行固件 `-i/-t`。

## 交付与模型边界

新增 `emtaint/core/{identity,program,session}.py` 和 `emtaint/graph/program_graphs.py`：Program、Function、BasicBlock、CallSite、Architecture/ABI、AnalysisSession、ProgramPoint、ContextId、BinaryId、MemoryObjectId。新 core/graph 不导入 angr、Claripy、pyvex、IDA 或 NetworkX，可在 `python -B -S` 下工作。详细作用域和调用约定见 [P2_MODEL_CONTRACT.md](../P2_MODEL_CONTRACT.md)。

稳定 ID 使用镜像 SHA256、函数/块 RVA、块变体和指令模式、语句/调用位置、上下文及对象来源；不使用可覆盖寄存器名或跨进程 Python hash。地址 0 合法；不同二进制的同地址、同地址不同块变体、None 与 statement 0、不同栈帧/上下文均区分。重定位保留镜像身份，地址转换验证架构位宽。

六类对象身份覆盖 stack/global/heap/argument/return/unknown；包含 frame、allocation site、context、region、接口索引或未知原因等来源。Heap 默认是分配点摘要；不同 ID 不证明 NoAlias。对象描述注册表尚不是 AbstractHeap，context 标签也不是已证明的递归摘要。

Program 和图快照不可变，Session 独占可变状态。CFG 支持同端点不同边类别、循环、入口/出口与不完整状态；CG 区分 confirmed/may/unknown，保留未解析目标。Session 校验无悬空引用、每个声明 callsite 有目标或 unknown；不能删除孤立函数/块来假装图完整。

CFG 每函数版本、CG 版本和含 session UUID 的 RevisionStamp 共同管理状态。图变化、确定性变化或对象集合变化使本会话缓存/摘要失效；重复相同更新不变版本。P2 采用整会话失效。缓存/摘要仅接受不可变 scalar/tuple 元数据，不接受原生 AST。预算耗尽显式抛异常、记录诊断并标记 Incomplete。

Program 当前是单镜像加载映射；跨模块/同镜像同时多实例、真实前端调用枚举、MemoryVersion、表达式仓库、真实过程摘要和数据流 Worklist 未实现。会话是单 owner API，没有并发写保证。上述边界没有被包装成已完成的 P3/P5 内存语义。

## 源码问题、兼容与修正证据

本轮入口源码快照保存在证据目录 `before-source/`，下表行号指该快照。

| 入口源码问题 | 修正与验证 |
|---|---|
| `program_builder.py:9,22-29` 类级 `_em_program` 被连续 build 复用；get_function 为空 | 实现移到 `compat/program.py`，原导入路径 re-export；build/getter 返回新实例，保留 functions、lookup、IR builder 方法；两个 fake builder 连续构建无污染 |
| `assembly/function.py:28-30` name/syscall/is_simprocedure 的尾逗号制造 tuple，且忽略传入 flag | 修正标量和 flag；None 保留为未知；脱离未实现的 angr Serializable 基类，protobuf 方法仍明确 NotImplementedError |
| `assembly/function.py:56` `if block.addr` 遗漏地址 0 | 使用显式 None 判断，地址 0 存取 fixture 通过 |
| `analysis/pag/ir_graph_builder.py:32` 只处理 `0x400963` | 默认处理全部给定函数；显式 function_addrs 可筛选，未知筛选地址报错；真实 build 循环由两个非调试地址 fixture 验证 |
| `analysis/pag/ir_graph.py:82` 固定 `0x4009c3`；builder `:132` 固定 `0x16fd8` | 从实际注册 entry 集合或显式参数取入口；空图、多个入口、断开环与未知入口测试通过；这是诊断遍历入口修正，不声称实现新数据流 |
| `analysis/pag/var_node.py:13-19` 类级 `_next_id` 跨图累计 | 改为 IRGraph 实例分配；28 个 visitor 构造点转到 graph.new_node；跨图/重复 map ID 拒绝，独立图分配互不影响 |

PAGVisitor 的算法分派保持原样：将入口快照的 28 个 VarNode 构造调用和对应 import 规范化后，AST 与当前源码完全一致。该证据证明没有同时改写 visitor 的分派逻辑，不替代 VEX/污点语义差分。旧 PAG 的原生 exec_stmt helper 原样迁到 `compat/legacy_pag.py` 延迟导入，未作为本轮已验证分析引擎。

`EmProgram.to_session(...)` 提供实际可运行的元数据复制边界，显式接收 BinaryId、Architecture、ABI、image_base。快照不保留原生 graph/IR 引用，并标记 Callsite/CFG/CG/IR 覆盖未导入。旧 Function/Block 门面和新模型的名字、返回标记、地址/块大小比较通过；门面后续修改不影响新快照。`main.py` 保留 build 返回实例，不再从全局 getter 取回旧程序。

本轮代码变更：新 core/graph 包、`compat/program.py`、`compat/legacy_pag.py`；修改 `program_builder.py`、`assembly/function.py`、`main.py`、旧 PAG 的 ir_graph/ir_graph_builder/visitor/var_node；新增两份模型/门面测试及 `scripts/p2_validate.py`；`.gitignore` 增加 `.p2-work/`。三份用户 v5 规划文档未修改，既有 P1 求解器实现未修改。

## 测试、环境和完整性

新证据目录：`BinaryAnalysis/.p2-work/20261028T083140Z-bcf22249/`。最终判定为 `final-review/validation-final.json`；原始测试、完整性清单、失败检查和模型 smoke 均保留。

| 命令（从 BinaryAnalysis，明确使用目标解释器） | 结果 |
|---|---|
| `.venv/Scripts/python.exe -B -S -m unittest discover -s tests -p 'test_program*.py' -v` | 34/34，退出 0 |
| `.venv/Scripts/python.exe -B -m unittest discover -s tests -v` | 99/99，退出 0；含既有 65 项回归 |
| `.venv/Scripts/python.exe -B scripts/p2_validate.py .p2-work/20261028T083140Z-bcf22249` | 测试/完整性/visitor 差分均通过；首次整体退出 1，原因仅为 main.py 一行新增尾随空白 |
| `git --no-optional-locks diff --check -- . ':!.venv'` 修正后复核 | 退出 0；原始失败记录未覆盖 |

先加入模型/门面测试，确认未实现模块和旧 angr 导入导致预期失败，再实施修正。34 项覆盖身份跨进程稳定、地址/架构/ABI 校验、同地址块、并行边与递归调用、Unknown 保留、图与 summary/cache 失效、预算失败原子性、原生对象拒绝、门面状态隔离、元数据差分及诊断入口。另通过 import blocker 明确拒绝 native 库，并在无 site-packages 环境中导入核心与旧公开入口。

最终只修正空白，15 个被测实现文件的 AST SHA 与测试通过时一致，因此仅重跑失败的 diff check，没有无依据重复测试。最终 PASS 合并已有 34/99 项成功测试、完整性、visitor 差分与修正后退出 0 的检查；`validation-20261028T085328Z-47298bac/validation-p2.json` 的原始 FAIL 状态保留。

实际目标运行 Python 3.12.9，包元数据 angr/Claripy/pyvex/cle/archinfo 9.3.4、z3-solver 4.13.0.0；遵循 [TARGET_RUNTIME.md](../TARGET_RUNTIME.md) 的用户版本决策。旧 Python 3.7.2 / angr 9.0.9792 沿用 P0/P1 证据，本轮未导入旧 native 环境。

前后完整清单的 SHA256、size、mtime_ns 一致：旧 EmTaint **13461** 文件（包括旧 .venv/.git/data）、目标 .venv **13044** 文件、全部 baselines **351** 文件、封存 P1 证据 **214** 文件。旧 Git status 保留原有三项 dirty/untracked；旧 base `72a9e3081632b2f9d1881141bc7b0d43c7158033`，目标 base `6cb026767db005e48b36b994ee8542962b6df627`。未 reset、clean、提交或 push。

AGENTS / BLUEPRINT / CODE_TASK 的 SHA 分别仍为 `a5e65f08291b0188fe114956929be15d9634cde28e84ba2e5a98968610c643ce`、`e43e442f54a67b219d8049c4ede8683d1448d1e25495aced2856dd7040fe2212`、`838949316fcc92ba733a6fb241b7e1d97056328101a87d63b8bad8c853a7ac27`。

## 指标与未执行项

合成模型 smoke：2 functions、3 blocks、2 CG edges（may + unknown）、1 unresolved callsite、2 contexts、6 个对象身份描述；添加后再移除 CFG 边，缓存和摘要均失效。该 fixture 最终 status=unknown，SMT 调用 0，约 0.0021 秒，仅证明模型操作，不是固件性能。

APG nodes/edges、AbstractHeap objects/cells、MemoryVersion、SSE DAG nodes、传播 facts、Worklist iterations、RSS 均为 null / 未实现或未采集。真实内存读写/别名/端序/部分覆盖/Source→Sink 差分、目标前端 lifting、Golden 语义重跑和 E2E 性能均未执行；Golden 仅验证字节与 mtime 不变。P5 Gate M、P7 Gate A 没有由 P2 代替，也没有加速结论。

## 回退与下一阶段

旧公开 EmProgram/Function 与旧 VexIR/PAG 路径仍保留，新 Session 尚未替代真实固件业务链。兼容入口变化是有意的：get_em_program 不再提供全局“上一次程序”，functions getter 的副本修改不写回，PAG 节点整数是图内句柄；需要状态的调用方必须持有实例或显式使用 setter。单纯撤回 P2 目标变更可恢复旧目标原型，不涉及旧 EmTaint 或 Golden。

下一阶段建议 **P3**：沿用本阶段身份，定义 typed CIR Load/Store/Call/UnknownEffect 与 Origin，固定 AccessRoot/Segments、APG/Heap/MemoryVersion/SSE refs、MemoryQueryPort/SolverLowering 的接口和版本化 schema；建立 M-01…M-12 契约 fixtures，未实现功能明确报错。P5 再实现真实内存行为与 Gate M。本轮未执行上述工作。
