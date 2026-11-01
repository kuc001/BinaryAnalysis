# API 兼容矩阵（P1 / v5.0）

2026-10-28：用户已将目标更新为 angr/Claripy 9.3.4，保持 `.venv`，直接 `import claripy`。当前证据和验收见 [P1-9.3.4-report.md](phases/P1-9.3.4-report.md)。旧 10.0.5 原生 CRASH 报告保留为 [历史记录](phases/P1-report.md)，不据此推断 9.3.4 的行为。

当前原始证据为 `.p1-work/20261028T081314Z-a53352b3/`；旧 `.p1-work/20261028T061905Z-221fb340/` 和 `20261028T062916Z-123a2aa6/` 不改标、不覆盖。

| 契约 | 旧环境 | 目标环境 | P1 边界/实测 |
|---|---|---|---|
| Python / angr | 3.7.2 / 9.0.9792 | 3.12.9 / 9.3.4 | 两个绝对解释器分别运行 |
| pyvex/cle/archinfo | 9.0.9792 | 9.3.4 | 用户已更新；代理不改依赖 |
| Z3 DLL | 4.13.3 | 4.13.0 | 直接 z3-python 的 SAT=7 两侧通过；目标包版本 4.13.0.0 |
| import 入口 | `import claripy` | `import claripy` | adapter 固定目标 .venv、9.3.4 元数据与模块路径，不回退全局或旧环境 |
| angr namespace 入口 | 不依赖 | 未作为支持入口测试 | 不创建 shim |
| BVS 的 args | `(name,None,None,None,False,False,None)` | `(name,bits)` | 仅普通无界 BV 归一化；VSA 标记明确拒绝 |
| BVS/BVV/size/op/variables | 通过 | 通过 | 32-bit 同名构造、变量集合与位宽通过 |
| Extract/Concat/ZeroExt/SignExt/ITE/溢出 | 通过 | 通过 | 6 个纯值 fixture 逐项相同，不涉及 SMT |
| AST replace | `root.replace` | `claripy.replace(root,old,new)` | 显式检查替换 sort/width；宽度不一致拒绝，不暗中改符号宽度 |
| children / leaves | 旧 recursive 属性存在 | 旧属性不存在 | `ast_tools` 提供前序 occurrence 遍历及显式 unique 模式；leaf 保留旧 LIFO 去重次序 |
| cache_key / 裸 hash | 存在 / 版本相关 | 不存在 / 版本相关 | 文档化纯 BV 子集使用结构 SHA256；不跨版本比裸 hash |
| 共享 Concat(x,x) | 2 occurrences / 1 unique | 同左 | export、key、leaf、replace 两侧完全相同 |
| annotations | tuple | tuple | SimplificationAvoidanceAnnotation 附加成功；portable export 拒绝非空 annotation，完整策略待 P5 |
| 自定义 Load/Store | AST 可构造，求解报 FrontendError | API 不存在 | 只提取 marker 描述；任何未 lower 的内存操作在启动 worker 前拒绝 |
| claripy.operations | 存在 | 存在 | 不整体搬运内部 operation registry |
| Claripy SAT / UNSAT | 成功 | 成功 | 两侧原生 SAT/EVAL/MIN/MAX=7、冲突约束 UNSAT；目标 SolverPort 另测枚举与范围 |
| eval 返回类型 | 实测 tuple | 实测 tuple | SolverPort 成功时规范化为 tuple[int] |
| Claripy 超时 | timeout=1ms，底层 unknown/timeout，上层 False | 底层 unknown/timeout，上层 ClaripySolverInterruptError | 目标 SolverPort 返回 TIMEOUT；旧布尔 False 不能当 UNSAT |
| 可靠状态入口 | 旧 check_satisfiability 也可能将 False 转 UNSAT | 9.3.4 backend_z3.z3_solver_sat 对 UNKNOWN 抛异常 | 只对固定、实测目标启用 bool False→UNSAT；注入模块默认 False→UNKNOWN |
| 非超时 UNKNOWN | 注入真实 backend 后 False | 注入真实 backend 抛 ClaripyZ3Error | 另穿过真实 Adapter 验证 UNKNOWN / TIMEOUT / resource-limit UNKNOWN；标明 fault injection |
| 异常/崩溃/父进程截止 | 原异常保留 | 原生崩溃由独立进程隔离 | 明确 ERROR/CRASH/TIMEOUT；禁止 SolverResult 转 bool |

调用点清单包含 import-resolved calls 与未解析候选，二者不能混称已验证 API：本轮旧源码扫描 166 文件、4 个 IDA Python 2/缩进语法文件单列并做文本候选检索；目标扫描 116 文件（含当时新增采集脚本，最终文件数可增加）。API 使用矩阵与内存映射见 [P1_MEMORY_MAPPING.md](P1_MEMORY_MAPPING.md)。

P0 的三个 IDA block / 六 IRSB lifting smoke 仍仅为历史前端证据，本轮未重跑。APG、AbstractHeap、MemoryVersion、内存 SolverLowering、完整 SSE 状态和端到端分析均未实现/未执行；当前没有 Rust 开发。
