# AGENTS.md — BinaryAnalysis P7 工程规则（Python-only）

版本 v8.0。当前只完成 P7 污点分析与漏洞检测，不开展 Rust、Microcode 或 P8 以后工作。

## 1. 当前状态
- P6 的 iCall/CG 已通过当前验收，作为冻结基线。
- 当前阻塞是 P7 后半段：污点传播、跨函数传播、漏洞判定、约束和证据。
- 已有 378 项回归通过状态必须保留；不得删除用例、降低断言或修改 Golden 制造通过。
- 目标是恢复旧 EmTaint `-t` 的语义，而不是只让告警数量相等。

## 2. 仓库与环境权限
- 只允许修改当前 `BinaryAnalysis/`。
- `../EmTaint/` 全部只读，包括源码、`.venv`、`data/`、固件、Git 元数据和未跟踪文件。
- 旧版 `-t` 只能在经批准的独立物理副本运行；不得在原始旧仓库直接运行。
- 不得自动安装/升级依赖、修改虚拟环境或切换 Python/angr/Claripy 版本。
- 不得覆盖 P6 冻结结果、旧版 Golden、P7 历史结果或日志。
- 新版分析使用 BinaryAnalysis 自己的解释器和独立输出目录。

## 3. P6 冻结规则
默认不得修改已通过的 iCall callsite→target、CG 边、函数可达性、图更新逻辑和寄存器 clobber/version 修复。
若 P7 证据证明 P6 是差异根因，必须提供最小复现、首次分歧事实、影响范围和独立回归，再单独修复并重跑受影响 P6 测试。不得隐式重写 P6。

## 4. P7 必须恢复的语义
分别核对 Source、TaintKind、寄存器/临时变量/算术/cast、栈/堆/全局内存、Load/Store、参数/返回值/调用副作用、ProcedureSummary、Sanitizer、Validator、Guard、LengthCheck、Sink、路径约束、漏洞证据和 JSON 输出。
每个 Finding 必须可追溯到 Source、传播事实、Sink、调用链、MemoryVersion、Guard/约束和原始地址。

## 5. 内存与精度约束
- CIR Load/Store 是程序内存 effect，不是可直接交给 SMT 的自定义 Claripy AST。
- AccessPath/APG 表示可能访问路径；APG 环不证明 Heap Alias。
- AbstractHeap/PointsTo 表示对象及指向关系；MemoryVersion 表示读写顺序、到达定义和 Join/Phi。
- SSE DAG 表示共享符号值，不无界展开嵌套 Load。
- 只有 MustAlias、唯一目标且完整覆盖才允许 Strong Update；MayAlias/Unknown 使用 Weak Update 或保守建模。
- Solver UNKNOWN/TIMEOUT/UNSUPPORTED、预算耗尽、MayTaint、Incomplete 不得当作 UNSAT、安全或无漏洞。
- MayAlias/MayTaint 只能形成候选，不能直接升级为 Confirmed Finding。

## 6. P7 迭代纪律
每轮只处理一个明确差异：
1. 选择 Difference ID；
2. 找到旧/新首次分歧的最早事实；
3. 保存该位置的输入状态快照；
4. 建立最小回归；
5. 修复一个根因；
6. 运行最小专项测试；
7. 运行受影响的 P6/P7 回归；
8. 更新差异矩阵。
连续两轮没有新诊断信息时，必须改变诊断方法（状态快照、阶段计数、依赖追踪、调用栈 profiling 或缩小 replay），不得盲目重复全量回放。
不得单纯提高预算掩盖算法问题；预算调整必须有成本画像、全局上限和未完成状态记录。

## 7. 工程质量
遵循 PEP 8；公共接口、核心类和复杂算法有准确类型标注及 docstring。注释解释算法不变量和边界条件。禁止裸 except、静默丢弃关键事实、exit(0)、伪造空结果、硬编码目标地址或手工补 JSON。状态归属 AnalysisSession；缓存声明依赖版本。P7 功能修复与无关格式化分开。

## 8. P7 报告
更新 `docs/migration/phases/P7-report.md`：P6 冻结 commit、iCall/CG 和 378 项基线、输入/Golden 身份、旧版 `-t` 规则映射、Source/Fact/Propagation/Summary/Sanitizer/Sink/Finding 差异、首次分歧、修复与回归、APG/Heap/SSE/Worklist/Alias/Solver 指标、Unknown/Unsupported/Incomplete/Timeout、测试命令/退出码、剩余风险和回退方式。未执行测试写“未执行”。
