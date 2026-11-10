# BinaryAnalysis 全面架构重置：Codex 主指令

## 本轮边界：只审计，不实现

先阅读用户提供的 `TASK_1.md` 和
`TASK_2.md`。它们是本次设计输入。当前任务只允许审计真实仓库、提出架构和形成文档；禁止修改
Python、删除文件、创建代码目录、运行测试、改依赖、提交或推送 Git。

### 项目目标

将 BinaryAnalysis 重新定义为支持多表示输入的 Python-first
二进制程序分析框架： - Binary-level：Machine Instruction、IDA
Disassembly、VEX、IDA Microcode。 - Decompiler-level：结构化 IDA
Hex-Rays CTree。 - HIR/CIR：保留高级语义并形成统一分析契约。 - Shared
Analysis：Dataflow、Def-Use/Use-Def、Alias/APG、Memory、Interprocedural、Taint、Vulnerability。 -
Infrastructure：Acquisition、Artifact、Cache、Analysis
Result、Debug/Provenance、Evidence。

不再把 P1--P7 作为架构或模块划分依据。旧 EmTaint
仅作为只读参考，不修改。

### 必须完成的只读审计

1.  盘点仓库目录、Python
    packages、CLI、依赖、配置、序列化、CI、文档和运行入口。
2.  审查 Frontend、IR/CIR、Program
    Model、CFG/CG/ICFG、Memory、APG、Alias、Dataflow、SSE/Demand、Summary、Solver、Taint、Vulnerability、Storage、Debug。
3.  搜索 P1--P7 命名、阶段专属接口、Schema、CLI 参数、文档和生成产物。
4.  审查 `scripts/` 是否被生产代码、CLI、CI、文档或 IDE
    配置引用；识别必须迁移到正式 Package 的功能。
5.  审查 `tests/`
    中哪些内容是旧架构测试，哪些包含有价值的语义用例、数据集或
    benchmark。
6.  对生产模块给出 KEEP / REFACTOR / REPLACE / REMOVE
    分类，必须引用真实路径和调用关系作为证据。
7.  设计 Acquisition、Artifact、Cache、Analysis Result、Debug/Evidence
    Artifact 的独立生命周期。
8.  评估 CIR 是否适合作为 canonical analysis
    IR；不能预设它必须保留或必须替换。
9.  评估是否需要 HIR，以及 HIR → CIR 的边界。
10. 设计 Hex-Rays CTree、VEX、IDA Microcode 的 Frontend Contract 和多层
    Provenance。

### CTree 要求

-   使用 IDA Hex-Rays 结构化 API（如
    cfunc_t、cinsn_t、cexpr_t、lvar_t、tinfo_t；以实际 IDA 版本 API
    为准）。
-   禁止用伪代码窗口文本解析作为主要语义输入。
-   保留变量身份、类型来源、表达式/语句节点、调用目标、数组/结构体/指针访问、控制结构、EA
    和 extraction completeness。
-   HIR 不得包含活的 Hex-Rays Python 对象，必须可序列化。
-   保留原始伪代码用于展示，但不能将其作为主要分析语义。
-   不支持节点必须保留为 partial/unsupported，不得静默丢弃。
-   HIR/CIR 必须共享统一的 Dataflow/Alias/Taint 引擎。

### 多层 Provenance 与可信度

设计多对多映射：
`CTree Node ↔ HIR Node ↔ CIR Definition/Value ↔ VEX/Microcode ↔ Machine Instruction`

区分：
`BINARY_CONFIRMED`、`DECOMPILER_RECOVERED`、`DECOMPILER_INFERRED`、`USER_ANNOTATED`、`ANALYSIS_DERIVED`、`UNKNOWN`。

类型冲突和来源不完整必须显式保留，不能静默覆盖或猜测。

### Acquisition 必须区分

-   Acquisition：解析输入、调用 Frontend、标准化和构建 Artifact 的过程。
-   Artifact：可版本化、可校验、可重载的持久化产物。
-   Cache：根据 fingerprint 复用有效 Artifact/Result 的机制。
-   Analysis Result：分析算法运行产生的结果。
-   Debug/Evidence Artifact：记录来源、事件和解释证据。

必须设计 manifest、fingerprint、schema version、per-function
artifact、atomic persistence、concurrency、partial recovery、incremental
invalidation。

### tests/scripts 清理

TASK_1 要求清理整个 `tests/` 和
`scripts/`。本轮只分析，不删除。必须先检查生产依赖、CI/CLI/文档引用，并说明迁移方案。不得把旧测试简单改名藏到其他目录。需要向负责人说明：清除历史
tests
不等于大型分析系统可以永久没有自动化验证；新架构稳定后应建立新的验证策略。

### 交付报告

输出： 1. 当前仓库结构与入口。 2. 生产模块职责与依赖图。 3. P1--P7
遗留清单。 4. tests/scripts 删除影响矩阵。 5.
KEEP/REFACTOR/REPLACE/REMOVE 清单。 6. CIR/HIR/CTree/VEX/Microcode
设计。 7. Acquisition/Artifact/Cache/Analysis Result 生命周期。 8.
新架构图和目录结构。 9. Schema/identity/provenance 设计。 10.
迁移里程碑和验收条件。 11. 风险、未知事项和负责人决策列表。

每项结论标记为 SOURCE_CONFIRMED、REQUIREMENT、RECOMMENDATION 或
OPEN_QUESTION。不得虚构仓库事实。

完成审计后停止，等待架构批准，不得自行开始清理或编码。
