# BinaryAnalysis — R1-C: Modern Program Analysis Algorithms & Core Architecture Extensibility Review

## 1. 项目背景

BinaryAnalysis 正在进行 Clean Architecture Reset。

已经完成：

- R1-A：旧版 EmTaint 核心算法静态研究。
- R1-B：Analysis Core Contract Consolidation。

R1-B 已产出：

- ANALYSIS_CORE_CONTRACT.md
- 更新后的 ARCHITECTURE.md
- 更新后的 BACKLOG.md
- 更新后的 EXECUTION_PLAN.md
- 更新后的 CORE_ALLOWLIST.md
- 更新后的 ALGORITHM_MIGRATION_MAP.md

R1-B 目前仍是设计提案，尚不等于所有数据契约已经正式冻结。

项目负责人进一步要求：

BinaryAnalysis 的新架构不仅需要借鉴旧 EmTaint 的二进制数据流算法，还必须参考近几年源代码程序分析领域的先进算法。

重点是判断这些算法的研究价值、实现前提，以及当前 CIR、Memory、Alias、SSE、Program Graph、Analysis Result 和 Provenance 架构是否适合后续扩展。

本任务不直接实现论文算法。

## 2. 本次任务的真正目标

本轮需要完成三项核心交付：

### A. Modern Algorithm Transfer Review

研究近几年值得借鉴的源代码程序分析算法，明确其核心机制、语义前提和迁移边界。

### B. Architecture Extensibility Review

对照现有 R1-B 契约，判断是否可以支持未来接入：

- Lazy Sparse Value-Flow Analysis。
- Demand-Driven Pointer/Alias Analysis。
- Bidirectional Analysis。
- CFL/IDE Path Transformers。
- Equivalent-Flow Merge and Replay。
- Selective Context Sensitivity。
- Incremental Value-Flow and Mod-Ref Analysis。
- Shared Pointer/Taint/ICall Semantic Facts。

### C. C1 Implementation Readiness

明确 C1-STORE-LOAD-ALIAS-SSE 在开始编码之前，哪些契约必须冻结，哪些仅需保留扩展余地，以及哪些先进优化应推迟到后续任务。

不得为了支持未来所有算法而一次性创建庞大的框架。

不得用空接口和设计文档代替真实程序分析能力。

## 3. 首先核对 R1-B 的真实结果

阅读：

- AGENTS.md
- CODEX_WORKFLOW.md
- ENGINEERING_STANDARDS.md
- ARCHITECTURE.md
- ACQUISITION_DESIGN.md
- DECISIONS.md
- ANALYSIS_CORE_CONTRACT.md
- ALGORITHM_MIGRATION_MAP.md
- CORE_ALLOWLIST.md
- BACKLOG.md
- EXECUTION_PLAN.md
- BUILD_LOG.md
- LEGACY_DATAFLOW_ALGORITHM_AUDIT.md

检查本地 Git HEAD、分支、未提交修改。

重点检查 R1-B 的实际契约，而不是按照之前的 R1-B 指令假设契约已经完成。

如果某个文件不存在或某项设计未完成，必须报告。

本轮不得修改 Python 生产代码、Git 历史或 references 中的旧 EmTaint 代码。

## 4. 第一组：必须深入研究的五篇论文

每篇论文必须优先使用正式论文、会议/出版社页面或作者公开全文。

不能只根据摘要、二手综述或论文标题推断完整算法。

论文原文已放到本地代码项目：architecture-reset\references\papers\内，可直接阅读

### Paper 1 — Hermes

Hermes: Making Path-Sensitive Pointer Analysis Scalable for Sparse Value-Flow Analysis

OOPSLA 2026

architecture-reset\references\papers\Hermes-OOPSLA-2026.pdf

重点研究：

1. Lazy Symbolic Expression Graph 的结构。
2. 不完整 SVFG 如何保存潜在依赖。
3. Memory Side Effect 的符号化方法。
4. 哪些查询触发图扩展。
5. 如何避免 Summary Explosion。
6. Lazy Graph 如何保证查询结果不因缺失边而失真。
7. 路径敏感分析和跨函数摘要如何交互。

必须回答：

- Hermes LSEG 与 BinaryAnalysis 的 SSE DAG 是不是同一类结构？
- 是否需要独立的 Sparse Value-Flow Graph？
- 哪些现有 Memory/Definition Facts 可以作为 Lazy Expansion 的输入？
- 未展开的边如何表示为 Pending/Unknown？
- 是否可以只在查询需要时构造 Memory-Def-Use Edge？

不得把“未构造依赖边”解释为“已证明没有依赖”。

### Paper 2 — LISPA

Efficient Pointer Analysis via Def-Use Graph Pruning

CASCON 2025

architecture-reset\references\papers\LISPA-CASCON-2025.pdf

研究：

1. Def-Use Pruning 的前提。
2. SSA 中间变量的分类。
3. 哪些节点能够安全绕过。
4. 剪枝如何保留指针语义。
5. 跨函数传播如何处理。
6. 剪枝后如何恢复必要证据。

分析适用于 VEX/CIR 的可能性。

重点考虑：

- WrTmp。
- Register Read/Write。
- Pointer Arithmetic。
- Load/Store。
- Width Conversion。
- Conditional Expression。
- Guard。
- UnknownEffect。

必须给出至少三个不能安全剪枝的反例。

不能通过忽略中间值来丢失地址计算、内存效果、类型宽度或 Provenance。

### Paper 3 — IDEDroid

Boosting the Performance of Alias-Aware IFDS Analysis with CFL-Based Environment Transformers

OOPSLA 2024

architecture-reset\references\papers\IDEDroid-OOPSLA-2024.pdf

研究：

1. IFDS Data Facts。
2. Access Path Explosion。
3. CFL Reachability。
4. IDE Environment Transformers。
5. Transfer Composition。
6. 字段敏感传播的压缩方法。

重点回答：

- BinaryAnalysis 的 APG 是否已有类似的关系表示？
- CFL Transformer 是 AccessPath 的替代，还是一种分析求解策略？
- 能否在不改变 Memory Object 语义的情况下引入？
- 如何处理 C/C++ 指针算术？
- 如何处理部分重叠和未知字节偏移？
- 如何保留 MemoryVersion 和 Guard？

不得将 Java 的字段路径直接等同于二进制 Load(base + offset)。

### Paper 4 — Merge-Replay

Merge-Replay: Efficient IFDS-Based Taint Analysis by Consolidating Equivalent Value Flows

ASE 2023

architecture-reset\references\papers\Merge-Replay-ASE-2023.pdf

研究：

1. Flow Fact Identity。
2. Activation Statement。
3. Backward Alias Propagation。
4. Forward Taint Propagation。
5. Equivalent Flow Merge。
6. Symbolic Activation。
7. Replay。
8. 合并正确性和恢复条件。

重点回答：

- 当前 SymbolicExprDAG 的 Hash Consing 是否足以实现等价值流合并？
- 什么是 Expression Equality？
- 什么是 Analysis Fact Equivalence？
- 不同 MemoryVersion 的事实能否合并？
- 不同 Guard、Call Context 或 Source Evidence 的事实能否合并？
- Replay 需要保留什么身份和状态？
- 哪些合并会导致误删数据依赖？

不得仅通过 AST Hash 相同就认定两个分析事实等价。

### Paper 5 — SILVA

SILVA: A Scalable Incremental Layered Sparse Value-Flow Analysis

TOSEM 2025

architecture-reset\references\papers\SILVA-TOSEM-2025.pdf

研究：

1. Incremental Pointer Analysis。
2. Incremental Mod-Ref Analysis。
3. Memory SSA。
4. Sparse Value-Flow Construction。
5. Dependency Tracking。
6. Incremental Invalidation。
7. 受影响子图的局部重计算。

必须结合 BinaryAnalysis 的场景：

- AliasQuery 发现新关系。
- 间接调用发现新 Target。
- Call Graph Revision 发生变化。
- Callee Summary 更新。
- Taint Policy 更新。
- CIR Artifact 改变。
- Provenance Mapping 改变。

明确哪些变化需要重新运行 Acquisition，哪些只需要重新运行 Analysis。

不允许把 Analysis Cache 和 Acquisition Cache 合并为一套语义。

## 5. 第二组：补充研究

以下论文只要求完成算法定位和接口需求分析：

- Cut-Shortcut — PLDI 2023
  architecture-reset\references\papers\Cut-Shortcut-PLDI-2023.pdf

- Cut-Shortcut — TPLS 2026
  architecture-reset\references\papers\Cut-Shortcut-TPLS-2026.pdf

- Moon — OOPSLA 2025
  architecture-reset\references\papers\Moon-OOPSLA-2025.pdf

- PacDroid — ICSE 2025
  architecture-reset\references\papers\PacDroid-ICSE-2025.pdf

- TaintCC — ISSTA 2026
  architecture-reset\references\papers\TaintCC-ISSTA-2026.pdf

重点考虑：

- 选择性上下文敏感度。
- 不依赖全量上下文克隆的精度提升。
- Pointer/Alias/Taint/ICall 共享语义。
- 通过语义保持的程序变换验证分析器。

如果论文完整机制无法核实，必须明确标记 NOT_VERIFIED，不得编造算法步骤。

其他论文如 APA、Valve 和跨语言分析，可以列为 FUTURE_RESEARCH，但不能扩大本轮必读范围。

## 6. 为每篇论文建立算法迁移记录

每篇论文必须记录：

1. Paper Title / Year / Venue / DOI。
2. 原始论文或作者公开版本 URL。
3. Source Language 和使用的 IR。
4. Target Analysis Problem。
5. Core Algorithm。
6. Data Structure。
7. Transfer / Propagation Rule。
8. Fixed-point 或 Termination 机制。
9. Soundness / Completeness 前提。
10. Precision 与 Performance 的权衡。
11. 论文实验结果及其原始比较对象。
12. 对 BinaryAnalysis 的潜在价值。
13. 二进制语义适配难点。
14. 需要的最小数据契约。
15. 应用阶段。
16. 是否值得实现。

最终分类：

- ADOPT_EARLY：近期可以开展有限实现。
- PREPARE_CONTRACT：当前只需保证扩展性。
- EXPERIMENT_LATER：后续通过研究原型验证。
- NOT_APPLICABLE：当前不适合。
- UNVERIFIED：缺少可靠证据。

不得把论文公布的加速比当作 BinaryAnalysis 的预期效果。

## 7. 核心任务：检查 R1-B 契约的扩展性

必须直接阅读当前 Python 代码和 ANALYSIS_CORE_CONTRACT.md。

### 7.1 CIR Definition / Use

检查：

- EffectId。
- DefinitionId。
- UseId。
- Scalar Def-Use。
- Memory-Def-Use。
- Effect Order。
- Function/CFG Revision。
- Unsupported/Havoc。
- Provenance。

判断是否足以支持：

- Sparse Value-Flow Graph。
- Def-Use Pruning。
- Lazy Edge Generation。
- Forward/Backward Query。

特别审查剪枝是否会破坏二进制寄存器别名、指针算术和内存效果。

### 7.2 Memory Model

检查：

- MemoryObjectId。
- AccessPath。
- MemoryLocation。
- MemoryVersion。
- Strong/Weak Update。
- Read/Write。
- Guard。
- Unknown。
- Partial Overlap。

必须重新审查：

Pointer Alias 与 Memory Access Overlap 是否被混为一谈。

给出两个具体候选契约：

A. 保留 AliasKind，增加独立的 AccessOverlap/ByteCoverage 结果。

B. 在现有 AliasResult 中显式区分地址关系、访问区间和覆盖程度。

对比二者的语义、兼容性和实现代价。

给出推荐，但不要直接修改已批准的核心 Schema。

### 7.3 SSE / Value-Flow

检查：

- SymbolicExprDAG。
- LazySubstitution。
- Definition Dependency。
- Use Dependency。
- Memory Dependency。
- Forward Query。
- Backward Query。

明确三种不同的身份：

1. Expression Identity。
2. Analysis Fact Identity。
3. Value-Flow Dependency Identity。

进一步检查：

- 是否能够进行等价事实合并？
- 是否能够安全 Replay？
- 是否能够延迟生成 Memory Dependency？
- 是否需要独立的 Value-Flow Index？
- 如何记录尚未扩展的查询 Frontier？

不得让 SSE DAG 同时承担全部内存对象管理、Alias 和跨函数图语义。

### 7.4 Query and Precision

检查 R1-B 的 QueryContext、QueryBudget 和 AliasQuery。

讨论是否需要明确区分：

- Query Identity。
- Analysis Context。
- Precision Policy。
- Resource Budget。
- Solver Refinement。
- Completeness。
- Evidence。

必须分析以下机制的支持条件：

- Fast Screening。
- Sparse Traversal。
- On-Demand Alias Refinement。
- Context-sensitive Refinement。
- SMT Refinement。

Precision Policy 决定选择什么求解策略。

QueryBudget 决定资源上限。

二者不得混为一谈。

当前 R1-B 的 AliasQuery 缺失候选导致错误 NOALIAS 的风险必须保留为高优先级问题。

不能在现代算法研究过程中忽略该正确性问题。

### 7.5 Incremental Analysis

检查是否存在或需要以下依赖：

- CIR Artifact → Definition Index。
- Definition → Use。
- Store → Load。
- Alias Evidence → Value-Flow Edge。
- CG Revision → Procedure Summary。
- Summary → Caller Query。
- Policy Revision → Taint Result。
- Analysis Result → Evidence Artifact。

为每种依赖明确：

- Identity。
- Revision。
- Invalidation。
- Unknown Dependency。
- Cache Reuse Preconditions。

特别说明：未知依赖足迹不能被当成不存在依赖。

### 7.6 Provenance and Result

检查：

- 多对多 Provenance。
- Source Artifact。
- CIR Effect。
- Memory Definition。
- Alias Evidence。
- Value-Flow Edge。
- Query Assessment。
- Persisted Result。
- Read-only Inspector。

确认高级算法中的剪枝、合并、Replay 和增量重计算不会破坏来源证据。

## 8. C1 实施前必须解决的三个问题

### 问题 A：Alias 与 AccessOverlap

给出最终推荐的最小契约。

必须明确：

- Pointer Equality。
- Pointer Aliasing。
- Access Overlap。
- Byte Coverage。
- Strong Update Preconditions。

不能只用 MUST_ALIAS 一项覆盖全部语义。

### 问题 B：私有 ID 与持久化

R1-B 允许从 CIR v1 派生私有 Definition/Effect ID。

但 C1 又要求持久化结果和跨进程 Reload。

必须说明：

- ID 是否是确定性的。
- 是否绑定 Artifact Fingerprint。
- 是否绑定 Function/CFG Revision。
- Reload 后如何解析。
- 临时私有 ID 是否可以进入 Result Schema。
- 何时必须升级为正式 CIR v2 Identity。

如果不能满足持久化要求，必须提出有界的 C1 分阶段实现方案，不得伪称跨进程身份稳定。

### 问题 C：真实 CIR 输入

明确 C1 选择哪个现有输入路径。

需要检查：

- 当前仍存在的 Frontend。
- 当前仍存在的 CIR Reader。
- 可用的 CIR Fixture。
- CFG/Origin/Memory Metadata。
- 是否存在旧 scripts 删除后无法构造输入的问题。

给出可执行的输入方案与替代方案。

不恢复旧 Acquisition 脚本。

不得以 Mock-only 测试宣称完整的真实二进制端到端能力。

## 9. 设计未来算法扩展边界

目标是明确职责，不是立即创建框架。

建议分析如下分层是否合理：

### Semantic Layer

- CIR。
- Program/CFG。
- Memory Object。
- MemoryVersion。
- Definition/Use。
- Provenance。

### Dependency Layer

- Scalar Value Flow。
- Memory Value Flow。
- Candidate Alias Edge。
- Guarded Dependency。
- Query Frontier。

### Analysis Strategy Layer

- Forward/Backward Worklist。
- Sparse Demand。
- Lazy Graph Expansion。
- Alias Refinement。
- IFDS/IDE。
- Context Refinement。
- Merge-Replay。

### Result & Incremental Layer

- Result Identity。
- Evidence。
- Graph Revision。
- Dependency Invalidation。
- Cache。
- Read-only Inspector。

检查分层是否引入循环依赖或重复的语义所有权。

对于尚无实际消费者的接口，只记录推荐的未来扩展边界，不创建空实现。

## 10. 必须建立架构扩展性矩阵

针对每种先进算法填写：

| Field | Required |
|---|---|
| Algorithm | 算法 |
| Paper | 来源 |
| Required Facts | 必需的程序语义 |
| Required Data Structures | 所需结构 |
| Existing Support | 已有能力 |
| Missing Contracts | 缺失契约 |
| Soundness Risks | 正确性风险 |
| Binary Adaptation | 二进制语义适配 |
| Minimum Change | 最小修改 |
| Implementation Stage | 实施阶段 |
| Acceptance Witness | 验收证据 |

不得使用“架构支持该算法”这样的笼统结论。

必须具体说明支持到什么程度，以及缺少什么。

## 11. 提出 C1 后续实现策略

基于 R1-B 和本次研究，重新审查 C1-STORE-LOAD-ALIAS-SSE。

明确：

C1 必须实现：

- 正确的 Memory Store/Load 语义。
- Alias 和 AccessOverlap 判定。
- 不确定性传播。
- 共享 Definition/Use 关系。
- Forward/Backward Dependency Query。
- 基础 Evidence。
- 明确的结果状态。

C1 暂不实现：

- 完整 Hermes LSEG。
- 完整 CFL/IDE。
- Merge-Replay。
- Selective Object Sensitivity。
- 完整增量 SVFA。
- 完整跨函数 Taint。
- 全量 Pointer Analysis。

可以提出后续 C2/C3 实验性任务。

但 C1 的基本语义不能因为未来先进算法扩展而被削弱。

如果 C1 过大，可以提出两个有界实施子门槛：

C1a：正确的 Store/Load/Alias/SSE 查询及可检查依赖证据。

C1b：确定性持久化、Reload、失效与只读 Inspector。

两个子门槛共同构成一个完整的 C1 纵向能力，不允许将 C1a 冒充整个 C1 已完成。

## 12. 新的验证策略

针对后续算法研究，给出验证设计，但本轮不运行测试。

至少设计：

### Semantic Correctness

- Must/May/No/Unknown。
- Access Overlap。
- Guard。
- Partial Store。
- Strong/Weak Update。
- Multiple Reaching Definitions。
- Unsupported/Havoc。

### Optimization Equivalence

- Pruning 前后结果一致。
- Lazy Expansion 与完整有界依赖图结果一致。
- Merge-Replay 前后依赖结论一致。
- Cache 命中与重新计算结果一致。

### Incremental Correctness

- 增加/删除 Call Graph Edge。
- 更改 Function Summary。
- 更新 Memory Effect。
- 更改 Taint Policy。
- 失效后不复用陈旧结果。

### Performance

记录：

- Query Time。
- Visited CFG/Value-Flow Nodes。
- Alias Queries。
- SSE Nodes。
- Memory Usage。
- Reanalyzed Functions。
- Expanded Edges。

不得只报告加速比而不核对分析精度和保守性。

可以借鉴 TaintCC 的变形测试思路，但需要证明测试变换保留相关程序语义。

## 13. 本轮文档交付

新增两个文档：

### MODERN_SOURCE_ANALYSIS_REVIEW.md

内容：

- 论文信息。
- 核心算法。
- 算法前提。
- 数据结构。
- 技术局限。
- BinaryAnalysis 迁移价值。
- 研究结论。
- 可核实来源。

### ARCHITECTURE_EXTENSIBILITY_REVIEW.md

内容：

- 当前 R1-B 契约审查。
- 先进算法扩展性矩阵。
- Alias/AccessOverlap 设计选择。
- Value-Flow/Query 分层。
- 增量依赖设计。
- C1 适用的最小契约修改。
- 后续算法实验计划。
- 需要负责人批准的事项。

允许更新：

- ANALYSIS_CORE_CONTRACT.md
- ARCHITECTURE.md
- CORE_ALLOWLIST.md
- BACKLOG.md
- EXECUTION_PLAN.md
- BUILD_LOG.md

只有在发现真实矛盾时才修改现有文档。

不得修改 DECISIONS.md 中 Accepted ADR 的状态。

如果需要改变已批准架构方向，提交 ACR 提案。

不要新增第三份管理文档。

## 14. 本轮禁止事项

- 不修改 Python 生产代码。
- 不修改 CIR Wire Schema。
- 不修改 Memory 运行时实现。
- 不创建 ValueFlowEngine 空框架。
- 不直接实现 IFDS/IDE 或 Hermes。
- 不复制 Java/LLVM 分析器代码。
- 不运行旧 EmTaint。
- 不运行测试。
- 不安装新依赖。
- 不恢复旧 scripts/tests。
- 不修改 references/legacy-emtaint。
- 不自动 Commit/Push。

本轮仅做有界技术研究和契约适配判断。

## 15. 结束条件

最终交付必须包含：

1. 五篇核心论文的可靠来源和算法机制审查。
2. 四篇补充论文的适用性判断。
3. 现代算法与旧 EmTaint 算法的对比。
4. 现代算法与 R1-B 契约的对比。
5. BinaryAnalysis 现有架构的扩展性矩阵。
6. Alias 与 AccessOverlap 的推荐分界。
7. QueryContext、PrecisionPolicy、Budget 的建议。
8. Lazy Value-Flow 和 SSE 的边界。
9. Incremental Analysis 的依赖要求。
10. C1 最小必要契约修订。
11. C2/C3 后续算法试验计划。
12. 不推荐迁移的算法及原因。
13. 需要负责人批准的决策。

必须区分：

- 论文已证明的结果。
- 旧 EmTaint 真实行为。
- BinaryAnalysis 现有能力。
- 提议中的新设计。
- 尚未验证的研究假设。

不得将算法适配建议描述为已经实现的功能。

完成后，将 R1-C 标记为 IMPLEMENTED，等待静态审查和负责人批准。

不得标记为 APPROVED。

完成后停止，不自动启动 C1、C2 或其他编码阶段。