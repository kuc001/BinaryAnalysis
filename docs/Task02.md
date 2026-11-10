# BinaryAnalysis — Milestone A2：Architecture Decision & Design Freeze

## 1. 任务背景

Milestone A 已经完成第一轮仓库审计。

请先阅读：

- REPOSITORY_AUDIT.md
- DECISIONS.md
- EXECUTION_PLAN.md
- TASK_1.md
- TASK_2.md
- AGENTS.md
- CODEX_TASK.md
- ARCHITECTURE.md
- ACQUISITION_DESIGN.md
- ENGINEERING_STANDARDS.md
- CODEX_WORKFLOW.md

当前仓库：

- Repository: kuc001/BinaryAnalysis
- Branch: codex/icall
- 本任务开始前先检查当前 Git HEAD 和工作区状态。

本任务的目标是完成架构决策分析和设计文档修订，为下一阶段仓库清理和代码重构建立明确依据。

## 2. 当前任务边界

本轮属于 Milestone A2。

允许：

- 阅读全部生产源代码。
- 对现有架构审计结论进行必要的二次核对。
- 修改架构设计文档。
- 修改 Acquisition 设计文档。
- 修改架构决策登记。
- 修改执行计划。
- 新增必要的技术设计文档，但必须说明其独立价值。

禁止：

- 修改 Python 源代码。
- 删除、移动、重命名任何生产代码。
- 删除 tests 或 scripts。
- 创建新的 Python Package。
- 修改 pyproject.toml。
- 修改 requirements.lock。
- 修改 CLI。
- 运行测试或基准。
- 修改 Git 历史。
- Commit 或 Push。

本轮只允许修改 Markdown 文档。

## 3. 首先复核 Milestone A 审计结果

不能盲目接受之前的审计结论。

针对 REPOSITORY_AUDIT.md：

1. 核实关键模块的实际代码。
2. 核实关键 import 和调用关系。
3. 核实 scripts 的生产依赖。
4. 核实 FunctionStore 的实际职责。
5. 核实 CIR、Memory、Alias、Demand、Taint 的真实数据流。
6. 核实 IDA Frontend 的实际实现。
7. 核实当前是否存在 CTree 或 Microcode 生产实现。
8. 核实打包配置是否存在重复声明。

发现不准确的地方，修正审计报告。

特别注意：pyproject.toml 和 setup.py 的 distribution name 不一致，目前只能确认声明不一致，不能在未构建验证时断言最终 wheel 的实际行为。

审计中必须区分：

- 已由源代码确认的事实。
- 之前审计的推论。
- 本轮新增的架构建议。

## 4. 重点完成 HIR / CIR 架构决策

这是本次设计最重要的任务。

请深入分析当前 CIR：

- CIRModule。
- CIRFunction。
- CIRBlock。
- Compute。
- LoadEffect。
- StoreEffect。
- CallEffect。
- ValueRef。
- Origin。
- ValueType。
- MemorySnapshot。
- SymbolicExprId。

回答：

1. 当前 CIR 是否能够表达高级变量、数组、结构体和指针语义？
2. 当前 CIR 是否能够表达 CTree 的变量定义和使用？
3. 是否需要独立 HIR？
4. HIR 应该保留哪些 CIR 不适合表达的高级语义？
5. CIR 是否继续作为统一分析表示？
6. 如何保留 HIR 到 CIR 的映射？
7. 如何避免 HIR 与 CIR 重复保存完全相同的数据？
8. 如何表达部分 Lowering 和 Unsupported？
9. 如何保证 Alias、Memory、Dataflow 和 Taint 不依赖 HIR 的具体实现？

必须比较至少两种方案：

方案 A：

CTree → HIR → CIR

VEX → CIR

Microcode → CIR

方案 B：

CTree → HIR ─┐

VEX → CIR ───┼→ Unified Analysis Model

Microcode → CIR ┘

分析它们的复杂度、语义保留、统一分析能力和长期扩展成本。

给出推荐方案和明确理由，但不要替项目负责人批准 ADR。

## 5. 完整设计 CTree Frontend

以 IDA Hex-Rays 结构化 CTree 为输入。

研究：

- cfunc_t
- cinsn_t
- cexpr_t
- lvar_t
- tinfo_t

根据实际 IDA API 版本确认可用能力。

必须设计：

1. IDA 内部 Exporter。
2. CTree Traversal。
3. Node Identity。
4. Local Variable Identity。
5. Type Serialization。
6. Call Target Extraction。
7. Array/Struct/Pointer Extraction。
8. Control Flow Extraction。
9. Unsupported Node Preservation。
10. HIR Serialization。

不能用伪代码字符串作为主要分析输入。

明确 IDA 运行环境和 BinaryAnalysis 主进程之间的边界。

主分析引擎不应依赖实时 Hex-Rays Python 对象。

## 6. 设计统一 Memory Model

结合当前真实的：

- memory/access_path.py
- memory/access_graph.py
- memory/state.py
- memory/engine.py
- memory/memory_version.py
- memory/query_port.py

重新设计：

1. Stack Object。
2. Global Object。
3. Heap Object。
4. Unknown Object。
5. Array Element。
6. Struct Member。
7. Pointer Dereference。
8. Access Path。
9. Memory Version。
10. Partial Overlap。
11. Strong/Weak Update。
12. Alias Query。

重点分析：

CTree 的：

v2[3]

如何与底层：

[SP + offset]

建立同一个候选内存对象的映射。

必须保留类型来源、偏移来源和可信度。

不要假设反编译器推断的数组或结构体布局必然正确。

不要因为引入 HIR 而重新实现一套 Alias Engine。

## 7. 设计 Multi-Level Provenance

明确以下关系：

CTree Node
    ↕
HIR Node
    ↕
CIR Definition / ValueRef
    ↕
VEX / Microcode
    ↕
Machine Instruction

必须支持：

- 多对多关系。
- 一个节点映射多条指令。
- 多个节点对应一条指令。
- Synthetic Node。
- No-EA Node。
- Partial Mapping。
- Ambiguous Mapping。
- Semantic Conflict。

每条映射应包含：

- Source Identity。
- Target Identity。
- Binary Identity。
- Function Identity。
- Mapping Method。
- Confidence。
- Completeness。
- Source Frontend。
- Frontend Version。

地址必须明确区分：

- RVA。
- IDA EA/VA。
- Runtime VA。
- File Offset。

不得通过编号或地址邻近关系猜测来源。

## 8. 设计 Decompiler Confidence

明确区分：

- BINARY_CONFIRMED。
- DECOMPILER_RECOVERED。
- DECOMPILER_INFERRED。
- USER_ANNOTATED。
- ANALYSIS_DERIVED。
- UNKNOWN。

设计冲突处理策略。

例如：

CTree 推断变量为 int *，底层指令仅能确认 32-bit Store。

不能直接将 CTree 类型当成二进制事实。

必须明确哪些分析结果可以继续，哪些需要保守降级，哪些必须标记 UNKNOWN。

## 9. 重新设计 Acquisition

结合 ACQUISITION_DESIGN.md 和实际 FunctionStore。

明确分离：

- Acquisition Service。
- Frontend Export。
- HIR Artifact。
- CIR Artifact。
- Provenance Artifact。
- Artifact Store。
- Acquisition Cache。
- Analysis Result Store。
- Analysis Result Cache。
- Debug/Evidence Store。

必须设计：

- Manifest。
- Fingerprint。
- Schema Version。
- Per-Function Artifact。
- Module-Level Metadata。
- Atomic Persistence。
- Concurrent Acquisition。
- Partial Recovery。
- Incremental Invalidation。
- Dependency Graph。

分析如何让：

python -m emtaint analyze --project project.yaml

自动复用有效 Artifact，缺少时自动 Acquisition。

显式 acquire 命令仍然保留。

不要让 Acquisition 与任何 P1-P7 逻辑绑定。

## 10. 增加 ADR-011 和 ADR-012

在 DECISIONS.md 中增加：

ADR-011：Multi-Representation Semantic Conflict Resolution。

ADR-012：Unified Analysis Model Boundary。

每项需要：

- Context。
- 当前源代码证据。
- 备选方案。
- 推荐方案。
- 技术取舍。
- 迁移影响。
- 需要负责人批准的问题。

所有 ADR 保持 Proposed，不允许自行标记 Accepted。

同时重新审查 ADR-001 到 ADR-010，必要时调整其建议。

## 11. 修订 ARCHITECTURE.md

将其从简单架构提案提升为详细设计文档。

至少包含：

1. System Overview。
2. Layer Responsibilities。
3. Frontend Architecture。
4. HIR Architecture。
5. CIR Architecture。
6. Program Model。
7. Memory Model。
8. Unified Analysis Engine。
9. Provenance。
10. Confidence。
11. Storage。
12. Cache。
13. Debugging。
14. CLI。
15. Dependency Rules。
16. Error / Unknown / Partial Semantics。

必须包含模块依赖图和主要数据流。

不得为了目录整齐过度拆分模块。

## 12. 修订 ACQUISITION_DESIGN.md

增加：

- CTree Artifact。
- HIR Artifact。
- CIR Artifact。
- Multi-Frontend Acquisition。
- Per-Function Fingerprint。
- Module Manifest。
- Cross-Function Dependencies。
- Incremental Rebuild。
- Cache Invalidation。
- Atomic Publish。
- Recovery。
- Artifact Compatibility。

明确 Acquisition 与 Analysis Result 的边界。

## 13. 修订 EXECUTION_PLAN.md

在 Milestone A 和 B 之间加入：

Milestone A2 — Architecture Decision & Design Freeze。

A2 的输出：

- 修订后的 ARCHITECTURE.md。
- 修订后的 ACQUISITION_DESIGN.md。
- 完整 DECISIONS.md。
- 修订后的 EXECUTION_PLAN.md。

A2 未经负责人批准，不允许开始 B。

重新设计 B–H 每个阶段的：

- 目标。
- 输入。
- 输出。
- 依赖。
- 涉及模块。
- 风险。
- 验收标准。
- 文档交付。

避免把计划写成只有几行的工作摘要。

## 14. 质量要求

所有设计必须基于实际源代码和明确需求。

不允许：

- 只画目录结构，不定义数据契约。
- 只定义类名，不定义语义。
- 为了支持 CTree 建立第二套分析引擎。
- 将所有信息都塞进 CIR。
- 将 HIR 当成伪代码文本 AST。
- 将 Acquisition 当成缓存目录。
- 将 Analysis Result 当成 Acquisition 输入。
- 静默丢弃 Unsupported。
- 将 Decompiler Inferred 当作 Binary Confirmed。
- 将 MayAlias 当作 MustAlias。
- 将候选 Taint Path 当作漏洞证明。

Python API 必须考虑实际 IDA 版本和 Hex-Rays 环境。

## 15. 本轮交付

只允许更新：

- REPOSITORY_AUDIT.md
- ARCHITECTURE.md
- ACQUISITION_DESIGN.md
- DECISIONS.md
- EXECUTION_PLAN.md

如需新增文档，必须先解释为什么不能合理地纳入上述文档。

不修改其他 Markdown。

不修改任何代码。

不运行测试。

不提交 Git。

## 16. 完成后的停止条件

输出：

1. 本轮审计修正。
2. 最终推荐架构。
3. HIR/CIR 设计结论。
4. Acquisition 设计结论。
5. Memory 统一设计。
6. Provenance 设计。
7. ADR-001 到 ADR-012 待确认列表。
8. B–H 实施计划。
9. 仍然需要负责人决定的问题。

所有 ADR 保持 Proposed。

完成后停止，等待负责人批准。

不得自动进入 Milestone B。

本轮唯一目标是：将 BinaryAnalysis 的新架构从概念提案提升为可以指导后续 Codex 实施的详细设计规范。