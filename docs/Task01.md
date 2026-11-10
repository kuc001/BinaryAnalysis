BinaryAnalysis — 第一阶段：全面仓库审计与架构重新设计
现在开始 BinaryAnalysis 的全面架构重置工作。

本次任务是整个项目重新设计的起点。

请严格遵守：本轮只进行源代码分析、架构审计和设计，不修改任何现有代码。
一、首先阅读项目文档
必须完整阅读以下文件：
1. AGENTS.md
2. 00_CODEX_INS.md
3. CODEX_TASK.md
4. ARCHITECTURE.md
5. ACQUISITION_DESIGN.md
6. ENGINEERING_STANDARDS.md
7. EXECUTION_PLAN.md
8. REPOSITORY_AUDIT_TEMPLATE.md
9. DECISIONS_TEMPLATE.md
10. CODEX_WORKFLOW.md
11. TASK_1.md
12. TASK_2.md
必须理解这些文档之间的关系。

如果不同文档之间存在冲突，记录冲突并给出建议，不要自行修改原始需求。
二、检查当前 Git 和仓库状态
首先确认：
- 当前仓库根目录。
- 当前 Git 分支。
- 当前 Commit。
- 工作区是否存在未提交修改。
- 是否存在多个 Worktree。
- 10 份架构文档是否位于正确的项目根目录。
不要修改 Git 状态。

不要执行 reset、clean、checkout、merge、rebase 或 commit。
三、全面审计当前生产代码
不要只阅读 README 或目录结构。

必须从实际源代码出发，逐步追踪模块的调用关系和数据流。

重点审查：
1. Python Package 和 CLI。
2. Frontend：IDA、angr、VEX。
3. CIR 和现有 IR Contracts。
4. Function、Block、CFG、CG、ICFG。
5. Memory Object、APG、MemoryVersion。
6. Alias Analysis。
7. Dataflow、Def-Use、Use-Def。
8. SSE DAG、Demand。
9. Interprocedural Analysis、Function Summary。
10. Solver。
11. Taint Analysis。
12. Vulnerability Detection。
13. Acquisition、Storage、Serialization。
14. Debugging、Provenance。
15. Configuration 和 Dependencies。
对于每个模块必须说明：
- 实际职责。
- 核心类和函数。
- 输入与输出。
- 上游依赖。
- 下游调用者。
- 当前设计问题。
- 是否存在重复实现。
- 是否存在循环依赖。
- 是否适合长期保留。
不能根据模块名称猜测功能。
四、重新评估整个项目架构
本项目不再采用旧 P1–P7 阶段式架构。

必须重新回答：
1. CIR 是否适合作为统一分析 IR？
2. 是否需要独立 HIR？
3. CTree 应该如何进入 HIR？
4. VEX 应该如何进入 CIR？
5. IDA Microcode 如何纳入未来架构？
6. 如何建立多对多 Provenance？
7. 如何统一 Dataflow、Alias、Memory、Taint？
8. 如何实现 Acquisition、Artifact、Cache 和 Analysis Result 的独立生命周期？
9. 如何实现函数级增量分析？
10. 如何避免不同 Frontend 形成不同的分析引擎？
不能因为旧代码已经实现某个功能，就默认该功能的设计正确。
五、重点审查 Acquisition
必须分析当前项目的实际 Acquisition 实现。

明确区分：
- Acquisition Service。
- Acquisition Artifact。
- Artifact Store。
- Artifact Cache。
- Analysis Result。
- Analysis Result Cache。
- Debug/Evidence Artifact。
重点研究：
- Binary Fingerprint。
- Frontend Fingerprint。
- Artifact Manifest。
- CIR/HIR Schema Version。
- Function-level Artifact。
- Atomic Persistence。
- Cache Invalidation。
- Incremental Acquisition。
- Concurrent Acquisition。
- Partial Recovery。
Acquisition 必须成为整个项目的通用能力，不能继续绑定 P7、RV130、httpd 或某个固定路径。
六、重点审查 IDA Hex-Rays CTree
必须研究结构化 CTree 接口。

分析：
- cfunc_t。
- cinsn_t。
- cexpr_t。
- lvar_t。
- tinfo_t。
明确：
1. CTree 如何导出。
2. 如何序列化。
3. 如何建立 HIR。
4. 如何进行 HIR-to-CIR。
5. 如何处理数组、结构体、指针、函数指针。
6. 如何保留类型推断来源。
7. 如何保留原始 CTree 节点。
8. 如何与机器指令建立多对多映射。
9. 如何保留不支持的节点。
10. 如何处理 CTree 和底层机器指令的语义冲突。
不要解析伪代码窗口文本来构建主要分析语义。
七、审查旧代码的保留价值
对每个主要模块给出：
- KEEP
- REFACTOR
- REPLACE
- REMOVE
必须给出具体文件、类、函数和判断理由。

特别审查旧的 Memory、APG、Alias、SSE、Demand 和 Taint 算法。

不能因为旧算法复杂或者已经投入大量时间，就默认必须保留。

也不能为了追求全新架构而无理由全部重写。
八、分析 tests 和 scripts 删除影响
项目目标是清理旧 tests 和 scripts。

但本轮只审查：
- 哪些 scripts 被生产代码调用。
- 哪些功能应该迁移到正式 Package。
- 哪些 CI 和 CLI 依赖这些脚本。
- 哪些测试数据和语义案例值得保留为未来重新设计的参考。
- 删除之后需要建立什么新的验证体系。
本轮禁止实际删除文件。
九、输出审计报告
使用 REPOSITORY_AUDIT_TEMPLATE.md 作为基础。

创建：
1. REPOSITORY_AUDIT.md
2. DECISIONS.md（只记录待确认的架构决策，不擅自标记为已批准）
同时更新 EXECUTION_PLAN.md 中的审计结果和待决事项。

审计报告必须包含：
- 完整仓库结构。
- 真实模块依赖图。
- 旧阶段遗留清单。
- tests/scripts 清理影响。
- KEEP/REFACTOR/REPLACE/REMOVE 清单。
- Acquisition 新设计。
- HIR/CIR 新设计。
- CTree Frontend 设计。
- Multi-Level Provenance 设计。
- 新架构图。
- 新目录结构建议。
- 后续实施顺序。
- 风险和需要人工确认的事项。
每项结论明确区分：

SOURCE_CONFIRMED
REQUIREMENT
RECOMMENDATION
OPEN_QUESTION
十、严格禁止事项
本轮绝对不允许：
- 修改 Python 源代码。
- 删除任何文件。
- 移动或重命名任何文件。
- 创建新的代码目录。
- 修改 pyproject.toml。
- 修改 requirements.lock。
- 修改 CLI。
- 修改 IR Schema。
- 运行测试。
- 生成测试代码。
- 执行旧 P1–P7 任务。
- 提交 Git。
- 推送 GitHub。
允许创建或更新的文件仅限：
- REPOSITORY_AUDIT.md
- DECISIONS.md
- EXECUTION_PLAN.md
不得覆盖原始 TASK_1.md、TASK_2.md 和架构设计文档。
十一、最终报告和停止条件
完成审计后：
1. 汇报实际阅读和审查的文件范围。
2. 汇报真实模块依赖。
3. 汇报架构设计结论。
4. 汇报需要人工决定的问题。
5. 给出下一阶段建议。
完成后立即停止，不得自动开始仓库清理或代码重构。

等待项目负责人审查并批准新架构。

本轮唯一目标：

基于真实源代码，确定 BinaryAnalysis 应该如何重新设计，而不是继续修补过去的 P1–P7 实现。