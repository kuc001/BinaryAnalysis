BinaryAnalysis — 全面架构重置与重新设计任务
1. 项目目标
本项目决定放弃之前 P1–P7 阶段式重构路线，重新审查和设计 BinaryAnalysis。

之前的 P1–P7 是阶段性重构方案，不再作为新项目的架构依据。

本次重构的目标是建立一个长期可维护、支持多种 Frontend、支持增量分析、支持多种程序分析算法的通用二进制静态分析框架。

核心要求：
1. 清除 P1–P7 阶段性架构和命名。
2. 删除整个 tests 目录及其内容。
3. 删除整个 scripts 目录及其内容。
4. 删除旧阶段生成的辅助文档、实验脚本和临时产物。
5. 重新审查所有生产代码的职责和依赖关系。
6. 将 Acquisition 融入整个项目体系。
7. 重新设计 Artifact、Cache 和 Analysis Result 的生命周期。
8. 重新设计 Frontend、IR、Program Representation 和 Analysis Engine 的关系。
9. 不以旧 EmTaint 的代码组织方式作为新项目的默认架构。
10. 仅保留经过重新审查后有价值的算法和实现。
旧 EmTaint 仓库为只读参考，不允许修改。
2. 当前执行阶段：只审计，不修改代码
本轮首先完成全面架构审计。

禁止：
- 修改 Python 源代码。
- 删除文件。
- 创建新目录。
- 提交 Git。
- 运行测试。
- 生成测试代码。
- 直接按照旧 P1–P7 计划继续工作。
本轮只输出分析报告和新架构建议。
3. 全面审查当前代码仓库
必须从项目根目录开始，分析所有生产代码。
3.1 仓库结构
统计并说明：
- Python Package 结构。
- CLI 入口。
- Frontend。
- IR。
- CFG/CG。
- Memory。
- Alias。
- Dataflow。
- SSE / Symbolic。
- Taint。
- Vulnerability。
- Solver。
- Storage。
- Debugging。
- Configuration。
- Dependencies。
3.2 旧阶段遗留
搜索整个仓库中的：
- P1
- P2
- P3
- P4
- P5
- P6
- P7
- 旧阶段专属类名和函数名。
- 旧阶段专属 CLI 参数。
- 旧阶段专属文件命名。
- 旧阶段专属 Schema。
- 旧阶段专属文档。
列出所有位置和依赖关系。

不得仅根据文件名判断代码是否应该删除。
3.3 tests 和 scripts 清理影响
本项目决定删除：
- tests/
- scripts/
但必须先分析：
1. scripts 中哪些代码被生产 Package 导入。
2. 哪些功能需要迁移到正式 Package。
3. 哪些文件可以直接删除。
4. 哪些 CI、CLI、文档仍然引用这些目录。
5. 删除之后哪些功能会受到影响。
最终目标是整个仓库不再依赖 tests 和 scripts 中的代码。

不要保留隐藏的旧阶段执行入口。
3.4 生产代码价值评估
对每个主要模块进行分类：
- KEEP：实现有价值，可以直接保留。
- REFACTOR：功能有价值，但架构需要调整。
- REPLACE：现有设计不合理，需要重新设计。
- REMOVE：属于历史遗留或无用功能。
重点审查：
- CIR 设计是否合理。
- OriginMap 是否足以支撑 Provenance。
- ValueRef 和 SymbolicExprId 身份设计。
- CFG、CG、ICFG。
- APG。
- MemoryVersion。
- MemoryQueryPort。
- Alias Analysis。
- SSE DAG。
- Demand。
- Taint Analysis。
- Function Summary。
- Solver 接口。
不允许因为之前已经完成某个阶段，就默认其实现正确。
3.5 依赖关系
建立实际的模块依赖图。

明确：
1. 哪些模块相互循环依赖。
2. 哪些模块承担了不应该承担的职责。
3. 哪些模块同时混合了 Frontend、Analysis、Storage 和 Debug。
4. 哪些接口应该独立。
5. 哪些对象应该作为统一的数据契约。
4. Acquisition 重新设计
Acquisition 不再属于 P7。

它是整个 BinaryAnalysis 的通用基础设施。

必须区分：
Acquisition Artifact
负责：
- Binary Metadata。
- Architecture。
- Loader Information。
- Memory Segments。
- Function Metadata。
- Machine Instructions。
- Frontend IR。
- CIR。
- CFG。
- OriginMap。
- Provenance。
Analysis Result
负责：
- Call Graph。
- Alias Results。
- Dataflow Results。
- Memory Analysis Results。
- Taint Results。
- Vulnerability Findings。
具体哪些属于 Acquisition，哪些属于 Analysis，必须依据其数据来源和计算依赖确定。
Cache
负责：
- Acquisition Artifact Cache。
- Analysis Result Cache。
- Cache Key。
- Cache Invalidation。
- Incremental Rebuild。
- Content Addressing。
不能把 Acquisition 和 Cache 混为一谈。

必须设计：
1. Artifact Manifest。
2. Artifact Version。
3. Binary Fingerprint。
4. Frontend Fingerprint。
5. IR Schema Version。
6. Per-Function Artifact。
7. Artifact Store。
8. Cache Manager。
9. Cache Invalidation。
10. Concurrent Acquisition。
11. Atomic Persistence。
12. Partial Acquisition Recovery。
Acquisition 应支持 IDA VEX、angr VEX 以及未来其他 Frontend。

禁止绑定特定固件、函数、文件路径或 P7 运行环境。

分析命令应能自动复用有效 Acquisition；没有有效 Artifact 时自动创建。
5. 新项目架构设计
提出一个完整的新架构。

至少包含：
- Project Management。
- Input Management。
- Acquisition。
- Frontend。
- IR。
- Program Representation。
- Memory Analysis。
- Program Analysis。
- Security Analysis。
- Solver。
- Debugging & Provenance。
- Artifact Storage。
- Result Storage。
- Cache Management。
- CLI。
明确每个模块的职责、输入、输出和依赖关系。

禁止为了目录整齐而进行过度拆分。

优先设计稳定的数据契约，再确定目录结构。
6. 技术路线
当前以 Python 为主要实现语言。

不考虑 Rust 迁移。

angr 作为一个可选 Frontend，而不是整个项目的基础架构。

IDA VEX 和 angr VEX 应尽可能使用统一的 Frontend Contract。

CIR 是否继续作为统一 IR，需要通过当前实现审查给出结论。

不得默认旧 CIR Schema 永远不变。
7. 本轮最终交付
只输出以下内容：
1. 当前仓库完整结构分析。
2. P1–P7 遗留清单。
3. tests/scripts 删除影响分析。
4. 生产代码 KEEP/REFACTOR/REPLACE/REMOVE 清单。
5. 当前模块依赖关系图。
6. Acquisition 新架构设计。
7. Cache 与 Artifact 生命周期设计。
8. 新项目完整架构图。
9. 推荐的新目录结构。
10. 分阶段重构计划。
11. 每个阶段的输入、输出和完成标准。
12. 可能导致功能丢失的风险。
本轮不修改代码，不提交 Git，不运行测试。

特别强调：

不要为了完成审计而直接沿用 P1–P7 的模块划分。

不要把 Acquisition 当作 P7 的辅助脚本。

不要把 Cache、Artifact 和 Analysis Result 混为一谈。

本轮的唯一目标是：基于当前真实源代码，重新确定 BinaryAnalysis 应该成为什么样的系统。