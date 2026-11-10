# BinaryAnalysis — Milestone B0：Repository Reset Preflight

## 1. 项目背景

BinaryAnalysis 已经完成：

- Milestone A：Repository Audit。
- Milestone A2：Architecture Decision & Design Proposal。

当前目标是彻底摆脱旧 P1–P7 阶段性重构体系，重新建立 BinaryAnalysis。

请首先阅读当前版本：

- AGENTS.md
- CODEX_TASK.md
- ARCHITECTURE.md
- ACQUISITION_DESIGN.md
- ENGINEERING_STANDARDS.md
- EXECUTION_PLAN.md
- REPOSITORY_AUDIT.md
- DECISIONS.md
- TASK_1.md
- TASK_2.md

必须以当前本地文件为准，不得使用旧 Commit 中的文档覆盖本地修改。

## 2. 本阶段目标

本阶段是 B0：Repository Reset Preflight。

目的不是实际删除文件，而是制定一份完整、可审查、可执行的仓库重置方案。

必须明确：

1. 哪些生产代码需要迁移。
2. 哪些历史代码可以删除。
3. 哪些 scripts 仍被生产代码依赖。
4. 哪些 tests 属于旧架构。
5. 哪些历史语义案例需要提炼为新架构的需求。
6. 哪些生成目录可以清理。
7. 如何保证清理后 BinaryAnalysis 仍然具有完整的产品入口。
8. 如何在清理过程中避免丢失有价值的算法实现。

## 3. 第一项工作：检查 Git 状态

执行：

- git status --short --branch
- git rev-parse HEAD
- git log -5 --oneline
- git worktree list
- git diff --stat
- git ls-files --others --exclude-standard

记录：

- 当前分支。
- 当前 HEAD。
- 所有未提交修改。
- 未跟踪文件。
- 其他 Worktree。
- 哪些文件属于本次架构设计文档。

必须保护现有用户修改。

禁止：

- git reset
- git clean
- git checkout
- git restore
- git rebase
- git merge
- commit
- push

不得覆盖、删除或重置任何未提交修改。

## 4. 第二项工作：scripts 完整清理审计

逐一检查 scripts 目录中的所有文件。

不能只检查 p1_runtime.py、p1_solver_worker.py 和 p7_acquire.py。

对每个文件分类：

### MIGRATE

被正式生产代码调用，必须迁移到正式 Package。

### REPLACE

属于阶段性实现，但功能仍有必要，应由新架构重新实现。

### DELETE

完全属于历史测试、实验、临时脚本或已无价值的工具。

### RETAIN_TEMPORARILY

在替代实现完成之前必须暂时保留。

每个文件必须提供：

- 文件路径。
- 主要功能。
- 被哪些生产代码调用。
- 调用位置。
- 输入输出。
- 依赖。
- 建议处理方式。
- 迁移目标模块。
- 删除前置条件。

特别检查：

1. ProbeWriteGuard / WriteGuard。
2. Solver Worker。
3. Legacy Backend。
4. Acquisition。
5. Source Manifest。
6. Baseline / Reference。
7. Alias Benchmark。
8. P1–P7 运行脚本。
9. PowerShell 辅助脚本。
10. 其他未分类脚本。

目标是最终彻底删除 scripts，不允许通过重命名 scripts 或将旧脚本搬到其他目录来规避清理。

但生产功能必须迁移到正式 Package。

## 5. 第三项工作：tests 完整清理审计

逐一检查 tests 目录中的文件。

分成：

- LEGACY_TEST：绑定旧 P1–P7 契约的测试。
- SEMANTIC_CASE：具有独立算法价值的语义场景。
- FIXTURE：输入二进制、JSON 和其他数据。
- BENCHMARK：性能或精度基准。
- OBSOLETE：已经没有价值的历史数据。

本项目决定清除旧 tests。

但是不能因为删除 tests，就丢失对算法设计有价值的语义知识。

对每个有价值的场景，提炼：

- 它验证的语义问题。
- 输入条件。
- 预期的分析性质。
- 对应的新架构模块。
- 是否需要未来重新建立验证场景。

不允许简单将旧测试文件改名后迁移到新目录。

新架构的验证体系必须基于新的 HIR、CIR、Memory、Alias、Dataflow、Taint 契约重新建立。

## 6. 第四项工作：历史产物清理

检查：

- .p1-work/
- .p7-work/
- .debug/
- 其他实验输出目录。
- 临时 Acquisition。
- 旧 CIR。
- 旧 Memory Snapshot。
- 旧分析报告。
- 旧 baseline。
- 旧调试 Sidecar。

逐项判断：

- 是否为生成数据。
- 是否有用户需要保留的数据。
- 是否被当前代码读取。
- 是否属于旧 Schema。
- 是否需要备份。
- 是否可以删除。

特别注意：

不得删除：

- .venv/
- Python 依赖配置。
- requirements.lock。
- Git 仓库。
- 用户的原始固件。
- IDA 数据库。
- 用户未提交的文件。

不要因为目录名称包含 P7 就直接认定其内容可以删除。

## 7. 第五项工作：修订 A2 设计文档

根据审计发现，对以下文档进行有限修订。

### REPOSITORY_AUDIT.md

- 合并历史审计与 A2 修正。
- 消除相互矛盾的当前事实。
- 将旧审计信息移至历史附录。
- 增加完整的数据生命周期图。
- 增加算法风险矩阵。
- 明确实际代码事实和架构推论。

### ARCHITECTURE.md

- 修正 Initial Call Graph、Refined Call Graph 和 ICFG 的数据流顺序。
- 明确 Static Callsite Hint 与 Analysis Result 的区别。
- 保留 HIR/CIR 的当前推荐方案。
- 明确 CTree 与底层指令的多对多映射。

### ACQUISITION_DESIGN.md

重点修正 Function-level Fingerprint。

必须采用两级设计：

Module Identity:
- Binary SHA256。
- Architecture。
- ABI。
- Loader Configuration。
- Module Metadata。

Function Semantic Fingerprint:
- Function Code Bytes Hash。
- Function Boundary。
- Relevant Relocations。
- Relevant Metadata。
- Frontend Version。
- Relevant Type Dependencies。
- Lowering Version。

不能让整个 Binary SHA256 的变化无条件导致所有函数重新 Acquisition。

如果无法可靠确定某个函数的依赖范围，则保守退化到模块级失效。

同时明确 Windows 环境中的原子发布、文件锁、并发和恢复要求。

### DECISIONS.md

保持 ADR-001 至 ADR-012 的 Proposed 状态。

不得自行批准架构决策。

### EXECUTION_PLAN.md

将 Milestone B 拆成：

B0：Reset Preflight。
B1：生产脚本依赖迁移。
B2：旧 tests/scripts 和历史产物清理。
B3：CLI、打包配置和文档整理。

明确每个阶段的依赖、输入、输出和验收条件。

## 8. 第六项工作：生成 RESET_MANIFEST.md

创建一份完整的仓库重置清单。

必须包含：

### A. 迁移清单

所有需要从 scripts 迁移到正式 Package 的功能。

### B. 删除清单

所有可以安全删除的 scripts、tests 和历史文件。

### C. 暂缓删除清单

尚未有替代实现的生产依赖。

### D. 数据保护清单

用户数据、原始固件、IDA 数据库、依赖环境及未提交文件。

### E. 清理顺序

必须明确先迁移、再替换、最后删除。

### F. 依赖检查

每项删除必须列出生产代码、CLI、CI、文档和开发流程中的引用。

### G. 风险

列出可能造成产品功能丢失的情况。

## 9. 第七项工作：重新审查未来开发入口

明确最终产品入口：

- Project Management。
- Acquisition。
- Artifact Store。
- Cache。
- Frontend。
- HIR/CIR。
- Program Analysis。
- Security Analysis。
- Debugging。

特别检查：

- main.py。
- python -m emtaint。
- pyproject.toml。
- requirements.lock。

明确哪些入口保留，哪些需要重构。

暂时保留 emtaint import package，除非有充分理由建议更名。

## 10. 输出文档

本轮允许修改：

- REPOSITORY_AUDIT.md
- ARCHITECTURE.md
- ACQUISITION_DESIGN.md
- DECISIONS.md
- EXECUTION_PLAN.md

新增：

- RESET_MANIFEST.md

不允许修改其他文件。

## 11. 严格禁止事项

本轮禁止：

- 删除文件。
- 移动文件。
- 重命名文件。
- 修改 Python 源代码。
- 修改 CLI。
- 修改依赖。
- 修改 IR Schema。
- 创建新 Package。
- 运行测试。
- 执行实际仓库清理。
- 修改 Git 历史。
- Commit / Push。

本阶段只进行审计、设计和文档修订。

## 12. 最终交付和停止条件

完成后输出：

1. scripts 全量处置清单。
2. tests 全量处置清单。
3. 历史生成目录清理清单。
4. 生产代码迁移清单。
5. 新架构文档修订内容。
6. RESET_MANIFEST.md。
7. B1–B3 的具体实施计划。
8. 可能造成的功能损失及规避方法。

每一项结论必须基于实际文件和调用关系。

完成后停止，等待负责人审查 RESET_MANIFEST.md。

未经负责人批准，不允许开始 B1 或执行任何删除操作。