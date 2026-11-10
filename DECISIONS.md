# BinaryAnalysis 架构决策登记（全部待确认）

> 2026-11-10。本文件只记录提案，**无一项标记为已批准**。证据和备选方案见 `REPOSITORY_AUDIT.md`。标签沿用 SOURCE_CONFIRMED / REQUIREMENT / RECOMMENDATION / OPEN_QUESTION。

| ID / 状态 | 待决问题与源代码证据 | 建议及替代方案 | 负责人决定 |
|---|---|---|---|
| ADR-001 / Proposed | **SOURCE_CONFIRMED** `ir/canonical/model.py` 有 typed non-SSA effects，`core/contracts.py` 的 `ValueType` 仅标量、`Origin` 一点来源，`CIRModule` 混入 memory snapshot。 | **RECOMMENDATION** 保留效果语义，演化为新版本 canonical CIR；备选是全新 IR 或维持 v1。需要 schema/迁移政策。 | **OPEN_QUESTION** 待批准 |
| ADR-002 / Proposed | **REQUIREMENT** CTree 高级语义和类型来源须保留；现有代码无 HIR。 | **RECOMMENDATION** 对 CTree 强制独立可序列化 HIR；VEX/Microcode 可直接到 CIR；备选是所有 frontend 都造 HIR。 | **OPEN_QUESTION** 待批准 |
| ADR-003 / Proposed | **SOURCE_CONFIRMED** `IdaVexFrontend` 读取 IDA CFG JSON 和 ELF，不调用 Hex-Rays。 | **RECOMMENDATION** IDA 内结构化 exporter→独立交换 artifact→HIR；伪代码文本仅展示。需确定支持的 IDA SDK/Hex-Rays 版本与运行方式。 | **OPEN_QUESTION** 待批准 |
| ADR-004 / Proposed | **SOURCE_CONFIRMED** `p7_acquire.py` 已按函数写 CIR，但固定路径、无通用 manifest/原子 publish。 | **RECOMMENDATION** module 元数据 + per-function source/HIR/CIR/provenance chunks；内容 hash、函数依赖 DAG、staging/原子发布、lease/恢复。备选整模块 artifact，增量成本较高。 | **OPEN_QUESTION** 待批准 |
| ADR-005 / Proposed | **REQUIREMENT** 后续清理旧 tests/scripts；**SOURCE_CONFIRMED** CLI/solver 仍调用 scripts，tests 含语义 fixtures。 | **RECOMMENDATION** 先迁移生产能力，再删历史套件，建立全新契约/语义/差分/端到端验证。备选永久无自动化验证须记录风险。 | **OPEN_QUESTION** 待批准 |
| ADR-006 / Proposed | **SOURCE_CONFIRMED** distribution 名 `binaryanalysis`，import 包 `emtaint`，`setup.py` 又用 `emtaint` distribution。 | **RECOMMENDATION** 先保留 import 路径并统一包元数据，确定兼容窗口；备选立即改名。 | **OPEN_QUESTION** 待批准 |
| ADR-007 / Proposed | **SOURCE_CONFIRMED** 无生产 Microcode exporter；CTree 和 VEX 也未建立交叉证据。 | **RECOMMENDATION** 先冻结 Microcode adapter/provenance 契约，待首个 CTree 纵向切片后实现。备选并行实现但会增加未稳定契约风险。 | **OPEN_QUESTION** 待批准 |
| ADR-008 / Proposed | **SOURCE_CONFIRMED** `Origin`/`ProvenanceIndex` 无完整多对多跨表示关系。 | **RECOMMENDATION** 独立版本化 provenance graph、源/目标命名空间、映射方法/完整度/冲突/置信标签；不按 EA 近邻自动配对。 | **OPEN_QUESTION** 待批准 |
| ADR-009 / Proposed | **SOURCE_CONFIRMED** `p7_legacy_reference.py` 是 CLI legacy backend，`process_port.py` 执行 script worker。 | **RECOMMENDATION** 决定 legacy 模式存续与迁移期；solver worker 若保留必须进入正式 package。 | **OPEN_QUESTION** 待批准 |
| ADR-010 / Proposed | **SOURCE_CONFIRMED** `FunctionStore` 的读取/补边和 `CIRModule.memory_snapshots` 混合 acquisition 与分析。 | **RECOMMENDATION** 分离输入 artifact、分析结果、缓存索引、debug/evidence；变更 provenance/语义依赖时选择性失效。 | **OPEN_QUESTION** 待批准 |

在上述核心身份、IR、artifact 决策获批准之前，不进入实现或仓库清理。
