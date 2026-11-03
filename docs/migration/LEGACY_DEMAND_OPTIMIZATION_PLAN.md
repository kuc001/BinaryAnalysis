# LegacyDemand 优化与替换执行计划

更新日期：2026-11-03（Asia/Shanghai）

## 1. 结论和边界

`LegacyDemand` 继续作为 P6 iCall/CG 的兼容参考实现，不在原类中直接叠加 P7
精度规则。P6 已冻结；任何可能改变 callsite→target、CG、候选枚举或 pending
语义的修改，都必须先有最小复现、首次分歧证据和独立回归。

长期目标不是把 `LegacyDemand` 原地重写成新引擎，而是建立可组合的需求分析
组件，让 P7 的 `ProcedureDemand` 逐步脱离继承。旧实现保留为差分 oracle 和安全
回退路径。

本计划只修改 `BinaryAnalysis/`。`../EmTaint/`、Golden、P6 冻结产物和历史
回放全部只读。工作区中已有的无关修改不得覆盖或回退。

## 2. 已知问题

| ID | 问题 | 风险 | 目标状态 |
|---|---|---|---|
| LD-ARCH-01 | 一个类混合 scalar、register、memory、alias、loop、summary、预算与诊断 | 修改局部规则会改变全链成本或语义 | 按不可变索引、单次查询状态和专用 resolver 拆分 |
| LD-ARCH-02 | `ProcedureDemand` 继承并覆盖 `LegacyDemand` 内部方法 | 父类实现成为未声明协议 | 先建立显式协议，最终改为组合 |
| LD-STATE-01 | steps、active、cycles、notes、rules 等跨查询共享 | 查询顺序影响完成度和预算 | 单次查询结果显式记录状态和成本；保留函数总上限 |
| LD-PERF-01 | register cutoff/reaching 反复扫描 block effects | 大函数重复工作 | 建立不可变 FunctionDemandIndex |
| LD-PERF-02 | memory definition 重复扫描前驱和 Store | memory work 膨胀 | 复用已验证的 DefinitionFrontierCache，只缓存选择前沿 |
| LD-PREC-01 | `local_address` 依赖浅层语法匹配 | 等价地址退化为 MayAlias | 建立 root+affine offset 地址抽象域和证明对象 |
| LD-PREC-02 | 父类只支持完整寄存器写 | 部分寄存器直接 Unknown | 使用切片几何、条件写和 CFG join；P6 行为不变 |
| LD-PREC-03 | guard/path 主要通过值集合合并 | 只适合 MAY，不足以证明 Finding | 把 guard/completeness 作为结果证据携带 |
| LD-LOOP-01 | 单 stride `base+i*stride` 缺少循环身份和边界 | 容易被误投影成具体迭代 | SCC 级摘要和显式 unknown tail |
| LD-TEST-01 | P6 直接单测仅覆盖主要 happy path | 重构缺少语义护栏 | 增加 join、clobber、partial、budget、order、cache 测试 |

## 3. 目标架构

```text
DemandFacade
  ├─ FunctionDemandIndex       # immutable body/CFG index
  ├─ DemandQueryContext        # per-query budget, recursion and diagnostics
  ├─ ScalarResolver
  ├─ RegisterResolver
  ├─ AddressNormalizer
  ├─ MemoryDefinitionResolver
  ├─ LoopSummarizer
  ├─ SummaryResolver
  └─ DemandPolicy
       ├─ LegacyCompatibilityPolicy
       └─ ProcedureTaintPolicy
```

缓存键必须声明 `FunctionID/body identity`、`Context`、runtime/function epoch、相关
`MemoryVersion` 和查询程序点。缓存只保存完成结果；包含 cycle placeholder、预算前沿
或上下文相关地址的结果不得复用。

## 4. 分阶段执行和验收门

### LD0：冻结与表征

- [x] 记录基线 commit：`91575ffee4ff8795d99ae5ac81b6e5ee528622f8`。
- [x] 确认目标文件修改前无工作树差异。
- [x] 运行 `test_p6_demand.py`：7/7，exit 0。
- [x] 运行 `test_p7_demand.py`：40/40，exit 0。
- [x] 增加 register join/clobber、预算 incomplete、缓存身份和查询顺序测试。

通过条件：所有新增测试描述现有保守语义，不使用 Golden 地址，不降低断言。

### LD1：不可变函数索引

- [x] 新增 `FunctionDemandIndex`，索引 value definitions、register events、Store、Call、
  CFG predecessor 和 effect count。
- [x] 索引结果使用只读容器，构建后不得依赖查询可变状态。
- [x] 在 P7 `ProcedureDemand` 中使用索引实现 `definition_cutoff`，P6
  `LegacyDemand` 保持不变。
- [x] 对逐 effect 旧扫描和新索引做等价测试，包括 `*` clobber 和 UnknownEffect。

通过条件：P6/P7 专项结果完全一致；索引查询不调用 MemoryQueryPort，不产生 SSE。

### LD2：显式查询结果与状态隔离

- [x] 新增 `DemandQueryResult(values, completeness, diagnostics, cost)`。
- [x] 新增查询入口，局部捕获 `DemandLimit` 并返回 `INCOMPLETE`，不得返回空集合
  冒充已证明无值。
- [x] 将 recursion/cycle 状态限定到顶层查询生命周期；跨查询只共享完成缓存。
- [x] 保留函数级 global ceiling，并记录 per-query scalar/memory/wall cost。

通过条件：交换独立查询顺序不改变已完成 value 集；预算失败有显式 frontier/reason。

### LD3：无语义变化的性能优化

- [x] 用索引和缓存消除重复 register cutoff/reaching 扫描。
- [x] 将已验证的 `DefinitionFrontierCache` 接到显式 Memory resolver；缓存 Store
  选择，不缓存带实际 load origin/address 的值替换。
- [ ] 缓存键加入 runtime revision、function epoch、MemoryVersion 和 object facts identity。
- [ ] 输出 cache hit/miss、reaching visits、alias 分类和 cutoff reason。当前已提供
  `demand_metrics()` 的 query/cache/frontier 计数；尚未接入已有脏工作区中的 CLI/P7
  manifest，避免覆盖用户修改。

通过条件：目标/unknown/pending 集合不退化；不得通过提高预算取得性能结果。

### LD4：地址和寄存器精度

- [ ] 建立 `AbstractAddress(root, offset, index_terms, provenance, completeness)`。
- [ ] 规范化 COPY/cast、零加法、常量 ADD/SUB、SP/FP/argument root。
- [x] 只有证明 root 和精确 offset 后才允许 MustAlias；其余保持 MAY/Unknown。
- [x] 将 P7 `exact_slice_before` 提炼为 RegisterSlice resolver，支持完整覆盖、不相交、
  部分重叠、条件写和 CFG join。

通过条件：每个新增 MustAlias/NoAlias 都有证明测试；P6 输出不变；真实回放不得丢失
旧 Source/Target。

### LD5：循环与路径证据

- [ ] 以 CFG SCC 标识 recurrence，摘要包含 loop identity、base、stride 和 unknown tail。
- [ ] guard/path condition 随结果传播；join 后只保留各路径真实成立的条件。
- [ ] 旧 `base+i*stride` 只作为 Legacy policy 的兼容投影。

通过条件：非仿射、多 stride、未知基值不产生伪具体地址；预算中断保持 unknown tail。

### LD6：从继承迁移到组合

- [ ] 定义稳定的 resolver/policy Protocol。
- [x] `ProcedureDemand` 先委托组合组件，保留旧方法 facade。当前已委托函数索引、
  query runner、地址证明、寄存器切片和循环摘要；scalar/memory/summary 尚未全部迁移。
- [ ] 按 scalar→register→memory→summary→loop 顺序逐项删除继承依赖。
- [x] `LegacyDemand` 保留只读参考路径，直至所有差分完成。

通过条件：没有调用方依赖父类私有可变状态；类型、缓存依赖和失效条件明确。

### LD7：差分切换和收尾

- [ ] 同一 CIR/CFG/summary 同时运行 legacy 和新引擎。
- [ ] 差异分类为 equivalent、proved refinement、conservative extra、legacy false
  positive、new missing、budget/scheduling。
- [ ] 执行最小专项→P6/P7 子集→完整回归→真实 17 站点回放。
- [ ] 只有全部差异有证据且 P6 冻结哈希不变时，才允许改变默认引擎。

通过条件：P6 17/17 站点、535 targets、2 rounds、0 pending 与冻结产物一致；P7
Unknown/Incomplete 不减少为“安全”；完整回归通过。

## 5. 每轮执行模板

1. 选择一个 `LD-*` Difference ID。
2. 保存修改前输入、首次分歧和成本快照。
3. 增加一个最小失败/表征测试。
4. 只修复一个根因。
5. 运行最小专项和受影响回归。
6. 检查 diff、P6 冻结边界和已有工作树修改。
7. 更新本文件的状态、测试命令、退出码和剩余风险。

连续两轮没有新诊断信息时，改用状态快照、调用栈 profiling、缓存命中统计或缩小
replay；不得继续盲目增加预算或重复全量分析。

## 6. 回退策略

- LD1–LD5 均通过独立模块和 P7 facade 接入；删除该接入即可回到原实现。
- 不迁移或删除 P6 `LegacyDemand`。
- 不修改 wire/schema、Golden、冻结 iCall/CG 和历史结果。
- 出现目标丢失、Unknown 被删除、pending 增加或成本失控时，立即回退本轮接入，保留
  失败快照和测试，不用硬编码地址修补。

## 7. 执行记录

| 日期 | 阶段 | 修改 | 验证 | 状态 |
|---|---|---|---|---|
| 2026-11-03 | LD0 | 创建本计划；确认目标文件干净；记录基线 | P6 demand 7/7；P7 demand 40/40 | 通过 |
| 2026-11-03 | LD1 | 新增只读 FunctionDemandIndex；P7 cutoff/reaching 使用索引；P6 未改 | 新索引 5 项；P6 51 项；P7 219 项 | 通过 |
| 2026-11-03 | LD2 | 新增 DemandQueryResult/Runner；预算失败为 INCOMPLETE+Unknown；cycle 查询隔离 | 查询/顺序/预算专项 3 项；完整回归覆盖 | 通过 |
| 2026-11-03 | LD3 | 增加 query/cache/frontier 指标；沿用 DefinitionFrontierCache | reaching/cache/memory 专项通过 | 部分通过；CLI 输出待接入 |
| 2026-11-03 | LD4 | 抽取 AddressProof normalizer 与 RegisterSliceResolver；保持 facade | address/memory 10 项；intra 11 项 | 部分通过；通用 AbstractAddress 未开始 |
| 2026-11-03 | LD6 | 抽取 LegacyLoopSummarizer，保留原 single-stride 算法和规则标签 | recurrence 1 项；P7 219 项 | 组合迁移部分通过；仍保留继承 |
| 2026-11-03 | 里程碑 | 完整测试与安全审计 | 488 tests，exit 0（最终复跑）；quality audit safety=0；py_compile exit 0 | 通过 |

当前停止点：LD0–LD2 已通过，LD3–LD4 完成无语义变化的安全子集。LD5 的循环/
路径语义和 LD6 的彻底去继承都会改变高风险分析行为，必须先增加真实目标差分快照，
不能仅凭单元测试继续推进。LD7 的真实 17 站点回放及默认引擎切换尚未执行。

