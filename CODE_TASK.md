# CODE_TASK.md — P7 污点分析与漏洞检测：差异驱动收敛手册

版本 v8.0。当前 P6 iCall/CG 已通过；当前唯一目标是完成 Python P7。先读 `AGENTS.md` 与 `MIGRATION_BLUEPRINT.md`。不重做 P0–P6，不推进 Rust/P8。

## 0. 当前会话授权

在 `BinaryAnalysis/` 中分析、修改 P7 代码并运行必要测试，目标是 P7-A/B/C/D 全部通过。
`../EmTaint/` 严格只读。旧版 `-t` 只能在获批隔离副本运行。不得覆盖 Golden、P6 冻结结果或历史报告；不得安装依赖/改变环境。
当前 P6 已通过，不要重新全量重做 P6。若发现 P6 是根因，按 AGENTS 的例外流程单独处理。

## 1. P7 运行方式：子阶段推进，不做无差别全量循环

P7 拆成 P7.0–P7.7：
- P7.0：冻结 P6、验证 Golden 来源、建立差异清单；
- P7.1：Source/Sink 规则及参数绑定；
- P7.2：函数内 TaintFact、寄存器/栈/算术传播；
- P7.3：Load/Store、APG、MemoryVersion、Alias 污点传播；
- P7.4：跨函数参数/返回值/内存副作用和 ProcedureSummary；
- P7.5：Sanitizer/Validator/Guard/LengthCheck；
- P7.6：Sink 与漏洞规则、Finding 证据；
- P7.7：真实目标逐证据差分和完整回归。

每个子阶段只处理其范围，生成简短报告和可回退 checkpoint。一个子阶段通过后再进入下一个；不得一次性大改整个 Taint pipeline。

## 2. Prompt P7.0 — 冻结 P6 和建立差异矩阵

```text
先检查 Git status、当前 commit、P6 通过报告、iCall/CG Golden 和 378 项回归报告。
记录 P6 冻结 commit、callsite→target、CG 边、输入二进制 SHA256、IDA metadata、CIR schema、分析配置和当前 P7 输出。
检查旧版 taint JSON 的来源：legacy_taint_confirmed / preexisting_unclassified / new_engine_current。来源不明不得当旧版 -t 真值。
不要重做 P6，不要在 ../EmTaint 直接运行 -t。
输出 P7 baseline manifest、旧版 -t 调用链和差异矩阵。若缺少可信 Golden，明确列出缺项和最安全的获取方式。
本子阶段只做基线和语义盘点，不大规模修改代码。
```

## 3. Prompt P7.1 — 迁移 Source/Sink 规则

```text
只处理 Source/Sink 识别与绑定。
从旧 main.py -t 真实调用链逐条定位 Source、Sink 的注册、匹配、参数索引、返回值、内存位置、taint kind 和地址条件。
输出 legacy symbol/branch → rule → new API → test → target evidence 映射。
在新代码中实现规则 registry 和稳定 ID；不能只按函数名模糊匹配，不能把任意被污染参数当 Sink。
对每个真实 Source/Sink 建立单元/fixture 和目标差异记录。
完成后停止，不修改传播算法。
```

## 4. Prompt P7.2 — 函数内传播

```text
只处理函数内污点传播。
迁移旧版对寄存器/临时变量赋值、算术/位向量/cast、寄存器 clobber/version、栈参数/局部变量的传播规则。
每条 transfer 说明输入事实、输出事实、kill/gen、guard、origin 和精度状态。
TaintFact 使用稳定 ValueID/ProgramPoint/Context/Guard 引用，不复制完整 AST。
比较旧/新每条关键传播边；先找首次分歧，再修复。增加 clobber、部分寄存器、算术、条件分支和 kill 的最小回归。
完成后停止，不做跨函数或漏洞规则。
```

## 5. Prompt P7.3 — 内存污点传播

```text
只处理内存污点传播。
通过 MemoryQueryPort 使用已验收的 AccessPath/APG/AbstractHeap/MemoryVersion/SSE DAG。
迁移旧版 Load/Store、SimAction、内存 alias、反向需求和 use/def 传播语义。
检查稳定 Root、Deref/Offset、points-to、到达 MemoryDef、部分覆盖、strong/weak update、MayAlias/Unknown。
自定义 Claripy Load/Store 不得直接进入 solver；仅对关键候选执行 SolverLowering。
对每个旧版内存传播例子比较 source location、read/write、alias、MemoryVersion 和 TaintFact。
不能用“未知即全污染”冒充精确实现，也不能把 Unknown 当 NoAlias。
完成后停止。
```

## 6. Prompt P7.4 — 跨函数传播与 ProcedureSummary

```text
只处理跨函数污点传播。
优先按旧源码迁移 `_update_expr_from_callees` 的真实语义，不要先设计通用摘要再猜旧行为。
逐项实现和对照：
1. caller 实参→callee 形参；
2. callee 形参→局部/内存；
3. callee 返回值→caller 接收变量；
4. callee 对 heap/global/pointed memory 的写入→caller；
5. caller/callee 的栈参数和 ABI 寄存器参数；
6. 外部函数和未知调用副作用；
7. 多调用上下文和递归函数摘要。
摘要缓存必须依赖 FunctionID、Context、MemoryVersion/CG revision 和 summary revision。只失效受影响摘要，不全程序清缓存。
建立每条摘要 effect 的旧/新事实对照及最小回归。完成后停止。
```

## 7. Prompt P7.5 — Sanitizer / Validator / Guard / Length

```text
只处理传播约束和过滤。
从旧版 SecurityCheck/Dataflow 逻辑确认 sanitizer、validator、guard、length check 的真实语义。
严格区分内容净化、输入验证、路径条件和长度约束；未知函数不能按名称默认 sanitizer。
验证 guard 是否附着到正确的 TaintFact/PropagationEdge，分支 join 后是否保留条件，跨函数摘要是否正确传递条件。
缓冲区长度与输入长度必须使用正确位宽和有符号/无符号比较。
每个旧版过滤规则至少有正例、反例和未知语义例。完成后停止。
```

## 8. Prompt P7.6 — Sink 与漏洞判定

```text
只处理漏洞规则与 Finding。
逐项迁移旧版缓冲区溢出、命令注入及其他实际存在的规则，不新增无旧版依据的漏洞类别。
每条规则单独定义 source requirement、sink operation、参数位置、长度/约束、guard、sanitizer、alias 和证据要求。
Taint 到达 Sink 先生成 Candidate；满足旧版规则所需路径和约束后才可 Confirmed。
MayAlias/MayTaint/Unknown/Timeout/Incomplete 不能直接变成 Confirmed，也不能当安全。
Finding 必须保存 Source→Sink 传播链、调用链、内存证据、guard/constraint、原始地址和二进制身份。
与旧版逐条比较，不得硬编码目标地址或手工补 JSON。完成后停止。
```

## 9. Prompt P7.7 — 真实目标收敛与 Gate

```text
执行 P7 最终差分。冻结 P6，不修改其已通过行为。
按 Source→初始绑定→传播边→Memory/Alias→Call/Return/Summary→Sanitizer/Guard→Sink→Constraint→Finding→JSON 的顺序比较。
对每个差异定位首次分歧事实；差异要么修复，要么以证据说明是预期 over-approx/precision difference，并标记状态。
运行顺序：最小专项测试 → 受影响的 P6/P7 子集 → 目标 -t 回放 → 378 项完整回归（里程碑时运行，不要每个小改动都跑全量）。
确认 P6 iCall/CG 不回退，Finding 逐项可追溯，预算耗尽标记 incomplete。
只有 P7-A/B/C/D 全部满足才标记 P7 通过；否则列出最小剩余 blocker 和下一项最早分歧。不得推进 P8。
```

## 10. 差异驱动的修复循环（每轮必须执行）

```text
选择一个 Difference ID
  → 导出首次分歧位置的状态快照
  → 比较旧/新输入与中间事实
  → 找到最早不一致 transfer/query/summary/rule
  → 添加最小回归
  → 修复一个根因
  → 跑最小专项回归
  → 跑受影响模块回归
  → 更新差异记录
```

如果两轮都没有新信息：
- 不得再次无差别全量回放；
- 增加 Source/Fact/Edge/Worklist 计数；
- 记录每个函数/站点的耗时和预算消耗；
- 记录 MemoryQuery/Alias/Solver 调用；
- 导出 callsite/function/context/memory state 快照；
- 检查重复事实、缓存命中/失效、summary 重算；
- 缩小到一个 source、一个 sink 或一个传播链。

## 11. P7 验收门槛

**P7-A 规则映射**
- 旧版 Source/Sink/Sanitizer/Guard/ProcedureSummary 全部有映射状态；
- 未迁移项有明确原因和影响范围。

**P7-B 传播保真**
- 已知 Source 的初始事实一致或差异有证据；
- 旧版关键传播边无不可解释丢失；
- 寄存器、栈、内存和跨函数传播正确；
- MemoryVersion/Alias/Guard 状态正确；
- unknown/unsupported/incomplete 显式记录。

**P7-C 漏洞结果**
- 旧版确认 Finding 逐项对照；
- 每项差异有首次分歧和根因；
- MayAlias/MayTaint 不直接升级为 Confirmed；
- Source→Sink、参数位置、路径条件、长度约束和漏洞类型正确；
- JSON 证据完整。

**P7-D 回归稳定性**
- 保留 378 项既有回归，不降低断言；
- P7 专项测试通过；
- P6 iCall/CG 结果不回退；
- 不把预算耗尽、timeout 或 unsupported 报告成无漏洞；
- 重复运行的差异可解释。

只有 P7-A/B/C/D 全部通过才可宣布 P7 完成。Golden 不完整时只能标记条件性验收，不得声称完全复现。

## 12. 资源与运行效率

- 不要每次修改后立即运行全部 378 项；按影响范围分层执行。
- 记录每个 Source/Sink/函数的 facts、unique/reused facts、Worklist pops、重复传播、APG/Heap/SSE 节点、MemoryQuery、Alias、Solver 调用、耗时和 cutoff reason。
- 预算分为 per-site、per-function、global wall-time、scalar、memory、alias、solver；全局上限不可突破。
- 动态公平调度只在成本画像证明存在资源竞争后实施；不得用预算调度替代语义修复。
- 预算不足返回 Unknown/Incomplete，并保存未完成队列；不能输出“无漏洞”。

## 13. 报告
每轮更新 `docs/migration/phases/P7-report.md` 和差异 CSV/JSON。报告本轮目标、Difference ID、首次分歧、根因、修改文件、测试命令/退出码、旧新事实、Finding 差异、预算和精度状态、回退方式、下一轮目标。
