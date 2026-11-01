# MIGRATION_BLUEPRINT.md — BinaryAnalysis Python P7 污点分析与漏洞检测收敛方案

版本 v8.0。当前 P6 iCall/CG 已通过；P7 污点分析与漏洞检测尚未通过。本次只完成 Python 重构至 P7，Rust、Microcode、P8+ 全部延期。

## 1. 目标与非目标

目标：在已通过的 P6 CG 上恢复旧 EmTaint `-t` 的实际语义：
- Source/Sink/Sanitizer/Validator/Guard/LengthCheck；
- 寄存器、临时变量、算术/cast、栈、堆、全局内存传播；
- Load/Store、APG、AbstractHeap、MemoryVersion、Alias；
- caller 参数→callee 形参、callee 返回值→caller、callee 内存副作用→caller；
- ProcedureSummary 和旧 `_update_expr_from_callees` 语义；
- 旧版已有的缓冲区溢出、命令注入等漏洞规则；
- 可追溯 TaintPath、Finding、约束和 JSON。

非目标：重做 P0–P6、Rust 化、新增无旧版依据的漏洞规则、大规模重构无关模块、仅以告警数量相等判断保真。

## 2. 冻结 P6

记录 P6 通过时 commit、iCall callsite→target、CG 边、函数可达性、378 项回归清单/报告、输入二进制 SHA256、IDA 元数据身份、CIR/Schema、配置和 P7 当前输出。
默认冻结 P6 的 iCall 目标、CG 边、寄存器 clobber/version 和图更新逻辑。若证明 P6 是 P7 差异根因，必须提供最小复现、首次分歧、影响范围、独立回归，并单独修复和重跑受影响 P6 测试。
旧 Golden 标注 `legacy_taint_confirmed`、`preexisting_unclassified` 或 `new_engine_current`。来源不明 JSON 不得冒充旧版 `-t` 真值。旧仓库只读，旧版重跑仅在批准的隔离副本执行。

## 3. 将 P7 拆成 8 个可验收子阶段

| 子阶段 | 范围 | 交付 | 通过条件 |
|---|---|---|---|
| P7.0 | 冻结基线和语义盘点 | P6 manifest、旧 -t 规则映射、差异清单 | 基线身份可信 |
| P7.1 | Source/Sink 识别与绑定 | Source/Sink registry、参数位置映射 | 规则有旧代码证据 |
| P7.2 | 函数内 TaintFact/Transfer | Fact、传播边、寄存器/栈/算术传播 | 关键函数内传播可对照 |
| P7.3 | 内存污点传播 | Load/Store、APG、MemoryVersion、Alias 事实 | 写后读和内存来源可解释 |
| P7.4 | 跨函数传播 | 参数/返回值/内存效果/summary | 旧 `_update_expr_from_callees` 语义映射 |
| P7.5 | Sanitizer/Validator/Guard/Length | 条件传播和路径过滤事实 | 不误杀/漏掉旧版路径 |
| P7.6 | Sink 与漏洞规则 | Candidate/Confirmed/Rejected Finding | 规则独立且证据完整 |
| P7.7 | 真实目标差分与回归 | `-t` 逐证据对照、378 项回归、Gate 报告 | P7-A/B/C/D 全通过 |

允许 Codex 在一个子阶段内连续分析和修改，但必须逐子阶段留报告。不能把所有问题混成一次大改。

## 4. 旧版语义还原矩阵（先于算法修改）

从旧版 `main.py -t` 的真实调用链静态追踪：
- Source 定义、初始化和寄存器/参数/内存绑定；
- Sink 识别及参数/操作数位置；
- taint kind 的定义、合并和清除；
- VarExpr/TraceExpr/SimAction/RecursiveExpr 如何携带污点；
- FastDataFlow 与 AccurateDataFlow 在 `-t` 中的实际分工；
- Load/Store、APG、MemoryVersion、Alias 如何影响污点读写；
- 参数、返回值、全局变量、堆对象如何跨函数传播；
- `_update_expr_from_callees` 如何更新 caller 表达式；
- ProcedureSummary 的库函数副作用；
- Sanitizer/Guard/LengthCheck 如何阻断或约束传播；
- SecurityCheck 如何从传播事实得到漏洞结论；
- JSON schema、字段、去重和状态。

输出 `legacy path/symbol/branch → semantic rule → new module/API → fixture → target evidence → status`。不能仅按函数名推断规则。

## 5. 目标模块职责（按需创建，禁止空壳）

```text
emtaint/analysis/taint/
  source.py          # Source 规则和初始化
  sink.py            # Sink 识别和参数绑定
  sanitizer.py       # Sanitizer/Validator/Guard/LengthCheck
  facts.py           # TaintFact/PropagationEdge
  transfer.py        # 函数内 transfer
  interprocedural.py # 参数/返回值/内存跨函数传播
  worklist.py        # 去重、调度、预算和收敛
  engine.py          # Taint pipeline

emtaint/analysis/bugfinder/
  rules.py
  buffer_overflow.py
  command_injection.py
  evidence.py
  engine.py

emtaint/procedures/registry.py
emtaint/results/finding.py
emtaint/results/serializer.py
emtaint/orchestration/taint_pipeline.py
```

必须融入项目现有的类型和模块，不得为照抄示例重复建立 ID、Context 或 Memory 类型。

## 6. 关键数据契约

**Source**：稳定 ID、函数/程序位置、来源类型（参数/返回值/内存/外部输入）、ValueID/Location/APG、taint kind、context、guard、origin、规则来源和置信状态。必须迁移旧版真实规则，不能只按函数名猜测。

**Sink**：ID、callsite、函数/地址、API/操作类型、参数索引或内存区域、漏洞类型、长度/约束条件和 provenance。命令注入与缓冲区溢出必须分别判定。

**Sanitizer/Validator/Guard/LengthCheck**：分别表达内容净化、格式/范围验证、路径可达性、长度约束和未知检查。未知检查不得默认安全。每条规则说明作用值、taint kind、参数、上下文和条件。

**TaintFact**：使用项目已有 ID 类型，引用 source、value/access_path/APG、memory_version、program_point、function/context、taint kind、guard、前驱事实、certainty、completeness、origin。不要复制整棵 Claripy AST。

**Finding**：rule/type、source、sink、参数位置、传播路径、调用链、APG/MemoryVersion/Alias 证据、guard、sanitizer/length-check 结果、solver 状态、candidate/confirmed/unknown/incomplete、原始地址和二进制身份。

MayAlias/MayTaint 只能形成候选，不能直接作为已确认漏洞。

## 7. 传播和跨函数语义

逐条核对旧版并迁移：
- Register/Temporary assignment；
- Arithmetic/bitvector/cast；
- Register clobber/version；
- Stack argument/local；
- Load/Store；
- Heap/Global；
- caller argument→callee parameter；
- callee return→caller destination；
- callee memory side effect→caller；
- ProcedureSummary；
- Unknown external call；
- Sanitizer/Guard/LengthCheck。

分析层只通过 CIR、SSE DAG、MemoryQueryPort 和已通过的 P6 CG 查询，不得直接检查 pyvex/angr/Claripy 原生 AST。

跨函数摘要至少表达 parameter-to-return、parameter-to-parameter、parameter-to-memory、memory-to-return、global/heap effects、sanitizer effects、guard requirements、unknown effects。缓存键包含 FunctionID、上下文、summary revision 和相关 Memory/CG revision。优先迁移旧 `_update_expr_from_callees` 的真实语义，不得用通用摘要删除旧版特殊处理。

## 8. 端到端流程

```text
Frozen P6 CG
  → Source Discovery
  → Initial Taint Facts
  → Intra-procedural Transfer
  → MemoryQueryPort / APG / MemoryVersion
  → Interprocedural Summary & Call Propagation
  → Sanitizer / Validator / Guard / Length Checks
  → Sink Matching
  → Candidate Finding
  → Demand-driven Alias / Solver Refinement
  → Confirmed / Candidate / Unknown / Incomplete
  → Evidence & JSON
```

污点到达 Sink 只是候选，必须检查路径、参数位置、长度、约束和 sanitizer。

## 9. P7 Gate 验收

- **P7-A 规则映射**：旧版 Source/Sink/Sanitizer/Guard/ProcedureSummary 均有映射状态；未迁移项有明确原因。
- **P7-B 传播保真**：Source 初始事实和关键传播边无不可解释丢失；内存及跨函数传播正确；sanitizer/guard 未被忽略或过度应用；unknown 显式报告。
- **P7-C 漏洞结果**：旧版确认 Finding 逐项对照；差异有证据和根因；MayAlias/MayTaint 不直接升级为 Confirmed；Source→Sink、约束、参数和漏洞类型正确；JSON 证据完整。
- **P7-D 回归稳定性**：保留 378 项既有回归、不降低断言；相关专项回归通过；P6 iCall/CG 不回退；预算耗尽不产生“无漏洞”结论。

只有 A/B/C/D 全部满足才允许标记 P7 通过。Golden 不完整时明确标记条件性验收，不伪称完全保真。

## 10. 报告
更新 `docs/migration/phases/P7-report.md`：P6 冻结版本、输入/Golden 身份、旧→新规则映射、差异矩阵、首次分歧、修复、测试命令/退出码、Finding 逐项对照、Unknown/Unsupported/Incomplete/Timeout、性能和回退。未执行的测试标记未执行。
