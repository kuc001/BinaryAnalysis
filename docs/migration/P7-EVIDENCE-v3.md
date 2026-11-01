# P7 私有证据 v3 兼容审查

范围：P7 analysis/evidence DTO，**CIR-Wire-v1、Memory-Semantics-v1 和 P3 公共 Schema 不变**。本变更不是 IR/内存效果语义版本变化，不引入 Rust。

真实旧代码依据：`SimProcedure.reg_taint_propagate` 只有在有界 copy 的 buffer 与 length 均被旧 taint 标记时，才设置 `taint_loc` 和 `0x1000`；`Collector.collect_weaks` 再收入 `weaks_copy_length`。无 length taint 仍传播 buffer taint，但不标记该旧 weak site。只有 length taint 的 memcpy 进入 `weaks_only_length`，原 SecurityCheck 不据此新增当前漏洞类别。`_calculate_copy_lenght_constraint` 仅采用 Cons type 4 的非零最小数值。

独立依据：`.p7-work/20261029T074944Z-3a0de46d/legacy-bounded-09` 原生执行上述两方法；`legacy-bounded-10` 再与移植后的纯 policy 和 Cons 规则差分。两个探针均使用旧 Python 3.7.2、旧 Claripy、禁写 PLY、只写新的 P7 目录，非旧 CLI。

v3 增加：

- `TaintDependency.constraint_type`：原 Cons 类型；0 表示未赋予特殊数值约束类型。
- 私有 dependency kind `scalar_argument`：按调用实参的**值**进行 use/def 绑定；与 pointee/buffer argument 分开。
- `SinkRequirement.weak_kind` 和 `length_dependencies`：保留 buffer 与 length 的独立来源。不能用同一条 buffer Source 冒充 tainted length。
- `TaintProcedureSummary.scalar_returns`：值污点的返回投影；`null` 表示该模式无证据，空数组表示模式已执行但没有已知值污点。不能把旧 v1/v2 缺少该字段当成 clean。

兼容边界：v1/v2 历史文件保持原样；reader 继续接受并校验原 recipe SHA。旧 bounded sink 缺少 length 来源时显式生成 unknown，而不伪造 Source 或宣布安全。未知版本拒绝。新 v3 reader/writer 必须 round-trip 新字段并验证空/null 的差别。

检测边界：clean length 不产生旧 bounded weak；unknown length 只作为未完成的条件证据；已知 tainted length 与已知 buffer Source 才进入原 heuristic policy。传播、MAY 与可触发性仍分开，confirmed 保持 false，未知不作为 UNSAT。
