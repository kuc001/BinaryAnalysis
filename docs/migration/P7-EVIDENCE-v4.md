# P7 私有证据 v4：全局定义输出审查

范围仅为 P7 摘要与证据 DTO；CIR-Wire-v1、Memory-Semantics-v1 和 P3 公共类型字段不变。v3 历史归档不改写。

旧版依据是 `FastSearch._get_argument_def_exprs` 的整数 `base_ptr` global 导出，以及 `FunctionAttribute.merge_input_global_taints_v1/v2`、`get_global_taints`、`kill_input_global_taints`。`legacy-global-02/report.json` 在旧 Python 3.7.2 中实际执行这些方法，验证 global 导出、去重、iCall 路径记录、按 block 地址取用和覆盖后移除；violations 为空。`legacy-global-01` 的包初始化失败记录保留。该探针不是旧 CLI。

新字段 `TaintProcedureSummary.global_outputs` 使用私有 `GlobalTaintOutput(address, width_bits, endian, span, origin, dependencies)`。span 是起始地址的数量：普通 Store 的 span=1，字节缓冲区的已知长度为 span；未知长度为 null。无 scoped SSE/APG/MemoryVersion ID 跨函数传递。导入时从同一映像地址重新取得稳定 Root，再经 MemoryQueryPort 做实际位置/alias 对照，并物化 caller 作用域的 Source fact。

`legacy-global-03` 还原生验证同一 global AST 的旧 merge；旧版只留下第一条 Source。新摘要对相同地址/宽度/端序/span 采用同样的位置合并边界，但保守保留各已有 Source。origin 是一个实际写入位置的代表，不声称是每条合并依赖的唯一写入证人；逐轮 raw summary 与 Source archive 保留原始证据。该额外 MAY 来源是明确的保守差异。

只枚举实际 Store、原 procedure 写入和实际 callee 输出，并在真实 Return 的截止点查询定义。保留 P5 的强/弱更新及字节覆盖规则；未知目标和超限均显式 incomplete。这里不新增无条件清污点或强更新算法。旧版 global kill 的可用边界由 P5 已验证的确定覆盖与 guard 决定。

参数输出只为实际对应的参数基址导出已知 Source；global 可能别名某参数但没有目的对应证据时保留 unknown，不能把 global 写伪装为所有参数的定义。global 仍通过独立输出传回 caller。P5 对 offset range 保留 MayAlias，即使其记录范围与点地址不同，P7 也不自行宣布 NoAlias；相关结果仍为 uncertain MAY。

global_outputs 的 null 表示该模式没有证据，空数组表示已执行且没有已知导出。v1/v2/v3 reader 将缺失值保留为 null；不能视为 clean。v4 writer 必须输出该字段，reader 严格验证字段和几何、recipe SHA。不同 CIR identity 的摘要累积重新开始，相同 identity 只合并已有 MAY 事实。

P7 候选证据另外区分 callsite_path 与已映射的 inter_functions；未测量的循环/传播/iCall 深度使用 null。Source fact 链接是实际归档事实的索引，不声称已证明完整 caller 投影、路径可达性或漏洞可触发性。
