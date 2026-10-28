# 当前迁移策略（2026-10-28）

用户确认：短期保留 Python 算法，优先复现 EmTaint 语义；中期再评估 Canonical IR、SSE 和数据流核心的 Rust 迁移；长期由 Python 对接 angr/IDA/LLM 与编排，Rust 承担主要计算。

当前版本不实施直接 Rust 迁移。本轮范围仅 P0-B：已有结果归档、独立物理副本中的旧版 `-i → -t`、重复性比较、独立 cProfile 和测量报告。不得将 profile 差异当作算法变更，不修改两个环境或旧算法。

下一阶段仍按 P1 的 Python/angr 10 兼容性边界执行；是否调整后续语言实现，另作阶段评审。
