# 当前目标环境决策（2026-10-28）

用户在上一轮 angr 10.0.5 原生求解故障后，已自行将目标 `BinaryAnalysis/.venv` 更换为 **angr 9.3.4**，并明确要求先执行 P0-B v5 补采，再完成 P1。此最新指令优先于三份 v5 规划文档中尚保留的 10.0.5 版本假设；本轮不安装或调整包，也不覆盖用户对规划文档的其他修改。

实际安装元数据已核实：

| 位置 | Python | angr/claripy/pyvex/cle/archinfo | z3-solver | Claripy 入口 |
|---|---|---|---|---|
| 旧 `EmTaint/.venv` | 3.7.2 | angr 等 9.0.9792；Claripy 含本地 Load/Store 扩展 | 4.13.3 | `import claripy` |
| 目标 `BinaryAnalysis/.venv` | 3.12.9 | 9.3.4 | 4.13.0.0 | `import claripy` |

旧、新解释器仍固定为各自 `.venv/Scripts/python.exe` 的绝对路径。旧分析继续仅使用旧解释器、在独立物理 RunRoot 运行；目标 9.3.4 不替代旧 Golden 的解释器。

先前 10.0.5 的 CRASH、DLL ordinal 线索、失败 manifest 和原始证据属于历史记录，不改标、不覆盖。本轮将从用户更新后的目标环境开始重新记录内容/mtime 清单；不得将用户已经完成的依赖变更归因于代理，也不得声称目标环境从旧的 10.0.5 会话以来没有变化。

此文件只更新运行版本决策，不改变 Python 保真优先、P3/P5 内存架构或 Gate M，不授权额外 Rust 工作。P0-B v5 与新的 P1 实测结果分别记录在对应阶段报告。
