# API 兼容矩阵

P0-A 已实测的结果保留在此；P0-B 再次归档两个环境的导入/来源、版本、pip freeze/check，不重复触发已知目标 solver 原生崩溃，也不进行 P1 修复。

| 契约 | 旧环境 | 目标环境 | 状态/后续 |
|---|---|---|---|
| angr/pyvex/cle/archinfo | 9.0.9792 | 10.0.5 | P0-A 实测，P0-B 再采集 |
| Python | 3.7.2 AMD64 | 3.12.9 AMD64 | 两套绝对解释器 |
| Z3 | 4.13.3 | 5.3.1 | 目标安装声明要求 5.3.1.0；不擅自降级 |
| import claripy | 成功 | ModuleNotFoundError | 目标入口原有导入失败 |
| from angr import claripy | ImportError | 成功 | 新模块为 angr.rustylib.claripy |
| BVS/BVV/size/op/args/variables | 通过 | 通过 | 简单表达式探针 |
| ast.Base/BV 类型判断 | 通过 | 通过 | 类型路径不同，不能据此假设语义等价 |
| replace/simplify/Extract/Concat/扩展/ITE | 简单场景通过 | 简单场景通过 | SSE 完整状态契约待 P1/P5 |
| recursive_leaf_asts / recursive_children_asts | 存在 | AttributeError | 需要适配遍历及次序 |
| cache_key | 存在 | AttributeError | 稳定结构身份另建契约 |
| hash / 缓存 | 简单重复稳定 | 简单重复稳定但值不同 | 不跨版本比较裸 hash |
| annotations | tuple | list | 基本 annotate 通过；完整语义未验 |
| 项目 Load/Store | 本机扩展存在且通过 | 不存在 | 旧 bv.py/operations.py 原文及 hash 随基线归档 |
| claripy.operations | 存在 | 不存在 | 原 global_config 等直接依赖 |
| Solver sat/unsat/eval/min/max | 通过，eval tuple | satisfiable 原生退出 0xC0000005 | P0-A 观察；P0-B 不重试、不掩盖 |
| 目标 eval 返回类型 | 不适用 | .pyi 声明 list | 未成功运行验证 |
| timeout 构造 | 通过 | 通过 | timeout/unknown 的运行契约待验 |
| 三个真实 IDA block lifting | 六个 IRSB | 相同六个 IRSB | 仅 smoke，auto_load_libs=False；不是全分析差分 |

P0-B 的 Golden 完全来自旧解释器，不受目标 solver 阻塞。后续当前版本优先 Python 适配层，不实施 Rust PoC。
