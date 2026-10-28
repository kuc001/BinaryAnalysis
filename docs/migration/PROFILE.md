# P0-B 隔离 profile：实测结果

本页保留首次采集的历史失败数据。**当前通过 Gate 的新采集为 `20261028T051055Z-96d1c781`，新墙钟、worker 内存与热点见 [P0-B 重采报告](phases/P0-B-recapture-report.md)。** 两轮数据不拼接，不据其差值推导算法加速。

采集 ID：`20261028T034805Z-b5b6f765`。原始数据位于共同父目录的 `baselines/rv130_1_0_3_44/<ID>/profile/`，使用第三份独立物理副本，先 `-i` 后 `-t`。没有修改旧算法源码或关闭调试输出。**最终完整性 Gate 失败：旧依赖 parsetab.py 的 mtime 被加载期写入改变，见 INTEGRITY_INCIDENT.md。本轮 profile 和快照仅为待审证据，不是通过 Gate 的 Golden。**

## 墙钟与旧内部计时

| 运行 | -i 墙钟秒 | -t 墙钟秒 | icall.time | taint_1.time |
|---|---:|---:|---:|---:|
| 普通首轮 | 48.491 | 83.033 | 37.497020 | 60.276383 |
| 独立重复 | 65.788 | 72.672 | 48.401976 | 48.597906 |
| 独立 cProfile | 81.456 | 158.459 | 64.113561 | 148.703821 |

六个 CLI 均退出 0。profile 结果与普通首轮、独立重复及历史结果逐字段比较，没有非计时差异；目标文件在各轮均相同。普通轮时间已有明显波动，本数据用于定位候选热点，不是算法加速/退化结论。两普通轮不足以建立稳健的性能分布。

cProfile 的 total_tt：`-i` 79.969 秒，73,236,214 次调用；`-t` 154.967 秒，157,974,977 次调用。profile 包括导入、日志/IO 和原生调用等待，不能当作纯 Python CPU 时间。以下 cumulative 时间互相包含，不能相加。

## -i 的主要证据

| 函数 | 调用次数 | exclusive 秒 | cumulative 秒 |
|---|---:|---:|---:|
| FunctionAttribute.__eq__ | 17,271,435 | 8.444 | 10.361 |
| CallGraph.get_pre_sequence_call_graph | 97 | 4.636 | 15.179 |
| EngineVEX.execute_block_irsb_v4 | 9,301 | 1.078 | 19.985 |
| FunctionCFG._block_sclicing | 4,449 | 0.114 | 7.821 |
| Collector.read_recursive_data | 21 | 0.060 | 3.886 |
| Claripy AST.replace | 10,499 | 0.031 | 2.924 |
| FastDataFlow.execute_loop | 146 | 0.039 | 0.961 |

调用图预序中的多处 list 成员判断（`call_graph.py:140/205/206` 等）与大量 FunctionAttribute.__eq__ 是一个应优先检查的 Python 候选。需要后续通过 caller 明细、characterization 和差分验证因果及改进效果；本阶段不把 list 换成 set，也不改变顺序。

## -t 的主要证据

| 函数 | 调用次数 | exclusive 秒 | cumulative 秒 |
|---|---:|---:|---:|
| EngineVEX.execute_block_irsb_v4 | 21,799 | 1.753 | 35.000 |
| FastSearch._merge_block_exprs | 77,609 | 3.930 | 19.185 |
| Claripy AST.__new__ | 231,125（含递归） | 3.727 | 14.978 |
| AccurateDataFlow.forward_data_trace2 | 20,680 | 0.650 | 13.010 |
| AccurateDataFlow.backward_data_trace2 | 19,094 | 0.473 | 4.810 |
| VarExpr.replace | 16,129 | 0.425 | 4.302 |
| CFGBlock.__eq__ | 10,568,326 | 4.590 | 5.621 |

由此可以支持后续优先保护/验证 VEX Action 预处理、块事实合并、表达式身份与替换契约。它不支持“全部时间都在 SSE”或“换成 Rust 就会取得固定倍数收益”的判断。当前版本继续保留 Python 算法。

## 覆盖与限制

- 当前样本、当前 dirty 源码、当前 iCall seed 的 warm-start 顺序；没有冷启动清空 iCall。
- profile 与两普通轮的统计/告警/完整 iCall 关联一致，但原 JSON 没有完整 CFG/CG/SSE/alias/source→sink/guard 证据，不能声称全事实图等价。
- cProfile 是 instrumentation 后结果，调用次数和耗时可能受到宿主调度、缓存、导入以及原调试打印影响。
- 本次 psutil 的约 4.8–4.9 MB 只测到 `Popen` 启动进程。Windows venv worker 未被完整覆盖，**不是实际分析内存峰值**。实际进程树峰值记为 unavailable，不据此作内存比较。
- 没有统一的 unsupported、unknown、timeout 计数；未统计不等于 0。日志可见 loader 符号大小警告，不能当作新旧语义差异。
- 两个环境、算法、依赖均不修改；目标 Claripy 求解器的原生崩溃仍留待 P1。

## 复查方式

用目标解释器的 `pstats.Stats` 读取归档 `.prof`；完整 top-50 cumulative/exclusive 和模块 exclusive 汇总已保存为 `*-profile.json`。`validation-v2.json` 保存选定函数和最终严格差分；`collection-tooling/` 保留实际采集时的脚本版本，之后比较器增加了有序嵌套列表的类型检查测试，未重写原始输出。
