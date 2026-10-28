# P0-B 重采报告：PLY 隔离验证与可复现基线

日期：2026-10-28（Asia/Shanghai）。**本次 P0-B Gate：PASS。** 独立验证和新目录重采均退出 0；通过范围是当前样本、当前 dirty 源码与既存 iCall seed 的可观察结果基线。未执行 P1，未改分析算法或两个环境，未实施 Rust 迁移。

## 证据位置与阶段边界

共同父目录固定为 `D:\works\dataflow\EmTaint\emtaint-migration`，旧仓库为其 `EmTaint` 子目录，目标为 `BinaryAnalysis`；不使用外层同名目录。

| 证据 | run ID / 状态 |
|---|---|
| 历史首次采集 | `20261028T034805Z-b5b6f765` / `legacy_integrity_failure`，保持原样 |
| 首次受控隔离验证 | `20261028T050103Z-7d878e7a` / `failed`，位置参数检查拒绝，旧仓库未变，未执行分析 |
| 修正后的独立隔离验证 | `20261028T050809Z-19845bc5` / `isolation_validated`，退出 0 |
| **本次新目录完整重采** | **`20261028T051055Z-96d1c781` / `collected`，退出 0** |

```text
BASELINE = D:\works\dataflow\EmTaint\emtaint-migration\baselines\rv130_1_0_3_44\20261028T051055Z-96d1c781
WORK     = D:\works\dataflow\EmTaint\emtaint-migration\baseline-work\rv130_1_0_3_44\20261028T051055Z-96d1c781
LEGACY   = D:\works\dataflow\EmTaint\emtaint-migration\EmTaint
TARGET   = D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis
```

新基线内 `manifest.json`、`isolation-proof.json`、`validation-summary.json`、`artifact-index.json` 为主要入口。`verify-recapture.py` 保存本次验收程序；它只读原始产物，使用 exclusive create 新建验收 sidecar。原始日志、JSON、profile、失败 manifest 均未覆盖。

旧 Git base：`72a9e3081632b2f9d1881141bc7b0d43c7158033`；目标 Git base：`3c718ca3d912aad6090cbf0ecd33461bd30b51ec`。旧工作树原有两项修改和一项未跟踪结果均保留，diff 与状态归档。目标仍为原分支的辅助文件修改，未创建提交或 push。

## PLY 写表隔离的实证

旧 angr 的 `sim_type.py:1616` 调用 PLY yacc，默认允许写表；`-B` 不能阻止显式生成 parsetab.py。修复仅存在于目标辅助脚本，并被物理复制至各 RunRoot，详见 [PLY_ISOLATION.md](../PLY_ISOLATION.md)。

1. 在两个独立副本中分别执行重定向写表与禁写表 probe，均先安装 Python 写入 guard，再导入 angr。前者只写副本私有 cache，正式分析只允许后者。
2. 两模式的四类类型解析、完整 typedef/struct/function AST 以及 parameter parser action/goto 表完全一致。表契约 SHA256：`90aa3c0f426412a53f394361288ae3f4f8f80b9cfc8cf50389771a568ecb6960`。
3. 重定向生成的 parsetab.py 与旧表内容哈希相同：`fe2bda1b1cefee26f5401ca231fc7cf1440b6c7961015424cc1c9dbb4f53584f`。禁写表 probe 的 cache 为空。
4. 本次完整采集再次验证相同契约。全部 11 份 bootstrap 报告均 `ok=true`、`violations=[]`，禁写表调用未在 cache 生成 `.py/.pyc/.out`。
5. 两个 probe、三次旧环境元数据命令、六次 CLI 后均全量重读旧仓库哈希、mtime 和 Git 状态；11 个逐步 checkpoint 全部通过。最终 before/after 的 **13,461 个文件记录完全相等**，包括 `.git`、`.venv`、历史结果、IDA 元数据与固件。

本次 bootstrap SHA256：`fb09560605c1ebc4dc3a8a278740f77ed0e41dfc65b07012ab7ee29bd6427729`。正式执行要求隔离证明与当前 helper 哈希匹配。Python guard 不构成任意原生代码的 OS 沙箱；本结论由实际契约、禁止写入记录和完整性校验共同支持。没有恢复首次事件改变的旧 mtime；本次不变性相对本次开始状态成立。

## 命令、环境与测试

从 TARGET 执行：

```powershell
# 独立验证，退出 0
& 'D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis\scripts\legacy_baseline.ps1' -Execute -ValidateIsolationOnly
# 新目录完整采集，退出 0
& 'D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis\scripts\legacy_baseline.ps1' -Execute -Profile -Repetitions 2
# 目标环境回归测试，25/25 通过，退出 0
& 'D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis\.venv\Scripts\python.exe' -B -m unittest discover -s tests -v
# 采集完成后的独立产物验收，退出 0；新建 sidecar，不能重复覆盖
& 'D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis\.venv\Scripts\python.exe' -B '..\baselines\rv130_1_0_3_44\20261028T051055Z-96d1c781\verify-recapture.py'
```

回归测试在独立验证前完成，25 项覆盖严格结果差分、类型/有序证据、目标丢失/重复、原始 JSON 保留、拒绝覆盖归档、RunRoot 范围、隔离证明哈希、显式位置参数、grammar/start/optimize 保留、禁止越界写入和同内容 mtime 变化。无跳过项；测试输出在本次会话控制台。最终独立验收读取两个 `.prof`，核对六次结果哈希、11 个 checkpoint、11 个 bootstrap 报告和目标文件一致性。

补充只读复核退出 0：重新从原始快照计算 staged comparison 并与归档比较一致；artifact-index 中 109 个文件的大小与 SHA256 全部通过；辅助脚本/测试 AST、辅助文件/迁移文档尾随空白检查通过；`git diff --check` 和目标 `emtaint/` 无修改检查通过。旧 Git 状态仍为采集前已有的三项记录。

实际旧调用始终使用 `D:\works\dataflow\EmTaint\emtaint-migration\EmTaint\.venv\Scripts\python.exe -B <RunRoot>\_p0b_bootstrap.py`。bootstrap 的参数、CWD、profile 输出路径与完整命令逐条保存于 `.command.json`。内部原 `main.py` argv 为：

```text
main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -i
main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -t
```

两普通副本及 profile 副本各物理复制 416 个文件，验证内容哈希、非 samefile、链接数为 1；不复制 `.git/.venv/__pycache__`，不更改旧源码。每份都按 `-i → -t` 顺序运行，阶段后立即快照。stdout/stderr 原样保留，不关闭旧调试打印。

两个解释器各自归档模块来源、sys.path、pip freeze/check：旧 Python 3.7.2 + angr/pyvex/cle/archinfo 9.0.9792 + Z3 4.13.3；目标 Python 3.12.9 + 对应包 10.0.5 + Z3 5.3.1。两环境 pip check 均退出 0。旧环境版本探测和 pip 元数据调用也走相同禁写表 bootstrap；没有裸导入旧 angr，没有安装或更新依赖。

## 结果差分与哈希

| 比较 | 非计时差异 | 仅集合顺序差异 | 计时差异 |
|---|---:|---:|---|
| reference → repeat-01，iCall | 0 | 0 | `/icall/time` |
| reference → repeat-01，Taint | 0 | 0 | `/icall/time`、`/taint_1/time` |
| reference → profile，iCall | 0 | 0 | `/icall/time` |
| reference → profile，Taint | 0 | 0 | `/icall/time`、`/taint_1/time` |
| 历史已有 JSON → reference 最终结果 | 0 | 0 | 上述两项 |
| 历史失败采集 reference → 本次 reference | 0 | 0 | iCall 一项、Taint 两项 |

六份目标文件完全一致，包括每个函数、调用点和目标；无新增/丢失/重排。结果比较覆盖完整告警字典、地址、函数、name、offset、info、sink_info 及其他原字段，没有只比较数量。`info` 保持有序；未删除或去重任何证据。

| 指标 | 本次结果 |
|---|---:|
| iCall 恢复 / 总数 | 14 / 17 |
| 目标函数字典 / 调用点 | 10 / 14 |
| 目标关联 / 不同目标 | 535 / 475 |
| Taint 分析函数 / 总函数 | 796 / 881 |
| 全部块 / tainted blocks | 30,919 / 4,584 |
| tainted sinks | 402 |
| 缓冲区类告警 / 命令执行告警 | 143 / 7 |

```text
binary          334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787
preexisting     972eb7b7c9e38b3ab9862b7f6f8aaa44aa6a43929a48cd4d231703a33a6d1f1c
reference -i    a4935cac6bfdec8f0daa01abee9a1aa4dd8a3ee5e4e0b0d214a059645d2e24fc
reference -t    5e7e0c56a1e88ad666e25115f77e94dcd92e50ea17038a2cf1588ad0dfbff55c
all targets     3ce126b46a43e6563277a7ecf7f309c075602a240ddb46990c1f4ddb71de1a6c
manifest        c7f146cf5e78a1e65b5a56e32dfbf84f5b63b589774539879ca01d57e1e2c95c
```

`-i` 快照带有 seed 中原有 `taint_1`，该阶段只重算 icall；本次重算的 taint_1 在 `-t` 快照。计时变化导致结果文件 SHA 不同，不代表告警变化。历史 JSON 没有被改标为分阶段 Golden。

## 新 profile 与内存口径

| 运行 | -i 墙钟秒 | -t 墙钟秒 | icall.time | taint_1.time | -i worker peak MiB | -t worker peak MiB |
|---|---:|---:|---:|---:|---:|---:|
| reference | 17.887 | 94.722 | 12.510653 | 85.036525 | 471.29 | 845.24 |
| repeat-01 | 17.894 | 87.872 | 12.116499 | 74.200955 | 470.86 | 843.91 |
| cProfile | 44.836 | 108.205 | 37.430075 | 89.687104 | 495.66 | 869.99 |

cProfile total_tt：iCall **42.463 秒 / 73,139,623 次调用**；Taint **102.457 秒 / 157,877,117 次调用**。profile 包裹 main.py，含其导入、原日志及 IO；父进程墙钟还含 bootstrap 安装。计时不是纯 Python CPU 时间，以下 cumulative 行互相包含，不能相加。

| 阶段 / 函数 | 调用数（含递归） | exclusive 秒 | cumulative 秒 |
|---|---:|---:|---:|
| iCall / EngineVEX.execute_block_irsb_v4 | 9,301 | 0.534 | 10.584 |
| iCall / Collector.read_recursive_data | 21 | 0.099 | 7.059 |
| iCall / Claripy AST.__new__ | 97,186 | 1.432 | 6.608 |
| iCall / Claripy AST.replace | 10,499 | 0.052 | 5.361 |
| iCall / CallGraph.get_pre_sequence_call_graph | 97 | 1.501 | 5.100 |
| iCall / FunctionAttribute.__eq__ | 17,271,435 | 2.848 | 3.544 |
| iCall / FastDataFlow.execute_loop | 146 | 0.026 | 0.696 |
| Taint / EngineVEX.execute_block_irsb_v4 | 21,799 | 0.913 | 18.469 |
| Taint / CallGraph.get_pre_sequence_call_graph | 97 | 3.944 | 12.939 |
| Taint / FastSearch._merge_block_exprs | 77,609 | 2.088 | 10.489 |
| Taint / FunctionAttribute.__eq__ | 17,273,832 | 7.097 | 8.862 |
| Taint / Claripy AST.__new__ | 231,125 | 1.899 | 7.883 |
| Taint / AccurateDataFlow.forward_data_trace2 | 20,680 | 0.296 | 6.360 |
| Taint / AccurateDataFlow.backward_data_trace2 | 19,094 | 0.245 | 2.728 |
| Taint / VarExpr.replace | 16,129 | 0.231 | 2.259 |
| Taint / FastDataFlow.execute_loop | 410 | 0.042 | 1.266 |

可据此确定后续 Python characterization 的优先点：调用图预序与成员判断、VEX Action 预处理、块表达式合并、AST 身份与替换、前后向数据流。当前不替换数据结构、不调整顺序或缓存，也不推导 Rust 固定加速倍数。旧失败 profile 保留在 [PROFILE.md](../PROFILE.md)，不与新数据拼接或作算法提速对比。

内存由实际分析 worker 内部的 Windows GetProcessMemoryInfo 读取 kernel peak working set，记录 PID；不再把约 5 MB 的 Popen 启动器指标当分析峰值。该值覆盖一个 worker，整个进程树聚合峰值仍不可用。

## 修改文件、覆盖限制与回退

辅助工具：`scripts/legacy_baseline.ps1`、`legacy_baseline.py`、`legacy_readonly_bootstrap.py`、`baseline_inventory.py`、`compare_baseline.py`；测试：`tests/test_baseline_tools.py`。本次隔离修复主要涉及 collector/bootstrap/inventory/入口及其契约测试，比较器沿用严格字段规则。

文档：本报告、`PLY_ISOLATION.md`、`INTEGRITY_INCIDENT.md`、`INVENTORY.md`、`LEGACY_CLI_CONTRACT.md`、`BASELINE_SCHEMA.md`，以及历史报告/profile 的新报告索引。`API_COMPAT_MATRIX.md` 与 `STRATEGY.md` 继续保留当前 Python 优先策略和已知兼容性事实。目标业务 `emtaint/`、旧业务代码及两个虚拟环境均未改。

- 本次是 warm-start：已有 dirty 工作树和 iCall seed。14/17 不能解释为从空 seed 独立发现 14 个调用点。
- 原 JSON 没有完整 CFG/CG/SSE/alias/source→sink/guard 事实，不能声称全部图/路径等价。日志和元数据已保留，完整逐事实导出留到后续相应阶段。
- opcode histogram、unsupported/unknown/solver timeout 总数和语义完整性百分比不可用；没有统一统计分母，不能填 0 或 100%。796/881 仅是函数分析覆盖，不能替代语义完整性。
- 143/7 是旧分析报告的 finding，不是已确认真阳性；本次没有新增漏洞验证。
- 两普通轮不足以建立稳健性能分布；调度、缓存、日志和 instrumentation 均影响耗时。
- 目标 Claripy satisfiable 的 P0-A 原生崩溃仍未修复，本次没有重试崩溃路径。目标端到端 iCall/Taint 未执行；不属于本阶段 Gate。

停止使用这些辅助入口即可停止新增运行；所有已生成基线与副本保留。若需回退，由审核者按本报告文件清单撤回目标辅助改动；不自动 reset/clean、不删除运行副本、不恢复旧文件或时间戳。历史失败记录继续为失败，后续采集总是使用新 ID。

## 下一阶段计划（未执行）

P1 先完善 Python/angr 10.0.5 边界：生成实际 API 调用点矩阵，在独立子进程最小复现目标 solver 原生崩溃，再为实际 SSE 操作建立 Claripy adapter 契约，重点覆盖 Load/Store、替换/遍历、annotations、稳定结构身份及 timeout/unknown。旧侧对照仍必须经已验证 bootstrap；不得为适配静默删除表达式或关闭传播。

通过 P1 契约后再进入 Program/Graph、Canonical IR 与旧 Python 数据流迁移。本轮完成 P0-B 后停止，等待阶段审核；当前版本不直接迁移 Rust。
