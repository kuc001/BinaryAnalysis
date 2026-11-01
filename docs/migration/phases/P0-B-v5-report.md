# P0-B v5 表达式规模补采

2026-10-28。Gate：PASS（隔离、观测一致性和已有 JSON 语义范围）。先完成本阶段，再开始用户授权的 P1；未安装依赖、未修改旧仓库或既有 Golden。

新归档：`emtaint-migration/baselines/rv130_1_0_3_44/20261028T074719Z-v5-e10e55ef/`；独立复核见其中 `validation-v5.json`。三份物理副本 control、observed-01、observed-02 均依次运行旧 `-i/-t`，六次退出码全部为 0。当前 dirty tree 和既有 iCall 为 warm-start seed，不是从空缓存重建的基线。旧 Python 3.7.2 / angr 9.0.9792 负责所有固件分析；目标 Python 3.12.9 / angr、Claripy 等 9.3.4 / Z3 4.13.0.0 此阶段仅采元数据。

## 实测规模与查询

以下是观测根的逐项最大值，各列最大值可能来自不同表达式；不是全会话累计唯一分配数。两份观测副本的这些规模和查询计数一致。

| 阶段 / 根 | unique nodes | expanded nodes | AST 深度 | 路径嵌套 Load 数 | 路径嵌套 Load/Store 数 |
|---|---:|---:|---:|---:|---:|
| iCall / ast | 13 | 15 | 8 | 3 | 3 |
| iCall / value | 7 | 7 | 5 | 2 | 2 |
| Taint / ast | 9 | 9 | 5 | 2 | 3 |
| Taint / solver input | 3 | 3 | 2 | 0 | 0 |

iCall：观测范围内公开 Solver 调用和实际 SMT check 均为 0。Taint：546 次公开调用，479 次实际 Z3 check（319 SAT、160 UNSAT，未观测到 UNKNOWN/TIMEOUT）；公开层与 FullFrontend 层合计 1025 条事件，不能相加当作独立查询。缓存等未进入原始 check 的事件单独保留。原始查询日志与状态、parent id 均已归档。

12 个源码指纹绑定的限额/歧义分支中，仅 `dataflow/data_trace.py:4143` 的函数分析次数上限触发 2 次；APTR 深度、别名歧义和循环上限分支命中为 0。分支命中不等于丢失的输出 fact 数，后者为 null。独立原生 fixture 注册全部 12 个 hook，并强制真实 `_find_store_use_v1` 深度保护触发一次，确认观测有效；fixture 计数没有混入固件指标。

本样本实测 AST 较小，不能据此否认其他输入可能爆炸，也不能把合成表达式增长作为本固件实测。全会话唯一 AST 分配、精确 Worklist 迭代、APG/Heap/MemoryVersion 数为 null / 未实现。构造调用数与传播访问数分别记录，不冒充唯一对象或唯一事实。

## 结果与时间

| 副本 | iCall wall 秒 | Taint wall 秒 | iCall worker peak bytes | Taint worker peak bytes |
|---|---:|---:|---:|---:|
| control | 54.186 | 82.025 | 493715456 | 884633600 |
| observed-01 | 105.114 | 261.068 | 494129152 | 886927360 |
| observed-02 | 110.784 | 224.258 | 494383104 | 886943744 |

峰值为实际分析 worker 的内核峰值，不是 venv launcher，也不是进程树之和。观测有明显时间开销，不作为新引擎性能或加速结论；原有成功 profile 保留。

两份 observed 相对 control、control 相对成功 Golden `20261028T051055Z-96d1c781` 均无非计时语义差异。iCall 14/17，535 个目标关联、475 个唯一目标；Taint 30919 blocks、4584 tainted、402 sinks、143 buffer、7 command。现有 JSON 不包含完整 CFG/SSE/Alias/path，不能据此宣称这些内部语义全部等价或 Gate A/M 通过。

## 隔离与复现

先验证 PLY 重定向与禁写模式解析契约一致，再运行副本；工具和 observer SHA 随归档固定。观测仅在副本 bootstrap 注入，未改旧源码。每次旧导入/分析之后核对旧仓库；最终完整清单确认旧目录、目标 `.venv`、全部既有归档内容和 mtime 不变。旧二进制 SHA 为 `334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787`，历史结果 SHA 为 `972eb7b7c9e38b3ab9862b7f6f8aaa44aa6a43929a48cd4d231703a33a6d1f1c`。

命令（从 BinaryAnalysis）：`./.venv/Scripts/python.exe -B scripts/p0b_v5_collect.py --execute`，退出 0；`./.venv/Scripts/python.exe -B scripts/verify_p0b_v5.py ../baselines/rv130_1_0_3_44/20261028T074719Z-v5-e10e55ef`，退出 0、PASS；采集前单元测试 60/60。原生 observer fixture 退出 0、零写入越界。新目录保存原始 JSON、查询日志、命令、stderr/stdout、环境和前后清单、工具快照及独立验证结果。

下一步只做已授权 P1：9.3.4 AST/API 适配、真实 SAT/UNSAT/eval/min/max、UNKNOWN/TIMEOUT 和进程故障边界；内存 marker 保持 UNSUPPORTED，APG/Heap/MemoryVersion 与语义 lowering 留在 P3/P5。Rust、P2 和新固件迁移未执行。

封存后勘误：`load_depth` 是一条 AST 路径上的 Load 数，允许中间有算术节点，并非仅相邻节点。后续工具还修正了 eval/min/max 枚举末次 UNSAT 的分类；本归档 1025 条查询均为 satisfiable，未触发该问题，离线独立校验的状态修正数为 0。封存的原始 observer 与结果保持原 SHA，未重写或重跑。
