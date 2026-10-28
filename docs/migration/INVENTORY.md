# 本机双仓库清单

共同父目录：`D:\works\dataflow\EmTaint\emtaint-migration`。

| 项目 | 旧仓库（严格只读） | 目标仓库 |
|---|---|---|
| 目录 | `EmTaint` | `BinaryAnalysis` |
| commit | `72a9e3081632b2f9d1881141bc7b0d43c7158033` | `3c718ca3d912aad6090cbf0ecd33461bd30b51ec` |
| 解释器 | `EmTaint\.venv\Scripts\python.exe` | `BinaryAnalysis\.venv\Scripts\python.exe` |
| Python | 3.7.2 / AMD64 / cpython-37 | 3.12.9 / AMD64 / cpython-312 |
| angr/pyvex/cle/archinfo | 9.0.9792 | 10.0.5 |

旧工作树原有：`dataflow/variable_expression.py` 两处调试打印修改，`httpd_icall.json` Git 修改标记，未跟踪的历史结果 JSON。目标原有三份未跟踪约束文档。当前工作树而非纯 HEAD 是基线输入，采集时保存完整 dirty diff、文件清单与 SHA256。

## 已确认的调用链与映射

| 旧模块/符号（行号为本机起始状态） | 作用 | 后续目标职责 |
|---|---|---|
| `main.py:402 perform_analysis` | 配置、CLI、组装分析与结果写入 | orchestration / results |
| `dataflow/ida_process.py:69 IDAProcess` | JSON CFG/CG、iCall/iJmp、地址映射 | IDA metadata reader / graph |
| `dataflow/generate_cfg.py:121 FunctionCFG._block_sclicing` | 二进制字节 → 多个 VEX IRSB | IDA+VEX lifter |
| `dataflow/vex_process.py:907 execute_block_irsb_v4` | VEX → Action / DefUse | frontend lowering / transfer |
| `dataflow/variable_expression.py:872 VarExpr.replace` | AST、sims、SimAction、基指针与上下文更新 | Python SSE domain / solver port |
| `dataflow/parse_ast.py:538 calculate_ast_struct_id` | 结构分类、解引用与偏移 | symbolic / memory domain |
| `dataflow/fast_data_flow.py:321 execute_loop` | 逆向 live-use / DDG / SCC | fast dataflow |
| `dataflow/accurate_data_flow.py:2628/2716` | 前向/后向表达式传播 | accurate dataflow |
| `dataflow/data_trace.py:337/484/5154 FastSearch` | 调度、摘要、跨函数 F/B 传播 | session / passes |
| `dataflow/data_collector.py:363 parse_icall_targets_v1` | 间接目标、静态内存与结果 | controlflow / results |
| `dataflow/security_check.py:33 check_taint_security` | 长度/约束/来源过滤、告警 | Python finding policies |
| `dataflow/procedures` / `global_config.py` | 外部调用摘要、架构与可变全局集合 | procedure registry / session |

静态扫描：旧 dataflow 159 个 Python 文件约 39,757 行，目标 emtaint 90 个文件约 3,790 行。原 IDA exporter 含 Python 2 语法和旧 IDA API，本阶段不执行 exporter。

目标仍为 VEX/PAG 原型：`assembly/function.py:28` 有 tuple 尾逗号；`program_builder.py` 有全局单例；`analysis/pag/ir_graph_builder.py:32` 有固定函数过滤；`frontend/angr/block_ir_builder.py` 有 exit/丢弃转换；IR/analysis 直接依赖 pyvex/angr。本阶段不修复这些业务代码。

## 输入与已有结果

样本 `firmware-binaries/rv130_v44/httpd`：626,308 字节，ELF32 ARMEL，小端，入口 `0x10e58`，映射基址 `0x8000`。SHA256：`334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787`。

IDA CFG 与 Block JSON 均有 881 个函数条目。现有 iCall JSON：10 个函数、14 个调用点、535 个目标关联、475 个不同目标；switch/ijmp JSON 为 `{}`，不能据此断言程序没有 switch。

历史结果 SHA256：`972eb7b7c9e38b3ab9862b7f6f8aaa44aa6a43929a48cd4d231703a33a6d1f1c`。历史计数：iCall 14/17；taint_1 分析函数 796/881；缓冲区类告警 143，命令执行告警 7。这些不是已确认真阳性。

## P0-B 写路径审计

当前通过的 P0-B：`20261028T051055Z-96d1c781`。六次 CLI 成功，11 个逐步校验及最终 13,461 文件的内容/mtime/Git 校验全部通过；详细差分和 profile 见 [重采报告](phases/P0-B-recapture-report.md)。

首次采集更新：业务 CLI 的写路径检查不足以覆盖依赖导入副作用，旧 angr 导入曾重写 pycparser/parsetab.py 的 mtime，见 INTEGRITY_INCIDENT.md。后续已按用户授权验证 bootstrap（见 PLY_ISOLATION.md）；该修复不恢复首次变化，而是要求后续采集相对各自开始状态全量内容和 mtime 不变。

`main.py:28-34` 从 CWD + dataflow.conf 计算目录；结果配置全为相对路径。写点为 `save_icall_info:71`、`save_icall_statistics:78`、`save_taint_statistics:111`、`save_switch_info:218`、`init_file_path:231`。

`data_trace._save_tmp_result` 仅定义，未检索到调用。`IDAProcess._dataPath` 绝对路径为未使用类属性。`parse_arm_binary.py:1013` 等 exporter 有绝对写路径；CLI 中自动 `parse_cfg_info` 调用被注释，元数据齐全时不启动 IDA。`ida_utils` 导入本身只定义函数。

采集器拒绝重解析点及逃逸 RunRoot 的结果配置，逐文件验证复制哈希、物理独立性及链接数；每次旧程序只在新 RunRoot 执行。本审计与路径检查不宣称实现了通用 OS 沙箱。全旧仓库（含 .git、.venv）前后清单和 Git 状态共同验证不可变性。
