# P0-B 基线与比较规则

存放：`emtaint-migration/baselines/rv130_1_0_3_44/<UTC-run-id>/`，不在两个 Git 仓库内，不上传、不提交。对应物理运行副本位于 `baseline-work/`，不使用链接且不复制 .git/.venv/__pycache__。

## 归档

主目录：`plan.json`、`manifest.json`、`preexisting.json`、`legacy-working-tree.diff`、`file-inventory-before/after.json`、`environment/`。

隔离验证：`isolation/{redirect,disabled}/` 保存两份物理副本的 parser probe、bootstrap 报告及逐步完整性检查；`isolation-proof.json` 绑定 bootstrap SHA256，保留完整类型/AST/解析表契约。`collection-tooling/` 保存实际执行工具源码。

每个旧环境探测/元数据命令和每个 CLI 阶段后保存 `legacy-integrity-*.json`：全量重读文件哈希、mtime 和 Git 状态，不复用旧哈希。`*.bootstrap.json` 记录 PLY 调用选项、私有 cache 文件、禁止写入尝试和实际 worker 内存。

普通首轮：`icall.json`、`taint.json`、`icall-targets.json`、`taint-targets.json`、各阶段 `.log`、`.command.json`、`.verified.json`、run-inventory-before/after。

`repeat-01/`：同样独立采集，另有 `comparison.json`。`profile/`：同样顺序并保存 `.prof`、`*-profile.json` 和对普通首轮的比较。

`normalized/`：独立派生表示，原始 JSON 不变。`historical-comparison.json` 比较历史结果与本次首轮最终结果。

Manifest 包含 commit、dirty 状态、解释器路径、命令/CWD、样本/结果 SHA、退出码、墙钟时间、峰值工作集、profile 标识及原旧仓库完整性。环境目录保存版本/模块来源/sys.path、pip freeze/check 和本机 Claripy 扩展实现。

## 旧结果字段

`icall`：`time`（字符串）、`all_icall`、`recovered_icall`、`min_tartet_num`（保留旧拼写）、`max_tartet_num`、`add_icall_target`（不同目标数，不是关联数）。

`taint_1` / `taint_0`：函数/块/sink 计数、buffer_overflow_num、command_exec_num；`buffer_overflow`、`command_exec`、`tained_length`（保留旧拼写）、`sink_info`。

告警键是无 0x 前缀的十六进制指令地址；`func` 为数值地址。`info` 四个有序元素分别是不同传播函数数、间接调用层数、污点传播层数、循环数，不能排序。`offset` 由 `save_taint_statistics` 将 stack_offsets 集合转为列表。

iCall 目标文件结构为 `{十进制函数地址字符串: {十进制调用点字符串: [数值地址或外部名称]}}`；Collector 从 targets 集合逐项写入，因此仅目标列表可作为无序集合比较。重复目标属于异常输入，比较器拒绝，不自动去重。

## 差分

- `semantic_changes`：新增/丢失/变动字段与逐告警证据；缺失不等于 null，类型不自动转换。
- `timing_changes`：仅已知 icall/taint_0/taint_1 的 time 单独列出，保留原值。
- `order_only_changes`：仅证明来自集合的 buffer_overflow/offset 重排。
- iCall 按函数、调用点及完整目标列表比较；目标重排独立标记。
- 未知字段、路径、info、调用上下文等列表默认严格有序。原始 JSON 从不就地排序。

统计 JSON 缺少完整 CFG/CG 边、SSE/alias 事实和 source→sink/guard 路径。P0-B 保存原始元数据、完整日志与 profile，但不能宣称已获得全部图/路径 Golden，更不能仅凭告警数相同证明完整语义等价。旧分析没有统一 unsupported/unknown 计数，数量与覆盖率必须记为 unavailable，不能写 0。

## 性能

普通轮墙钟、旧内部 time、独立 profile 时间分别报告。原 psutil peak_wset 仍只覆盖 Popen 启动器，不作为分析峰值。新版 `analysis_worker_memory` 由实际 worker 内部的 Windows GetProcessMemoryInfo 上报 kernel peak working set（含 PID），保存在 verified/manifest 中；它不等于整个进程树的峰值。cProfile 的 cumulative 行互相包含，不能相加；模块汇总使用 exclusive time。保留调试打印与原加载选项，profile 包含 main.py 的导入、日志和 IO；父进程墙钟还包含 bootstrap 安装等启动开销。
