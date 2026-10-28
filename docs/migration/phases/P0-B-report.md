# P0-B 基线与隔离 profile 报告

本页为首次失败采集的历史报告，其停止状态和命令描述对应当时工具版本。**当前 P0-B 已在新目录重采通过，见 [P0-B-recapture-report.md](P0-B-recapture-report.md)。** 原失败 manifest 和原始数据未改标或覆盖。

日期：2026-10-28（Asia/Shanghai）。**阶段状态：BLOCKED，完整性 Gate 未通过。** 基线/profile 已采集，但不能标记为已批准 Golden；未进入 P1，也未实施 Rust 迁移。

## 结果与阻塞

两份独立普通物理副本和第三份 profile 副本，各执行 `-i → -t`，六次退出码均为 0。分阶段快照、iCall 目标、日志、环境/哈希清单及两个 .prof 均已保存。

最终全旧仓库 13,461 个文件的内容/大小/路径以及 Git 状态一致，但 `.venv/Lib/site-packages/pycparser/parsetab.py` 的 mtime 改变。其 SHA256 保持 `fe2bda1b1cefee26f5401ca231fc7cf1440b6c7961015424cc1c9dbb4f53584f`。

这是加载旧 angr 时 PLY 显式写解析表的副作用；`-B` 无法阻止。不是历史 JSON 覆盖，也没有修改旧算法源码或安装依赖，但仍违反旧 .venv 不可修改约束。发现后已停止所有旧环境执行，不回写文件属性。详细来源、前后纳秒时间和拟议隔离修复见 [INTEGRITY_INCIDENT.md](../INTEGRITY_INCIDENT.md)。

原始 `manifest.json` 保留 `legacy_integrity_failure`，顶层采集器退出码 1。没有通过忽略 mtime 或修改 manifest 把失败改成成功。现采集器新增只读静态预检，发现此加载期风险时，在旧环境导入、复制或新归档创建之前拒绝执行。

## 路径和版本

```text
MIGRATION_ROOT = D:\works\dataflow\EmTaint\emtaint-migration
LEGACY_ROOT    = MIGRATION_ROOT\EmTaint
TARGET_ROOT    = MIGRATION_ROOT\BinaryAnalysis
LEGACY_PYTHON  = LEGACY_ROOT\.venv\Scripts\python.exe
TARGET_PYTHON  = TARGET_ROOT\.venv\Scripts\python.exe
BASELINE       = MIGRATION_ROOT\baselines\rv130_1_0_3_44\20261028T034805Z-b5b6f765
RUN_ROOTS      = MIGRATION_ROOT\baseline-work\rv130_1_0_3_44\20261028T034805Z-b5b6f765\{reference,repeat-01,profile}\EmTaint
```

旧 commit：`72a9e3081632b2f9d1881141bc7b0d43c7158033`，Python 3.7.2、angr/pyvex/cle/archinfo 9.0.9792。目标 commit：`3c718ca3d912aad6090cbf0ecd33461bd30b51ec`，Python 3.12.9、对应包 10.0.5。两环境 pip check 均退出 0；包来源、sys.path、freeze 和 Claripy 扩展源均归档。

旧工作树已有的两个修改标记和未跟踪结果均保留，dirty diff 已归档。没有修改两个环境的依赖。目标仍在原分支，仅新增辅助文件和文档，无业务实现重构、提交或 push。

## 命令和退出码

所有 Python 使用上述绝对解释器，带 `-B` 和 `PYTHONDONTWRITEBYTECODE=1`。

目标环境测试：

```powershell
& $TargetPython -B -m unittest discover -s tests -v
```

最终 **21/21 通过，退出 0**，覆盖缺失告警/目标、地址变化、类型与有序证据保留、允许的集合重排、拒绝重复目标、不覆盖归档、运行目录拒绝和加载期风险 fail-closed。测试 stdout/stderr 和完整命令位于 BASELINE 的 validation-tests.*。

实际采集入口：

```powershell
.\scripts\legacy_baseline.ps1 -Execute -Profile -Repetitions 2
```

首轮与重复轮分别从各自 RunRoot 执行：

```powershell
& $LegacyPython -B main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -i
& $LegacyPython -B main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -t
```

profile 副本分别执行：

```powershell
& $LegacyPython -B -m cProfile -o "$Baseline\profile\icall.prof" main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -i
& $LegacyPython -B -m cProfile -o "$Baseline\profile\taint.prof" main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -t
```

六个准确 argv/CWD、开始时间、退出码及哈希在各 `.command.json` / `.verified.json`，不能把采集器最终退出 1 隐去。当前版本默认 dry-run 退出 0 并列出 execution_blockers；--execute 的 fail-closed 行为已通过 mock 验证，没有再次运行旧解释器。

辅助命令异常：首次测试被 Windows 沙箱临时目录权限阻塞，允许环境复测通过；最终测试明确在目标工作区创建独立临时目录并检查清理范围。一次辅助归档命令路径解析错误退出 1，未复制文件，修正后成功。这些不涉及旧仓库修复或依赖安装。

## 差分结果

使用 final comparator 重新验证的 `validation-v2.json` 为最终派生比较；保留采集时工具副本和最初 comparison.json。

| 比较 | 语义变化 | 仅集合顺序变化 | iCall 目标文件 |
|---|---:|---:|---|
| 普通首轮最终结果 vs 历史结果 | 0 | 0 | 历史统计不含完整目标；初始元数据单独归档 |
| 普通首轮 vs 独立重复 -i | 0 | 0 | 完全相同 |
| 普通首轮 vs 独立重复 -t | 0 | 0 | 完全相同 |
| 普通首轮 vs profile -i | 0 | 0 | 完全相同 |
| 普通首轮 vs profile -t | 0 | 0 | 完全相同 |

差异仅已保留的 time 字段。目标关系：10 个函数、14 个恢复调用点、535 个关联、475 个不同目标；总 iCall 17。taint_1 分析函数 796/881，块 30,919，污点块 4,584，污点 sink 402，缓冲区类告警 143，命令执行告警 7。逐告警地址、name、offset、info、func 均一致，不是仅比较数量。

warm-start 的初始 iCall 未清空；首轮 -i 快照中 taint_1 来自 seed，只对本阶段 icall 重算作保证。没有将历史 preexisting.json 伪装为阶段结果。

## Profile 发现

普通首轮 -i/-t 墙钟 48.491/83.033 秒；独立重复 65.788/72.672 秒；profile 81.456/158.459 秒。保留原 loader 默认设置和 debug 输出，不作固定倍数的性能结论。

- -i：调用图预序累计 15.179 秒；函数对象相等判断 17,271,435 次，exclusive 8.444 秒。
- -t：VEX Action 执行累计 35.000 秒；块表达式合并 77,609 次，累计 19.185 秒；VarExpr.replace 16,129 次，累计 4.302 秒。
- profile 累计项包含子调用，不能相加；导入和 IO 也在 profile 内。
- 实际分析 worker/进程树内存未测到，约 5 MB 启动进程数字不能作为分析峰值。

完整指标与解释见 [PROFILE.md](../PROFILE.md)。这些是本轮诊断证据；完整性 Gate 失败使其不能替代隔离修复后的正式采集。

## 覆盖、风险和下一步

旧 JSON 没有完整 CFG/CG/SSE/alias/source→sink/guard 快照；旧引擎也无统一 unsupported/unknown 统计，因此这些维度为 unavailable，不能记成 0 或 100% 完整。目标 Claripy SAT 原生崩溃仍是 P1 阻塞，本阶段不修复。

下一步需先审核并验证 RunRoot bootstrap 对 PLY 写表的加载期隔离（例如 write_tables=False，保留 grammar/start/optimize），使用隔离副本做导入/类型解析契约和逐阶段完整性检查；通过后用全新 run ID 重采 P0-B。不能再次直接使用当前旧导入路径。当前版本继续保留 Python 算法，不进入 Rust 工作。

## 新增文件与回退

新增 scripts 下采集器/PowerShell 包装/比较器、tests/test_baseline_tools.py、docs/migration 下清单/CLI/API/schema/策略/profile/完整性事件及本报告。未改 emtaint 业务代码。`git diff --check` 与源文件解析检查通过。

回退只针对目标新增辅助文件；没有自动删除任何目录。基线、运行副本、失败 manifest 及旧依赖当前状态均保留，不能通过删除证据或恢复旧 mtime 进行回退。三个用户原有约束文档不属于本轮可回退文件。
