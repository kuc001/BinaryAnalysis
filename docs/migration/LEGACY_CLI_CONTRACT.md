# 旧 CLI 与隔离运行契约

**所有旧环境调用必须经已验证的 bootstrap。** 首次采集发现旧 angr 导入时通过 PLY 重写旧 .venv 的 parsetab.py。用户随后授权隔离验证，已证明禁写表模式保留解析契约且旧环境不变，见 PLY_ISOLATION.md。下面的旧命令描述语义契约，不应直接手工执行；采集器在副本中通过 bootstrap 设置相同 main.py argv 后运行。

旧解释器固定为 `D:\works\dataflow\EmTaint\emtaint-migration\EmTaint\.venv\Scripts\python.exe`。所有探测/执行带 `-B`，设置 `PYTHONDONTWRITEBYTECODE=1`。不激活环境，不安装依赖。

仅从 `emtaint-migration/baseline-work/rv130_1_0_3_44/<run-id>/<label>/EmTaint` 运行：

```powershell
& $LegacyPython -B main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -i
& $LegacyPython -B main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -t
```

`main.py:600` 参数还包括 `--switch_check`、`--resolve_icall`（默认整数 1）、`--debug`、`--load_ida_bytes`。`load_binary` 不显式禁用自动加载库；本基线保留这个原始行为。

## 顺序与共同输出

1. 两阶段均通过 `FastSearch._reconstruct_cfg` 读取初始 `httpd_icall.json` 并加入调用图边；`--resolve_icall 0` 跳过这部分。
2. `-i` 更新 `data/ida_data/rv130_1_0_3_44/httpd_icall.json`，重建结果 JSON 的 `icall` 字段。
3. `-t` 默认重建结果 JSON 的 `taint_1`，保留之前 `icall`；`--resolve_icall 0` 写 `taint_0`。
4. 共用 `data/result_data/rv130_1_0_3_44.json`，因此必须在每阶段结束立即快照。不能用最终文件代替两个阶段结果。

本轮以已有 dirty 工作树和既存 iCall 为 seed，属于 warm-start 复现；没有将 iCall 清空。各独立重复从同样初始文件创建新副本。历史 JSON 先归档为 `preexisting.json`，不能重标记为分阶段 Golden。

`icall.json` 是完整阶段快照，其中可能仍带 seed 中历史 `taint_1`；本次 `-i` 只证明 `icall` 重算。`taint.json` 才含本次重算的 `taint_1`。`*-targets.json` 保存对应阶段实际 iCall 关联。

## Profile

第三份独立副本执行同样顺序，通过 bootstrap 内部的标准库 cProfile 包裹 main.py，并保存到独立归档路径。保留原日志/调试打印，不修改算法源码、不静默关闭分析。profile 与普通运行分别记录，不能把其耗时混作无 instrumentation 的性能；profile 本体不包含少量 bootstrap 安装工作，父进程墙钟包含全部启动开销。

```powershell
# 默认 dry-run（不创建基线、不执行旧 CLI）
.\scripts\legacy_baseline.ps1 -Profile -Repetitions 2
# 仅验证 PLY 隔离（也使用新目录）
.\scripts\legacy_baseline.ps1 -Execute -ValidateIsolationOnly
# 显式执行；只创建唯一的新目录
.\scripts\legacy_baseline.ps1 -Execute -Profile -Repetitions 2
```

采集器使用目标 Python 管理文件/比较/测试；旧 CLI、隔离 probe 和旧环境元数据使用旧 Python，并统一经过 bootstrap。stdout/stderr 直接写二进制日志，避免 PowerShell 编码转换。单阶段默认 1800 秒超时，失败保留日志/manifest，不自动续跑。
