# BinaryAnalysis 人工调试手册

本手册仅针对当前 Python P7。所有动态运行都写入新的
`BinaryAnalysis/.p7-work/manual-debug/` 子目录；不会修改旧仓库、P6 冻结目录、Golden
或历史结果。日志默认关闭到 `WARNING`，只有显式传入 `--log-level` 才输出详细事件。

## 1. 调试前检查

在 PowerShell 中进入 `BinaryAnalysis`，确认解释器、环境和工作树：

```powershell
Set-Location D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis
$Python = (Resolve-Path .venv\Scripts\python.exe).Path
& $Python -B -c "import sys, angr, claripy; print(sys.version); print(angr.__version__, claripy.__version__)"
git status --short
& $Python -B scripts\quality_audit.py emtaint
```

不要运行 `pip install`，不要在 `..\EmTaint` 中启动 `main.py -i/-t`，不要把输出目录指向
已有 Golden、P6 或历史 P7 目录。

## 2. 先跑最小检查

```powershell
& $Python -B -m unittest tests.test_debug_logging -v
& $Python -B -m unittest discover -s tests -p 'test_p7*.py' -q
```

需要最终确认时再跑全量：

```powershell
& $Python -B -m unittest discover -s tests -p 'test_*.py' -q
```

## 3. 安全生成一次聚焦 taint 调试运行

先选择一个已通过且只读的 iCall 输出目录。脚本只复制 `icall.json` 和
`icall-targets.json` 到新目录，taint 不会写回该冻结目录。

```powershell
$Binary = (Resolve-Path ..\EmTaint\firmware-binaries\rv130_v44\httpd).Path
$Ida = (Resolve-Path ..\EmTaint\data\ida_data\rv130_1_0_3_44).Path
$Acquisition = (Resolve-Path .p7-work\20261029T074944Z-3a0de46d\acquisition-03).Path
$FrozenIcall = (Resolve-Path .p7-work\v8-p70-20261030T081526Z\p77-chain-2d394-4e330-01\output).Path

& scripts\manual_debug.ps1 `
  -Mode Taint `
  -BinaryFile $Binary `
  -IdaData $Ida `
  -Acquisition $Acquisition `
  -IcallInput $FrozenIcall `
  -TaintFunctions 0x1db6c,0x1cf1c,0x1cfb4,0x2d228 `
  -FunctionSeconds 30 `
  -TaintRounds 4
```

脚本末尾会打印唯一输出目录和 `debug-taint.jsonl`。诊断子集按设计返回
`incomplete`/退出码 2；这不等同于“无漏洞”。

上例的 `$FrozenIcall` 是当前工作区内已核对为 17 个站点、535 个候选目标的只读输入；
若以后切换冻结基线，只替换这个路径，并先确认其中的 `icall.json` 状态为
`candidate_fixed_point`。

若确需重新验证 iCall，仍使用全新目录：

```powershell
& scripts\manual_debug.ps1 -Mode Icall -BinaryFile $Binary -IdaData $Ida -Acquisition $Acquisition
```

P6 已冻结时通常不需要这一步。

### iCall 实时执行路径

`manual_debug.ps1 -Mode Icall` 现在会同时输出人类可读的控制台进度，并把完整字段保存到
`debug-icall.jsonl`。长函数每 10 秒输出 `icall.analysis.heartbeat`，因此可直接判断当前仍在
分析哪个函数，而不是把静默误认为挂起。主要顺序是：

```text
cli.acquisition.started / heartbeat / completed
icall.sites.discovered
icall.function.loading / loaded
icall.index.building
icall.search.round.started
icall.search.function.dispatched
icall.analysis.started / heartbeat / completed
icall.search.round.completed
icall.site.resolved
icall.artifact.written
cli.completed
```

运行结束后脚本会直接打印状态、站点覆盖、候选目标数、轮数、pending 数、三个核心文件
SHA256，以及日志事件/函数执行/ERROR 计数。

```powershell
$Run = (Get-ChildItem .p7-work\manual-debug -Directory |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$Log = Join-Path $Run 'debug-icall.jsonl'

# 当前/最慢函数及资源成本
Get-Content $Log | ConvertFrom-Json |
  Where-Object event -eq 'icall.analysis.completed' |
  Sort-Object wall_seconds -Descending |
  Select-Object function,sites,target_values,steps,wall_seconds,metrics |
  Format-Table -AutoSize

# 每轮新增事实、失效和下一轮重算规模
Get-Content $Log | ConvertFrom-Json |
  Where-Object event -eq 'icall.search.round.completed' |
  Format-List round,target_facts,target_values,affected,next_worklist,new_runtime_events

# 17 个站点的结果
Get-Content $Log | ConvertFrom-Json |
  Where-Object event -eq 'icall.site.resolved' |
  Format-Table function,site,targets,certainty,exhaustive -AutoSize

# 异常、ERROR 或尚未结束的 started/heartbeat
Get-Content $Log | ConvertFrom-Json |
  Where-Object { $_.level -eq 'ERROR' -or $_.event -like '*.heartbeat' } |
  Format-Table timestamp,event,function,elapsed_seconds -AutoSize
```

正确的当前 RV130 基线应至少满足：`status=candidate_fixed_point`、输入/观察站点
`17/17`、候选目标 `535`、固定点 `2` 轮、`graph_pending=[]`。这些计数用于发现回退，
最终仍应使用 SHA256 与冻结 P6 文件比较，不能只比较数量。

## 4. 日志检索顺序

```powershell
$Run = (Get-ChildItem .p7-work\manual-debug -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$Log = Join-Path $Run 'debug-taint.jsonl'

# 阶段/轮次/函数概览
Get-Content $Log | ConvertFrom-Json | Where-Object event -in @(
  'taint.started','taint.round.started','taint.function.completed',
  'taint.round.completed','taint.completed','cli.failed'
) | Format-Table timestamp,event,function,round,status,changed,pending,wall_seconds -AutoSize

# 预算、超限和未完成查询
Get-Content $Log | ConvertFrom-Json | Where-Object {
  $_.event -in @('taint.function.limited','taint.query.incomplete')
} | Format-List

# 单函数或单查询
Get-Content $Log | ConvertFrom-Json | Where-Object function -eq '0x2d228' | Format-List
Get-Content $Log | ConvertFrom-Json | Where-Object query_id -eq '<query-id>' | Format-List

# Summary/table 失效链
Get-Content $Log | ConvertFrom-Json | Where-Object {
  $_.event -in @('taint.table.updated','taint.round.completed')
} | Format-Table event,writer,version,sources,invalidated,changed,next_worklist -AutoSize
```

推荐按以下次序定位首次分歧：`taint.function.started` → `taint.query.started` →
`taint.query.completed/incomplete` → `taint.function.completed` →
`taint.round.completed`。先找最早变化的事实或预算状态，再看最终 Candidate JSON。

## 5. 结果文件检查

```powershell
$Phase = Get-ChildItem $Run -Directory -Filter 'taint-*' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Get-Content (Join-Path $Phase.FullName 'manifest.json') | ConvertFrom-Json | Format-List
Get-Content (Join-Path $Phase.FullName 'invocations.json') | ConvertFrom-Json |
  Sort-Object wall_seconds -Descending | Select-Object -First 20 |
  Format-Table function,round,pending,sinks,source_facts,steps,wall_seconds -AutoSize
Get-Content (Join-Path $Phase.FullName 'unknowns.json') | ConvertFrom-Json | Format-Table -AutoSize
```

函数级证据位于 `round-NNN-function-0x...-result.json`；其中重点检查
`query_history`、`pending_query_ids`、`argument_preparations`、`unknown_frontiers`、
`metrics`、`source_bindings` 和 `summary`。不要手工修改这些 JSON。

## 6. 进入 Python 断点

对最小单元测试使用标准库调试器：

```powershell
& $Python -B -m pdb -m unittest tests.test_p7_query_worklist
```

常用命令：`b 文件.py:行号` 设置断点，`c` 继续，`n` 单步，`s` 进入，`p 表达式`
查看值，`where` 查看调用栈，`q` 退出。端到端 CLI 很大，优先用上面的函数子集和 JSONL
找到具体 query/function 后，再在对应 transfer、memory query 或 summary join 位置断点。

## 7. 每次人工 check 的记录模板

记录：源码 commit/`git status`、二进制和 metadata SHA256、冻结 iCall 输入路径、唯一输出
目录、函数列表、预算、首个分歧事件、相关 result JSON、根因、最小回归、修复前后日志和退出码。
`Unknown`、`Timeout`、`Unsupported`、`Incomplete` 必须原样保留，不能登记为“无漏洞”。
