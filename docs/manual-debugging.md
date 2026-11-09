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

控制台默认显示 `INFO` 级阶段进度，完整 `DEBUG` 事件写入格式化 JSON 数组，避免数万次 SSE/Memory
操作淹没人工终端。每条控制台日志仅显示源码文件名、代码行和函数，例如：

```text
2026-11-02T11:57:07 INFO emtaint.cli [cli.py:127 run_icall] icall.sites.discovered {...}
```

如确需把全部采样事件也显示到终端，可在 CLI 中传入
`--log-console-level DEBUG`；`manual_debug.ps1` 默认使用 `INFO`。日志文件沿用
`.jsonl` 文件名以兼容既有命令，但内容是可直接阅读和解析的缩进 JSON 数组。每个事件的
`source_file`、`source_line`、`source_function` 字段可直接跳转到首次产生日志的源码。
涉及函数地址的 iCall/CFG/CG/Memory 事件同时写入 `function_rva` 与 `function_va`：前者是
相对镜像基址的地址，后者是可直接在 IDA Pro 跳转的虚拟地址。兼容字段 `function` 保留
各事件原有语义，人工检索应优先使用两个显式字段。例如镜像基址为 `0x8000` 时：

```json
{
  "event": "icall.search.function.dispatched",
  "function": "0x8ee0",
  "function_rva": "0x8ee0",
  "function_va": "0x10ee0"
}
```

核心事件按实现层划分：

| 层 | 关键事件 |
|---|---|
| CFG/CG | `cfg.replaced`、`cg.edges.added`、`cg.inferred_edges.replaced`、`analysis.dependencies.invalidated` |
| Worklist | `icall.search.round.started/completed`、`icall.search.function.dispatched` |
| SSE/传播 | `sse.*`、`dataflow.transfer.started/completed`、`dataflow.value.updated`、`dataflow.register.updated` |
| AccessPath/APG | `apg.address.bound`、`apg.path.created/cache_hit`、`apg.field_closure.*`、`apg.membership.*` |
| MemoryVersion | `memory.read/write/havoc/definitions.completed`、`memory.location.*` |
| Alias | `alias.query.completed`、`alias.cache.hit/miss` |
| 跨函数 | `summary.recipe.stored`、`icall.cir_search.recipe.*`、`taint.round.*` |

高频事件采用“开头完整记录 + 周期采样”，每条带 `event_sequence`；最终
`diagnostic_event_counts` 保存真实总次数。因此未看到每一次操作不表示操作未执行，应同时查看总计。

运行结束后脚本会直接打印状态、站点覆盖、候选目标数、轮数、pending 数、三个核心文件
SHA256，以及日志事件/函数执行/ERROR 计数。

```powershell
$Run = (Get-ChildItem .p7-work\manual-debug -Directory |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$Log = Join-Path $Run 'debug-icall.jsonl'
$Events = @(Get-Content -LiteralPath $Log -Raw | ConvertFrom-Json)

# 当前/最慢函数及资源成本
$Events |
  Where-Object event -eq 'icall.analysis.completed' |
  Sort-Object wall_seconds -Descending |
  Select-Object function_rva,function_va,sites,target_values,steps,wall_seconds,metrics |
  Format-Table -AutoSize

# 每轮新增事实、失效和下一轮重算规模
$Events |
  Where-Object event -eq 'icall.search.round.completed' |
  Format-List round,target_facts,target_values,affected,next_worklist,new_runtime_events

# 17 个站点的结果
$Events |
  Where-Object event -eq 'icall.site.resolved' |
  Format-Table function_rva,function_va,site_rva,site_va,targets,certainty,exhaustive -AutoSize

# 异常、ERROR 或尚未结束的 started/heartbeat
$Events |
  Where-Object { $_.level -eq 'ERROR' -or $_.event -like '*.heartbeat' } |
  Format-Table timestamp,event,function_rva,function_va,elapsed_seconds -AutoSize

# 直接定位事件源码
$Events |
  Select-Object -First 30 timestamp,event,source_file,source_line,source_function |
  Format-Table -AutoSize

# SSE/Memory/Alias/APG 采样轨迹
$Events | Where-Object {
  $_.event -like 'sse.*' -or $_.event -like 'memory.*' -or
  $_.event -like 'alias.*' -or $_.event -like 'apg.*'
} | Select-Object event,event_sequence,function_rva,function_va,origin,state,location,expression |
  Format-Table -AutoSize
```

正确的当前 RV130 基线应至少满足：`status=candidate_fixed_point`、输入/观察站点
`17/17`、候选目标 `535`、固定点 `2` 轮、`graph_pending=[]`。这些计数用于发现回退，
最终仍应使用 SHA256 与冻结 P6 文件比较，不能只比较数量。

## 4. 日志检索顺序

```powershell
$Run = (Get-ChildItem .p7-work\manual-debug -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$Log = Join-Path $Run 'debug-taint.jsonl'
$Events = @(Get-Content -LiteralPath $Log -Raw | ConvertFrom-Json)

# 阶段/轮次/函数概览
$Events | Where-Object event -in @(
  'taint.started','taint.round.started','taint.function.completed',
  'taint.round.completed','taint.completed','cli.failed'
) | Format-Table timestamp,event,function,round,status,changed,pending,wall_seconds -AutoSize

# 预算、超限和未完成查询
$Events | Where-Object {
  $_.event -in @('taint.function.limited','taint.query.incomplete')
} | Format-List

# 单函数或单查询
$Events | Where-Object function -eq '0x2d228' | Format-List
$Events | Where-Object query_id -eq '<query-id>' | Format-List

# Summary/table 失效链
$Events | Where-Object {
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
查看值，`where` 查看调用栈，`q` 退出。端到端 CLI 很大，优先用上面的函数子集和结构化 JSON
找到具体 query/function 后，再在对应 transfer、memory query 或 summary join 位置断点。

## 7. 每次人工 check 的记录模板

记录：源码 commit/`git status`、二进制和 metadata SHA256、冻结 iCall 输入路径、唯一输出
目录、函数列表、预算、首个分歧事件、相关 result JSON、根因、最小回归、修复前后日志和退出码。
`Unknown`、`Timeout`、`Unsupported`、`Incomplete` 必须原样保留，不能登记为“无漏洞”。


## 8. IDA VA display

Pass `--debug-ida-image-base 0x140000000` to use the exact IDA database base. Debug inspectors display `IDA VA 0x140015688 (RVA 0x15688)` for RVA `0x15688`. The optional `--debug-runtime-base` is a separate runtime module base. Neither option changes CIR, FunctionId, ValueRef, OriginId, or internal addresses. Without an IDA base, the inspector reports `IDA_IMAGE_BASE_NOT_CONFIGURED`.

Use these expressions in VS Code Watch without an outer `print()`:

```python
demand.debug.inspect_value(operand)
demand.debug.inspect_demand_value(demand, operand)
demand.debug.inspect_expr(roots[0], max_depth=8, max_nodes=200)
```

The current saved acquisition records OriginMap statement indexes and opcode names, but not full VEX statement text, instruction bytes, or disassembly. Reports identify these gaps instead of guessing assembly from `Ijk_*` jump kinds.


## 9. Complete D1-D4 source and trace workflow

The updated acquisition writes two additive files beside each function body:

- `debug-provenance.jsonl`: ValueRef-to-OriginMap role, VEX temporary, and register hints.
- `debug-instructions.jsonl`: VEX statement text, IMark machine bytes, Capstone assembly when the configured decoder recognizes the exact instruction, and ARM/Thumb mode.

These files are independent of `function.json`; they do not change the CIR wire version or analysis identities. Their SHA256 values and record counts are stored in the acquisition report. Regenerate the acquisition using the updated source to capture instruction-level details. Older acquisitions remain readable; absent sidecars are reported as unavailable rather than guessed.

For taint analysis, enable the bounded trace and optional IDA export:

```powershell
python -B -m emtaint -t -f <binary> -n <firmware-name> -v <firmware-version> `
  --ida-data <ida-data> --acquisition <acquisition> `
  --output <new-output-under-.p7-work> `
  --debug-ida-image-base 0x140000000 `
  --debug-ida-export `
  --debug-trace --debug-trace-max-events 50000
```

Each analyzed function writes an append-only `*-trace.jsonl` and, when requested, a `*-ida-map.json` beside its function receipt. Trace events carry stable IDs, producer-derived parent event IDs, input/output identities, OriginMap identity, instruction RVA, and rule details. The backward causal slice follows existing producer/consumer identities; it does not rerun analysis.

### Inspector / Watch expressions

```python
demand.demand.debug.inspect_value(value_ref)
demand.demand.debug.inspect_instruction(origin_id)
demand.demand.debug.inspect_expr(sse_expression, max_depth=8, max_nodes=200)
demand.demand.debug.inspect_demand_value(demand.demand, value_ref)
demand.demand.debug.inspect_memory_version(memory_version)
demand.demand.debug.inspect_memory_read(memory_read_expression)
demand.demand.debug.inspect_alias(memory_version, left_location, right_location)
demand.demand.debug.inspect_taint_state()
demand.demand.debug.inspect_trace(sse_expression)
```

Memory-read inspection lists structurally ancestral candidate stores and their guards, update strength, and recorded alias evidence. These are candidates, not proof that a store reaches the read. Alias inspection is read-only: it displays a cached result when available and otherwise reports `NOT_CACHED`; it never launches a new points-to, alias, or solver query.

The trace is bounded per function. The function receipt records event count and dropped-event count. A truncated trace is explicitly incomplete and must not be interpreted as proof that no propagation or memory event occurred.


## 9. 完整 Debug Explainability 工作流

### 9.1 重新采集前端来源信息

旧 acquisition 不含 `debug-provenance.jsonl` 和 `debug-instructions.jsonl`，只能提供原有 CIR/OriginMap 信息。若要解释真实 VEX Statement、指令 Bytes 和 Assembly，需要用当前版本重新执行 acquisition：

```powershell
python -B scripts\p7_acquire.py --folder .p7-work\acquisition-debug-<unique-name>
```

acquisition 生成的两个调试 sidecar 有独立 SHA256 和记录数，不修改 CIR wire schema。VEX statement 取自 pyvex 对象本身；机器指令 bytes 来自对应 chunk 中的真实指令范围；assembly 只在 Capstone 能完整解码相同地址和长度时输出。

### 9.2 运行完整调试采集

在已有、匹配的 iCall fixed-point 输出目录上执行 taint：

```powershell
python -B -m emtaint -t -f <binary> -n <firmware-name> -v <version> `
  --ida-data <ida-data> --acquisition <acquisition> `
  --output <existing-fixed-point-output> `
  --debug-ida-image-base 0x140000000 `
  --debug-runtime-base 0x7ff700000000 `
  --debug-trace --debug-report --debug-ida-export
```

`--debug-trace` 必须在分析开始前启用，不能为之前已经完成的传播补造事件。每个被分析函数会在其独立结果目录生成 trace、IDA map 和 debug-report。Debug report 默认有节点数量上限，避免把大型二进制的整个 SSE DAG 无界写出。

### 9.3 报告目录

```text
<function-receipt>-debug-report/
  README.md
  session.json
  provenance.json
  analysis-events.jsonl
  values/
  expressions/
  memory/
  reports/
    demand-explanations.md
    taint-evidence.md
    address-mapping.md
```

报告只遍历已经存在的 CIR、DAG、MemoryVersion、Demand memo 和 trace 记录。未记录的历史会明确标注，不会在导出阶段重新执行 alias、memory 或 solver 查询。
