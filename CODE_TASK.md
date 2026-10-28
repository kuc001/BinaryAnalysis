# CODE_TASK.md — 可直接交给 Codex 的完整执行手册

**项目**：EmTaint (angr 9.0.9792) → BinaryAnalysis (angr 10.0.5)  |  **平台**：Windows + PowerShell + VS Code + Codex  |  **版本**：v3.0 · 2026-10-28

**已确认结构**：`emtaint-migration/` 是共同父目录；`EmTaint/` 为只读旧仓库（内含 `.venv/`），`BinaryAnalysis/` 为可修改目标仓库（内含 `.venv/`）。没有外层 `EmTaint/venv`，也不存在第二个旧仓库。

> **立即执行范围**：默认仅执行本手册的 **Step A（只读检查）+ Prompt P0-A（只读审计）**；未经单独授权，不自动运行历史 `-i/-t`、不重构代码、不安装包、不删除或覆盖输出。准备开始迁移时，按 P0-B、P1……P9 的顺序逐阶段执行。每阶段结束暂停，由人审核。

## 目录

1. Windows 环境定位、旧/新虚拟环境检查（Step A）
2. 保留原始运行结果并建立独立 Golden Data（Step B，须批准）
3. 正确启动 Codex / 约束文件与开发分支
4. 通用 Codex 执行模板与 P0—P9 提示词
5. 各阶段验收、Review、失败分类与回退
6. 完成定义与启动建议

---

## Step A — Windows PowerShell 只读环境诊断（从 BinaryAnalysis 根目录运行）

在 VS Code/PowerShell 打开 `...\emtaint-migration\BinaryAnalysis`。以下变量可直接使用，不依赖 PowerShell 环境激活，也不调用全局 `python`。

```powershell
$ErrorActionPreference = 'Stop'
$env:PYTHONDONTWRITEBYTECODE = '1'  # 避免在只读旧仓库/虚拟环境中产生 __pycache__
$TargetRoot = (Resolve-Path (Get-Location).Path).Path
$MigrationRoot = (Resolve-Path (Join-Path $TargetRoot '..')).Path
$LegacyRoot = (Resolve-Path (Join-Path $MigrationRoot 'EmTaint')).Path
$LegacyPython = Join-Path $LegacyRoot '.venv\Scripts\python.exe'
$NewPython = Join-Path $TargetRoot '.venv\Scripts\python.exe'
$LegacyResult = Join-Path $LegacyRoot 'data\result_data\rv130_1_0_3_44.json'
$LegacyBinary = Join-Path $LegacyRoot 'firmware-binaries\rv130_v44\httpd'

Write-Host "MigrationRoot=$MigrationRoot"
Write-Host "LegacyRoot=$LegacyRoot"
Write-Host "TargetRoot=$TargetRoot"
Write-Host "LegacyPython=$LegacyPython"
Write-Host "NewPython=$NewPython"

foreach ($p in @(
    (Join-Path $LegacyRoot 'main.py'),
    (Join-Path $LegacyRoot 'dataflow'),
    (Join-Path $LegacyRoot 'data'),
    $LegacyBinary,
    $LegacyPython,
    (Join-Path $TargetRoot 'emtaint'),
    $NewPython
)) {
    if (!(Test-Path -LiteralPath $p)) { throw "预期路径不存在: $p" }
    Write-Host "FOUND: $p"
}

& $LegacyPython -B -c 'import sys, angr; print("LEGACY", sys.executable, sys.version, angr.__version__)'
if ($LASTEXITCODE -ne 0) { throw 'Legacy Python/angr 无法导入；不得继续基线执行' }
& $NewPython -B -c 'import sys, angr; print("TARGET", sys.executable, sys.version, angr.__version__)'
if ($LASTEXITCODE -ne 0) { throw 'Target Python/angr 无法导入；不得继续迁移验证' }

foreach ($r in @($LegacyRoot, $TargetRoot)) {
    Write-Host "=== GIT $r ==="
    git -C "$r" rev-parse HEAD
    git --no-optional-locks -C "$r" status --short
}

if (Test-Path -LiteralPath $LegacyResult) {
    Write-Host 'Legacy result exists (read-only):'
    Get-FileHash -LiteralPath $LegacyResult -Algorithm SHA256
} else {
    Write-Host 'Legacy result currently missing; do not fabricate a baseline.'
}
Get-FileHash -LiteralPath $LegacyBinary -Algorithm SHA256
```

**PowerShell 独立会话注意事项**：后续 Step B 依赖本段定义的变量。如果新开终端，请重新执行上面的定位部分；切勿手工复制过时的绝对路径。

### A.1 唯一旧仓库与权限确认

- `LEGACY_ROOT = MIGRATION_ROOT\EmTaint`，无需在外层目录中搜索其他旧源码。
- 两个 `.venv` 都位于各自仓库内：旧 `EmTaint\.venv`、新 `BinaryAnalysis\.venv`。
- 旧仓库中的 `main.py`、`data/`、`firmware-binaries/`、`.venv/`、`.git/` **全部只读**，不能通过 `-i/-t` 直接更新旧结果。
- 建议记录旧仓库 `git status` 和关键 `data/result_data`/输入文件 SHA256，作为旧仓库不可变性验证。
- `../EmTaint` 处于目标仓库工作区以外，Codex 可能需要读权限批准；不要通过扩大成可写工作区解决。若不能读取，记录阻塞并由用户配置只读访问。

### A.2 Claripy / angr 10 API 探测（只读）

依次在两个**绝对解释器路径**下执行；如果语义 API 探测失败，应进入 P1 兼容性定位，不应为了让命令通过而更换解释器。

```powershell
& $LegacyPython -B -c 'import importlib.util,angr,claripy,pyvex; x=claripy.BVS("probe",32); print("legacy angr",angr.__version__); print("legacy claripy",getattr(claripy,"__file__",None),type(x),x.size()); print("legacy VEX",getattr(pyvex,"__version__","unknown"))'

& $NewPython -B -c 'import importlib.util,angr; from angr import claripy; x=claripy.BVS("probe",32); print("target angr",angr.__version__); print("target claripy",getattr(claripy,"__file__",None),type(x),x.size()); print("standalone claripy spec",importlib.util.find_spec("claripy"))'

& $NewPython -B -c 'from angr import claripy; x=claripy.BVS("probe",32); s=claripy.Solver(); s.add(x==claripy.BVV(7,32)); print("solver eval",s.eval(x,1))'

& $LegacyPython -B -m pip freeze
& $NewPython -B -m pip freeze
```

**要求 Codex 将探测输出按环境归档**；`find_spec("claripy")` 即使有返回，也不意味着两个版本的 AST/solver 行为相同。务必测试 `VarExpr/TraceExpr/SimAction/parse_ast` 实际用到的替换、简化、hash/key、AST 遍历、提取位宽等 API。

### A.3 判断新旧仓库是否被意外混合

```powershell
# 在 BinaryAnalysis 根目录
Get-ChildItem -Force | Select-Object Name,Mode
Get-ChildItem Env:PYTHONPATH,Env:VIRTUAL_ENV -ErrorAction SilentlyContinue
& $NewPython -B -c 'import sys,angr; print("python",sys.executable); print("angr",angr.__file__); print("sys.path",sys.path[:6])'
```

若旧仓库路径通过 `PYTHONPATH` 注入新进程，必须先记录并在受控终端中消除污染。**不修改旧 venv，不把新环境安装到旧目录。**

---

## Step B — 安全的 Golden Data 采集（默认只读；重跑须用户批准）

**硬约束**：`LEGACY_ROOT` 是完全不可修改的旧仓库。用户提供的 `-i/-t` 都可能写 `data/result_data/rv130_1_0_3_44.json`，所以**绝对不能从 LEGACY_ROOT 直接运行这两条命令**。

### B.1 第一步：只读归档现有历史结果（不会修改旧仓库）

在已经运行 Step A 的同一 PowerShell 会话：

```powershell
$Stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ')
$BaselineDir = Join-Path $MigrationRoot ("baselines\rv130_1_0_3_44\" + $Stamp)
if (Test-Path -LiteralPath $BaselineDir) { throw '基线目录已存在；不覆盖' }
New-Item -ItemType Directory -Path $BaselineDir | Out-Null

if (Test-Path -LiteralPath $LegacyResult) {
    Copy-Item -LiteralPath $LegacyResult -Destination (Join-Path $BaselineDir 'preexisting.json')
    Get-FileHash -LiteralPath $LegacyResult -Algorithm SHA256 | Out-File -LiteralPath (Join-Path $BaselineDir 'legacy-result-sha256.txt')
}
Get-FileHash -LiteralPath $LegacyBinary -Algorithm SHA256 | Out-File -LiteralPath (Join-Path $BaselineDir 'input-sha256.txt')
& $LegacyPython -B -m pip freeze | Out-File -LiteralPath (Join-Path $BaselineDir 'legacy-pip-freeze.txt') -Encoding utf8
& $NewPython -B -m pip freeze | Out-File -LiteralPath (Join-Path $BaselineDir 'target-pip-freeze.txt') -Encoding utf8

# 可选：保留仓库引用与已有 dirty 状态（仅查询）
git -C "$LegacyRoot" rev-parse HEAD | Out-File -LiteralPath (Join-Path $BaselineDir 'legacy-commit.txt')
git --no-optional-locks -C "$LegacyRoot" status --short | Out-File -LiteralPath (Join-Path $BaselineDir 'legacy-status.txt')
git -C "$TargetRoot" rev-parse HEAD | Out-File -LiteralPath (Join-Path $BaselineDir 'target-commit.txt')
$Meta = [ordered]@{
    baseline_kind = 'existing_result_unclassified'
    captured_at_utc = $Stamp
    legacy_root = $LegacyRoot
    target_root = $TargetRoot
    legacy_python = $LegacyPython
    target_python = $NewPython
    binary_sha256 = (Get-FileHash -LiteralPath $LegacyBinary -Algorithm SHA256).Hash
    existing_result_sha256 = if (Test-Path -LiteralPath $LegacyResult) {
        (Get-FileHash -LiteralPath $LegacyResult -Algorithm SHA256).Hash
    } else { $null }
    source_repo_modified = $false
    rerun_status = 'not_started'
}
$Meta | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $BaselineDir 'manifest.json') -Encoding UTF8
Write-Host "Readonly baseline archived to $BaselineDir"
```

`preexisting.json` **只是历史结果，不得擅自将其标注为 `icall.json` 或 `taint.json`**：它可能包含两阶段中任一阶段或多个阶段的综合结果。需解析 schema、时间和依赖后确认。

### B.2 第二步：需要分别重现 -i/-t 时，创建独立副本（须批准）

建议放在：`MIGRATION_ROOT\baseline-work\rv130_1_0_3_44\<run-id>\EmTaint`，与原旧仓库分离。优先在 Windows 本地 NTFS 上复制需要的完整源码、`data/`、`firmware-binaries/`、元数据和配置；不要复制 `.venv`（仍使用旧解释器的绝对路径），不要使用 NTFS 硬链接、软链接、联接点或其他回写原位置的机制。

**复制前，先只读审计源码是否含硬编码绝对输入/输出路径，或读取进程工作目录以外的旧数据。** 即使切换工作目录，只要代码显式写旧目录，仍可能修改旧仓库。若无法确认，停在本步骤并报告风险，不执行分析。

经人工明确批准后，可用以下 PowerShell 命令复制到唯一的新工作目录：

```powershell
# 依赖 Step A/B.1 已定义 $MigrationRoot、$LegacyRoot、$BaselineDir、$LegacyPython
$RunRoot = Join-Path $MigrationRoot ("baseline-work\rv130_1_0_3_44\" + $Stamp + "\EmTaint")
if (Test-Path -LiteralPath $RunRoot) { throw '隔离运行目录已存在；不覆盖' }
New-Item -ItemType Directory -Path $RunRoot | Out-Null

# /XJ 跳过目录 junction；排除不可移植的虚拟环境和 Git 元数据。
robocopy "$LegacyRoot" "$RunRoot" /E /XJ /XD .git .venv __pycache__ /R:1 /W:1 /NFL /NDL
if ($LASTEXITCODE -ge 8) { throw "robocopy failed: $LASTEXITCODE" }

foreach ($p in @('main.py', 'firmware-binaries\rv130_v44\httpd', 'data')) {
    if (!(Test-Path -LiteralPath (Join-Path $RunRoot $p))) { throw "隔离副本缺少: $p" }
}

$RunResult = Join-Path $RunRoot 'data\result_data\rv130_1_0_3_44.json'
$CopySha = (Get-FileHash -LiteralPath (Join-Path $RunRoot 'firmware-binaries\rv130_v44\httpd') -Algorithm SHA256).Hash
$LegacySha = (Get-FileHash -LiteralPath $LegacyBinary -Algorithm SHA256).Hash
if ($CopySha -ne $LegacySha) { throw '固件样本 SHA256 不一致' }
Write-Host "RunRoot=$RunRoot"
```

注意：`robocopy` 对符号链接、重解析点、ACL 和少见文件类型的行为需在本机复核；`/XJ` 并不是完整的沙箱，不能代替源码中的写路径审计。若含指向旧仓库的链接，应先隔离处理，否则禁止运行。复制可能占用较大磁盘空间；运行前先评估样本目录体积。**Codex 不得自行删除旧副本或覆盖既存目录。**

### B.3 第三步：在隔离副本中重跑两个阶段（须另行批准）

仅在 B.2 路径检查、硬编码输出审计、权限审计、样本 SHA 验证通过后执行：

```powershell
$IcallLog = Join-Path $BaselineDir 'icall.log'
$TaintLog = Join-Path $BaselineDir 'taint.log'
$LegacyStatusBefore = (git --no-optional-locks -C "$LegacyRoot" status --porcelain) -join "`n"
$LegacyResultHashBefore = if (Test-Path -LiteralPath $LegacyResult) { (Get-FileHash -LiteralPath $LegacyResult -Algorithm SHA256).Hash } else { '' }

Push-Location $RunRoot
try {
    # 先 -i：修改的只能是隔离副本中的 data/；不得回写 ../EmTaint
    & $LegacyPython -B main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -i *> $IcallLog
    $IcallExit = $LASTEXITCODE
    if ($IcallExit -ne 0) { throw "隔离 -i 失败，退出码 $IcallExit，见 $IcallLog" }
    if (!(Test-Path -LiteralPath $RunResult)) { throw '隔离 -i 缺少结果 JSON' }
    Copy-Item -LiteralPath $RunResult -Destination (Join-Path $BaselineDir 'icall.json')

    # 再 -t：保留 -i 生成的所有中间数据，不能重新创建空副本
    & $LegacyPython -B main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -t *> $TaintLog
    $TaintExit = $LASTEXITCODE
    if ($TaintExit -ne 0) { throw "隔离 -t 失败，退出码 $TaintExit，见 $TaintLog" }
    if (!(Test-Path -LiteralPath $RunResult)) { throw '隔离 -t 缺少结果 JSON' }
    Copy-Item -LiteralPath $RunResult -Destination (Join-Path $BaselineDir 'taint.json')
} finally { Pop-Location }

# 检查两阶段输出；旧仓库状态/结果 hash 必须保持一致。
# 注意：此处检查仅覆盖 git 跟踪状态与一个 JSON；正式验收还需检查未跟踪的 IDA 元数据及其他关键文件。
$LegacyStatusAfter = (git --no-optional-locks -C "$LegacyRoot" status --porcelain) -join "`n"
$LegacyResultHashAfter = if (Test-Path -LiteralPath $LegacyResult) { (Get-FileHash -LiteralPath $LegacyResult -Algorithm SHA256).Hash } else { '' }
if ($LegacyStatusBefore -ne $LegacyStatusAfter -or $LegacyResultHashBefore -ne $LegacyResultHashAfter) {
    throw '检测到原旧仓库状态或历史结果变化：立即停止，人工核查，禁止再次运行'
}
Get-FileHash -LiteralPath (Join-Path $BaselineDir 'icall.json'),(Join-Path $BaselineDir 'taint.json') -Algorithm SHA256
Write-Host "Golden Data: $BaselineDir"
```

这只是最低限度的参考流程，**不是证明副本能绝对隔离的安全沙箱**。如果旧代码在导入阶段、配置读取阶段或日志写入阶段依赖硬编码绝对路径，不能运行之前的代码审计未通过时强行执行。另需核实本次输出不是之前复制的旧 JSON（对比写入时间、内容与日志）；将版本、参数、IDA 元数据 hash、额外副产物、退出码、耗时和覆盖情况写入 manifest。若发现任何可能回写旧仓库的路径，立即停止。

### B.4 补充的 P0 验收要求

- 旧仓库绝不修改；必要时在运行前后生成关键文件清单和哈希（不能仅靠 `git status` 检测未跟踪的 `data/` 变化）。
- 需要保留至少 `icall.json`、`taint.json`、对应日志与含路径、环境版本、二进制和 IDA 元数据哈希的 manifest；两阶段结果无法采集时记录 blocker，不得补造数据。
- 了解 `-t` 是否依赖先前 `-i`，确保真实 CLI 顺序与所需副产物。
- Baseline 文件置于 `emtaint-migration/baselines/`，不提交到 Git，不自动上传或覆盖。
- 在本机允许时重复独立运行以验证稳定性；如不稳定，保存多个 run ID 而不修改既有 Golden。

---

## Step C — 启动 Codex（全部在 Windows）

1. 在 VS Code 打开 `...\emtaint-migration\BinaryAnalysis`，确保已安装 OpenAI Codex 扩展，或使用本机 Codex CLI。
2. 把本资料包中的 **`AGENTS.md`、`MIGRATION_BLUEPRINT.md`、`CODE_TASK.md`** 放在 BinaryAnalysis 项目根目录（这些文档可以先作为未提交文件供 Codex 读取）。
3. PowerShell：

```powershell
Set-Location '<替换成实际绝对路径>\emtaint-migration\BinaryAnalysis'
git status --short
# 如已清理/保存当前修改，且分支不存在：
git switch -c refactor/emtaint-canonical-ir
codex
```

如果 `git status` 有用户其他未提交修改，先保存/确认再建分支；不要直接 `git reset --hard` 或 `git clean`。若已创建过同名分支，请改为 `git switch refactor/emtaint-canonical-ir`。

4. 先进入 `/plan`（或在任务中要求只读规划）；**P0-A 本身不需要任何写入权限**。在 Codex 中粘贴下面的 P0-A Prompt。
5. 日后每阶段仅对目标仓库允许工作区写入，对读取旧项目的授权仅用于只读操作；绝不要无条件开放两个仓库全部写权限。Codex 可能因为沙箱限制无法读取工作区外的旧仓库，此时单独允许**只读访问**或先把需要的清单复制到目标文档，不要使用相当于新增整个旧仓库写权限的绕过手段。

---

## Step D — Codex 通用执行约束（每个阶段自动适用）

执行下面提示词前，先读 `AGENTS.md` 和 `MIGRATION_BLUEPRINT.md`，且每个阶段按下列输出规范提供报告：

```text
1. 正在执行的阶段 ID；上一阶段 Gate 是否通过。
2. 唯一旧仓库 `../EmTaint` 的 commit、只读状态与隔离基线位置。
3. 具体准备修改的目标文件和函数；新增/变更的接口契约。
4. 先通过的 characterization tests，再实施小批量修改。
5. 每次测试的解释器绝对路径、命令、退出码、实际结果、失败堆栈。
6. 与 -i / -t 原始 Golden 的逐项差分（无基线时说明 blocker）。
7. 未支持 IR 操作、求解 unknown、图分析缺失的数量和影响。
8. Git diff 摘要；潜在回归和最小回退操作。
9. 完成当前阶段即停止，不自动进入下一阶段。
```

**阶段 P0-A：只读规划。** 此阶段不写业务代码。P0-B 在用户批准后允许创建归档/测试辅助文件。

### Prompt P0-A — 双仓库只读审计（第一条指令，直接复制到 Codex）

```text
你是 EmTaint→BinaryAnalysis 迁移项目的长期维护架构师。
先阅读当前目录 AGENTS.md、MIGRATION_BLUEPRINT.md、CODE_TASK.md。
本轮严格只读：不修改任何文件、不安装依赖、不运行旧 -i/-t、不修改 Git、不要清理结果。

当前目录是 Windows 下 `emtaint-migration/BinaryAnalysis`；新 Python 为 `.venv\Scripts\python.exe`（angr==10.0.5）。
**唯一**旧仓库是 `../EmTaint`，旧 Python 为 `../EmTaint/.venv/Scripts/python.exe`（angr==9.0.9792）。旧源码、`data/`、样本、`.venv/` 一律只读；先检查 `main.py`、元数据、样本、Git 状态和解释器版本，不再搜索所谓外层/内层旧仓库。

任务：
1. 核实路径、解释器、两个 angr 版本、Python ABI、sys.path、Claripy 导入和 solver API，识别依赖污染。
2. 阅读原始 main.py 的 -i、-t、--resolve_icall、结果写入与执行顺序；说明两个命令如何影响同一 JSON。
3. 遍历旧 dataflow 和新 emtaint，给出具体模块/符号/调用链、依赖和可迁移价值；对每条结论列文件及函数证据。
4. 确认 VEX 与 IDA 元数据获取方式、多个 IRSB 与 IDA 基本块映射、FastSearch/SSE/污点以及当前目标原型缺陷。
5. 收集新旧 angr/pyvex/Claripy API 差异点，尤其 AST 操作、替换、求解、type/isinstance、caching/hash；区分已实测与尚待验证。
6. 设计 P0-B Golden Data 采集计划、old-to-new module map、风险与可执行回归测试矩阵。
7. 在回答中给出下一步最小可验证任务；不要现在执行重构。

本轮只输出检查结果和待审核计划，不写任何文件。无法访问 sibling 时说明具体限制，不伪造结论。
```

### Prompt P0-B — 经批准后建立 Golden 与比较器（仅本阶段）

```text
执行 P0-B：目标是生成真实、可信的旧 EmTaint Golden Data 与可审计比较器；不重构分析算法。
先只读归档 `../EmTaint/data/result_data/rv130_1_0_3_44.json`，记录旧仓库状态和样本 SHA256；该现有文件不得作为已确认分阶段 Golden。
在确认用户批准、且检查旧代码没有绝对路径写回原仓库后，构建 `../baseline-work/<run-id>/EmTaint` 的独立物理副本；新 `RUN_ROOT` 必须包含旧命令依赖的所有 IDA 元数据及样本。
**仅在 RUN_ROOT** 先执行 -i 并快照 icall.json/log，再在同一副本中执行 -t 并快照 taint.json/log。绝不在只读 `../EmTaint` 中执行可能修改 `data/` 的分析命令。
在目标仓库 docs/migration 下写 INVENTORY.md、LEGACY_CLI_CONTRACT.md、API_COMPAT_MATRIX.md、BASELINE_SCHEMA.md 和阶段报告。
若需创建脚本，把 scripts/legacy_baseline.ps1 放目标仓库；脚本默认 dry-run，必须显式授权开关才能执行会覆盖旧输出的命令。
在 `../baselines` 中保存 Golden（不进 Git），构建结果对比器，解释间接目标、CG、污点和 finding 差异；还须核查旧仓库文件/结果未改变。不得修改 Golden 以使测试通过。
如任何前置条件不满足，停止并明确列出 blocker。完成 P0-B 后停止。
```

### Prompt P1 — angr 10.0.5 / Claripy 兼容层

```text
只执行 P1（前提 P0 已通过）。不改写污点、SSE 或间接调用算法。
1. 真实扫描 legacy 全部 angr/pyvex/claripy/cle/archinfo API 使用点、目标仓库调用点，生成调用点矩阵（文件/行/旧行为/新 API 实测/适配/测试）。
2. 用旧 Python 和新 Python 单独运行 introspection + contract probes；不得用旧 Python 导入新项目或安装旧 Claripy 到目标环境。
3. 针对 angr 10.0.5 实现边界层：lifter/provider API 可封装到 frontend；SolverPort + ClaripyAdapter 可封装到 solver。
4. 覆盖 BVS/BVV、位宽、AST 遍历/替换/简化、求解、SAT、超时、异常、structural key，禁止基于猜测修改全项目的 isinstance 类型判断。
5. 必须实际运行 tests/conformance/test_solver_contract.py（或等价真实测试），汇报所有缺失操作与风险。
6. 不升级/降级任何依赖，不动旧仓库源码。通过后停止。
```

### Prompt P2 — Program/CFG/CG 核心模型

```text
只执行 P2：检查 BinaryAnalysis 当前 assembly/program/graph/cfg/pag 代码后，设计稳定 Program/Function/BasicBlock/CallSite/AddressSpace/Architecture/ABI/Session 接口。
修复有证据的现有原型问题（类型、tuple 尾逗号、硬编码地址等）；保留向旧类兼容的 Facade。
核心领域模型不能导入 angr、pyvex、IDA。建立独立手工构造 Program 的 CFG/CG/edge/ID/cache tests，不触碰 SSE/taint。
完成报告并停止。
```

### Prompt P3 — Canonical IR（不要直接迁移 VEX 子类）

```text
只执行 P3：定义脱离 pyvex 的 Canonical IR；推荐 typed non-SSA effect-based IR，含 Expr/Stmt/Terminator/Origin/ABI 与 versioned serialization。
为位宽/符号/zero-sign-extend/Extract/Concat、端序、寄存器别名、Load/Store、Guard/Jump/Call/Return、未知外部副作用编写手工语义测试。
严格模式对 unsupported 抛可追踪异常；保守模式生成 Opaque/Havoc/UnknownEffect 并设置 incomplete，禁止静默略过。
本阶段不迁移旧污点算法、不把 VEX/Claripy native AST 放进公共 IR。结束后展示依赖扫描结果及测试报告。
```

### Prompt P4 — 两条 VEX 前端（直连 angr / 兼容 IDA+VEX）

```text
只执行 P4：
A. 实现 AngrVexFrontend：angr 10.0.5 读取 binary/arch/CFG（如适用）与 VEX，转换为 CIR。
B. 实现 IdaVexFrontend：读取原 EmTaint IDA CFG、block、switch、icall 元数据，用 angr 10.0.5 对真实 binary byte ranges lifting，再转换 CIR。
复核 .vex、IRSB、IMark、Exit、next、jumpkind 和条件 Load/Store 在 angr 10 API 的真实变化。
处理一个 IDA Block 对应多个 IRSB 的情况；保留原始地址/provenance；对不支持 IR 明确报告。
旧 IDA exporter 可先保持不变，不在此阶段要求升级 IDA。取消硬编码单个函数地址，添加跨多个函数/架构的有限测试。
在当前已有测试基线上出 CIR 统计和 CFG 差分；不得因 CFG 相同就声称 SSE/漏洞已迁移成功。
```

### Prompt P5 — SSE / Claripy / Memory / Alias

```text
只执行 P5：先为 legacy VarExpr、TraceExpr、SimAction、parse_ast 的关键场景编写双环境行为对照（或结构化 Golden），再分离 SymbolicDomain、MemoryDomain、AliasAnalysis。
通过 P1 的 ClaripyAdapter 使用 angr 10 的 Rust/Claripy API；不得把原生 AST 类型暴露到 Canonical IR。
优先沿用旧表达式替换、表达式约束、内存指针/结构偏移、别名、强/弱更新逻辑；遇 AST 差异以可验证语义适配，不简化为常量或 unknown 以欺骗测试。
测试典型 pointer arithmetic、stack/global/heap、structure field、Load/Store 和 solver unknown。
旧 SSE 表达式的每项差异必须列具体案例和根因；通过后停止。
```

### Prompt P6 — Dataflow、Switch、间接调用恢复与 CG 更新

```text
只执行 P6：从 FastSearch 拆出 session、worklist、fast/accurate transfer、procedure summaries、图更新机制、switch/indirect-call 分析 Pass。
保留原有计算次序/传播语义，只有通过对照用例才可替换算法。CallGraph/CFG 更新后标记相关 summaries/facts 失效并增量重分析。
使用 rv130 -i 的真实 icall.json Golden 比较：已知函数、callsite、目标集合、证据、CG 边和分析完整性。
不能仅比较 recovered_icall 数量；unknown target 和 solver timeout 明确输出；不改造尚未到阶段的污点规则。
通过后停止。
```

### Prompt P7 — 污点类漏洞与兼容 CLI

```text
只执行 P7：将 Source/Sink/ProcedureSummary/Sanitizer/Guard/Taint propagation/漏洞机制判定与结果收集迁入独立模块，保持 buffer overflow、command injection 等旧有类别和告警证据。
实现 Windows 下 BinaryAnalysis -i、-t 可用 CLI 入口，参数与原 main.py 尽量兼容，输出到目标仓库的独立路径，绝不覆盖 legacy data/result_data/rv130_1_0_3_44.json。
先跑 -i，保留中间 CG；再跑 -t，比较基线 taint.json 的 source/sink/路径/finding 及缺失原因。
避免仅以污点可达就判定漏洞；保留原 security_check 的守卫/约束逻辑直到逐项差分证明等价。
命令、退出码、日志、结果 schema 和 Gate 报告齐全后停止。
```

### Prompt P8 — IDA Microcode Frontend（基于已完成的 CIR）

```text
只执行 P8：新增 IdaMicrocodeFrontend，先选择有限函数和可控成熟度（例如 MMAT_LOCOPT，须以安装版本 API 为准）。
IDA/Hex-Rays 环境独立导出 portable MicrocodeSnapshot，至少含 function/block/operation/operands、width、控制流、来源地址、ABI、IDA version、maturity 和 binary SHA。
在 Windows BinaryAnalysis 的 Python 10.0.5 环境中解析 snapshot 并转换为相同 CIR，不依赖 IDA 原生 Python 对象、不先转 VEX。
为 microcode opcode 覆盖与 unsupported 建立报表，对 VEX 后端比较可观察语义（读写、分支、call、污点），不要求 IR 行数或变量编号一致。
未安装 IDA 时可仅用 fixture 快照测试；不得声称已完成真实 IDA 集成测试。通过后停止。
```

### Prompt P9 — 清理、性能评估与发布

```text
只执行 P9：执行全矩阵回归，汇总 P0-P8 的能力覆盖和 angr10 API 兼容报告。对废弃代码先输出引用证据及候选删除清单，经审核后再删除；禁止大范围自动格式化。
比较同一 rv130 的 -i/-t 数据流、CG、污点路径与 finding；报告构造 IR 成本、analysis time、memory、函数覆盖和 unsupported 率。
检查依赖边界、Git 状态、CLI/JSON 兼容性、版本锁定和文档，提出 release/tag 与 rollback 方案。不可自动 git push 或升级依赖。结束后停止。
```

---

## Step E — 审查 / Gate / 回退模板

### E.1 审查操作

在 VS Code 或 Codex 的当前任务结束后，先检查：

```powershell
git status --short
git diff --check
git diff --stat
git diff
```

Codex 内使用 `/review`，专门要求审查 *IR 语义丢失、Claripy API 不兼容、间接调用目标漏失、CG 增量更新遗漏、污点漏报、异常吞噬、基线/旧环境意外修改*。

### E.2 常见失败分类（报告必须注明）

| 分类 | 典型迹象 | 应采取的动作 |
|---|---|---|
| ENV | Windows `../EmTaint/.venv` 或目标 `.venv` 不存在/错误版本 | 停止；确认解释器与 ABI；不自动安装 |
| API | angr10 找不到旧类/参数或 AST API 异常 | 最小复现；补 compatibility adapter/契约测试 |
| LIFT | IR 转换缺项、位宽/Jumpkind 错误 | Strict diagnostic；保守状态 incomplete；不能 `continue` |
| CFG | 基本块切分/目标边不一致 | 比较 ISA、IDA 来源和多 IRSB 地址映射 |
| SOLVER | Rust Claripy expression replace/hash/simplify 差异 | 与旧版对照，修适配器，保持 unknown 状态 |
| TAINT | 老版 source→sink 路径丢失 | 找到最早失真的 IR/DefUse/调用边，不直接改 Golden |
| RESULT | JSON 字段/路径/顺序不一致 | Schema-aware normalize，保留原始结果 |
| PERFORMANCE | 运行时间上升或循环不收敛 | 相同预算重测，记录 graph update/pass iterations |

### E.3 回退规则

- 每阶段单独 Git commit 或分支 checkpoint；未提交修改需要人工确认处置，**不自动使用** `git reset --hard`、`git clean`。
- `../EmTaint` 所有文件（包含 Git、`.venv`、IDA `data/`、固件及历史 JSON）均不改；仅在 `../baseline-work` 副本复现基线，Golden Data 是不可变参照。修改新代码造成回归时，只回退目标仓库本阶段相关变更。
- 如果本地旧工程基线依赖未跟踪文件，应记录且保护它们，不在 `git clean` 中丢弃。
- 迁移期间维持兼容执行路径或 feature flags，直到用户确认新实现通过所有 Gate。

---

## Step F — 项目完成定义（Definition of Done）

只有满足以下条件，才可将此次迁移标记为完成：

- [ ] `../EmTaint/.venv/Scripts/python.exe` 与目标 `.venv/Scripts/python.exe` 已隔离并经探测；旧仓库各类文件未修改。
- [ ] 旧 `-i/-t` 在获准的隔离副本中复现并分阶段保存结果/Manifest/输入 hashes；原始旧仓库保持只读。
- [ ] 新 `-i/-t` 实现经过相同样本和已解释的差分测试（保留核心结果/证据）。
- [ ] Core / IR / Analysis 没有原生 VEX/IDA 导入，手工 IR 分析单测可独立运行。
- [ ] Claripy/Rust 兼容矩阵覆盖 SSE 实际用到的 API，unsupported/timeout 均可观察。
- [ ] VEX、IDA+VEX 两个前端可交付；IDA Microcode 有至少一个真实/fixture 支持子集和语义测试。
- [ ] 有迁移过的 SSE/alias/iCall/CG/taint/bugfinder 回归用例，旧 Golden 的差异逐例说明。
- [ ] 没有以“正常结束、零告警”代替分析完整性与漏洞检测正确性。
- [ ] 每阶段报告、测试命令、Git 回退点和未支持能力都被记录。

## 第一次正式操作（只需要以下一条提示词）

在 BinaryAnalysis 打开 Codex 后发送：

```text
请先阅读 AGENTS.md、MIGRATION_BLUEPRINT.md、CODE_TASK.md。
现在执行 CODE_TASK.md 的 Prompt P0-A：双仓库只读审计。
只读，不要修改文件、不要安装或升级依赖，也不要运行可能覆盖旧结果的 -i/-t。
请先核实实际旧项目位置与两个 Python 环境，再给出有代码证据的迁移计划与 P0-B 基线采集审批清单。
完成后停止，等待审核。
```

