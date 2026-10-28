param(
    [switch]$Execute,
    [switch]$Profile,
    [switch]$ValidateIsolationOnly,
    [ValidateRange(1, 5)][int]$Repetitions = 2
)
$ErrorActionPreference = 'Stop'
$TargetRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$TargetPython = Join-Path $TargetRoot '.venv\Scripts\python.exe'
$env:PYTHONDONTWRITEBYTECODE = '1'
$Arguments = @('-B', (Join-Path $PSScriptRoot 'legacy_baseline.py'), '--repetitions', "$Repetitions")
if ($Execute) { $Arguments += '--execute' }
if ($Profile) { $Arguments += '--profile' }
if ($ValidateIsolationOnly) { $Arguments += '--validate-isolation-only' }
& $TargetPython @Arguments
exit $LASTEXITCODE
