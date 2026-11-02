[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Icall', 'Taint')]
    [string]$Mode,
    [Parameter(Mandatory = $true)]
    [string]$BinaryFile,
    [Parameter(Mandatory = $true)]
    [string]$IdaData,
    [Parameter(Mandatory = $true)]
    [string]$Acquisition,
    [string]$FirmwareName = 'rv130',
    [string]$FirmwareVersion = '1_0_3_44',
    [string]$IcallInput,
    [string[]]$TaintFunctions,
    [int]$FunctionSeconds = 120,
    [ValidateRange(1, 15)]
    [int]$TaintRounds = 15
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "BinaryAnalysis interpreter not found: $python"
}

$binary = (Resolve-Path -LiteralPath $BinaryFile).Path
$ida = (Resolve-Path -LiteralPath $IdaData).Path
$acquisitionPath = (Resolve-Path -LiteralPath $Acquisition).Path
$parent = Join-Path $root '.p7-work\manual-debug'
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMddTHHmmss'
$run = Join-Path $parent ($stamp + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))

if ($Mode -eq 'Taint') {
    if (-not $IcallInput) {
        throw '-IcallInput is required for Taint mode.'
    }
    $frozen = (Resolve-Path -LiteralPath $IcallInput).Path
    $required = @('icall.json', 'icall-targets.json')
    foreach ($name in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $frozen $name) -PathType Leaf)) {
            throw "Missing frozen iCall receipt: $name"
        }
    }
    New-Item -ItemType Directory -Path $run | Out-Null
    foreach ($name in $required) {
        Copy-Item -LiteralPath (Join-Path $frozen $name) -Destination (Join-Path $run $name)
    }
}

$arguments = @(
    '-B', '-m', 'emtaint',
    '-f', $binary,
    '-n', $FirmwareName,
    '-v', $FirmwareVersion,
    '--ida-data', $ida,
    '--acquisition', $acquisitionPath,
    '--output', $run,
    '--log-level', 'DEBUG',
    '--log-file', ('debug-' + $Mode.ToLowerInvariant() + '.jsonl'),
    '--log-format', 'jsonl',
    '--log-console',
    '--log-console-level', 'INFO'
)
if ($Mode -eq 'Icall') {
    $arguments += '-i'
} else {
    $arguments += @('-t', '--function-seconds', $FunctionSeconds, '--taint-rounds', $TaintRounds)
    if ($TaintFunctions) {
        $arguments += '--taint-functions'
        $arguments += $TaintFunctions
    }
}

Push-Location $root
try {
    & $python @arguments
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

Write-Host "Debug output: $run"
Write-Host "Structured log: $(Join-Path $run ('debug-' + $Mode.ToLowerInvariant() + '.jsonl'))"
if ($Mode -eq 'Icall') {
    $manifestPath = Join-Path $run 'icall.json'
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        Write-Host ("iCall summary: status={0}, sites={1}/{2}, targets={3}, rounds={4}, pending={5}" -f `
            $manifest.status, $manifest.observed_sites, $manifest.input_sites, $manifest.target_entries, `
            $manifest.rounds, @($manifest.graph_pending).Count)
        foreach ($name in @('icall.json', 'icall-targets.json', 'cg-logical-edges.json')) {
            $artifact = Join-Path $run $name
            if (Test-Path -LiteralPath $artifact -PathType Leaf) {
                $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash
                Write-Host ("SHA256 {0} {1}" -f $hash, $name)
            }
        }
    }
    $logPath = Join-Path $run 'debug-icall.jsonl'
    if (Test-Path -LiteralPath $logPath -PathType Leaf) {
        $events = @(Get-Content -LiteralPath $logPath -Raw | ConvertFrom-Json)
        Write-Host ("Log summary: events={0}, function-runs={1}, rounds={2}, errors={3}" -f `
            $events.Count, @($events | Where-Object event -eq 'icall.analysis.completed').Count, `
            @($events | Where-Object event -eq 'icall.search.round.completed').Count, `
            @($events | Where-Object level -eq 'ERROR').Count)
    }
}
exit $exitCode
