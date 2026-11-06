# Native alias query CLI (in progress)

The `-a` mode analyzes an ELF binary without firmware acquisition or IDA metadata.
It uses CIR lifting, `AliasProcedureDemand`, procedure summaries, and
`MemoryQueryPort.alias`. The output is a new directory under `.p7-work/` with
`alias-query.json` (schema `emtaint-alias-query-v1`).

Manual query at a binary callsite:

```powershell
.venv/Scripts/python.exe -m emtaint -a -f path/to/sample.elf `
  --function main --site 0x4009d0 --left arg:0 --right arg:1 `
  --output .p7-work/alias-manual-001
```

`arg:N` identifies the Nth CIR call argument at that exact site. Additional
manual locators are `reg:NAME` (register value before the call), `mem:0xADDR`
(pointer-sized value stored at an absolute address before the call), and
`addr:0xADDR` (the pointer literal). They use the same demand and memory
query path. Source-level variable names still require a proven binary location
mapping; unsupported names raise `VARIABLE_MAPPING_UNAVAILABLE`. DWARF
variable locators are not available. Caller-context specialization currently
applies to an `arg:0`/`arg:1` pair; other locator pairs use the stated
function-local program point.

Scan calls to configured pure observer functions:

```powershell
.venv/Scripts/python.exe -m emtaint -a -f path/to/sample.elf `
  --discover-alias-calls --observe-call Alias `
  --output .p7-work/alias-scan-001
```

Each observation records the function, absolute callsite, observer symbol,
prediction, alias kinds, evidence, completeness and reason codes. Exit 0 means
all discovered observations are complete; exit 2 means at least one is
incomplete. A scan with no observations is not proof of marker coverage;
test adapters must compare the binary observations with an independent source
inventory. The CLI never reads source expectations.
