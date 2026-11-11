# BinaryAnalysis build and verification log

Record evidence for each bounded task. This log does not approve an ADR or milestone. Commands, exit codes, observed outputs, skipped checks and affected artifact IDs belong here; status is mirrored in `BACKLOG.md` and `EXECUTION_PLAN.md`. Codex does not commit or push by default.

## GOV-001 — Pre-B1 governance enhancement (2026-11-10)

- **Baseline:** `codex/icall`, HEAD `3716b9648aa5b683a62b6f4e34d277ab547202a3`; pre-existing changes to `ACQUISITION_DESIGN.md`, `ARCHITECTURE.md`, `DECISIONS.md`, `EXECUTION_PLAN.md`, `REPOSITORY_AUDIT.md`, plus untracked `RESET_MANIFEST.md` and `docs/Task03.md`. These were read/preserved; this task edits only its seven allowed Markdown paths.
- **Scope:** update `AGENTS.md`, `CODEX_WORKFLOW.md`, `EXECUTION_PLAN.md`, `ENGINEERING_STANDARDS.md`; create `TASK_SPEC_TEMPLATE.md`, `BACKLOG.md`, `BUILD_LOG.md`.
- **Design decision:** AGENTS holds short durable rules; WORKFLOW owns gates/change control/status; STANDARDS owns Definition of Done; PLAN owns milestones; TEMPLATE specifies tasks; BACKLOG owns dependency queue; this log owns evidence. A2/B0 remain proposals pending owner review; B1 is not started.
- **Verification:** `git diff --check` exited without whitespace errors (Git emitted only LF→CRLF notices). A read-only Python 3.12 document check found all seven gate names and eight status values, three new files with final newlines, and no trailing whitespace in the seven edited/created files. `git status --short` confirmed no Python/code changes and preserved the pre-existing B0 edits, `RESET_MANIFEST.md` and `docs/Task03.md`. No runtime tests or benchmarks were run.
- **Status:** VERIFIED for the documentation scope. Architecture compliance review and owner approval are not recorded; B1 remains NOT_STARTED.

## R1-A — local legacy algorithm research (2026-11-10)

- **Scope and baseline:** owner-supplied R1-A documentation-only task plus local-source priority clarification; `codex/architecture-reset`, HEAD `2176e78f7cc410838603912886b35be7cf39c5d1`, clean at start. `references/legacy-emtaint` is tracked inside BinaryAnalysis and has no nested Git metadata; its original EmTaint commit is unknown. Runnable comparison checkout `emtaint-migration/EmTaint` HEAD `72a9e3081632b2f9d1881141bc7b0d43c7158033` was identified, not run.
- **Evidence produced:** 164 local `dataflow/` files listed and SHA256-hashed in `LEGACY_DATAFLOW_SNAPSHOT.md`; source-backed module map, four algorithm chains, migration/dependency map, allowlist and architecture/plan/backlog updates. A later source check found the unused and inconsistent `_initialize_taint_source` path and corrected the taint audit to identify reachable procedure-model initialization.
- **Static commands/results:** `git status --short --branch` initially reported no changes; `rg --files references/legacy-emtaint/dataflow` and `Get-ChildItem ... -Recurse -File` each counted 164; `git log -1 -- references/legacy-emtaint` identified containing commit; `Get-FileHash -Algorithm SHA256` rechecked all 164 manifest rows with **0 mismatches**; `git diff --check` exited 0. `rg` and `Get-Content` were used to inspect callsites and source ranges. No Python production code, legacy analysis, tests, network source, commit or push was used.
- **Gates/status:** repository baseline and documentation scope established. R1-A deliverables are IMPLEMENTED. Static consistency checks are recorded, but full independent algorithm review, runnable behavioral comparison and owner acceptance remain open. C/F/G contract freezes and code slices are not authorized by this work. No schema or Python code changed.

## Entry format for future work

### Task ID / date / baseline

- Approved task scope and dependencies:
- Priority and applicable gate/ADR/ACR:
- Input fixture/artifact IDs and expected property:
- Exact commands, exit codes and observed results:
- System path checked (input → representation → analysis → result/evidence):
- Partial/unsupported/failure and cache/invalidation checks:
- Diff and architecture compliance reviewer/findings:
- Skipped checks and risk:
- Status transition with evidence; owner approval reference if any:
- Git submission (owner action or explicit delegation only):

### Root-cause note after two unsuccessful targeted changes

- One acceptance issue and minimal reproducer:
- Expected versus observed:
- First targeted change, hypothesis and check result:
- Second targeted change, hypothesis and check result:
- Upstream/downstream causal path and competing hypotheses:
- Violated or uncertain contract; ACR ID if needed:
- Revised plan, owner decision needed, and condition to resume:
