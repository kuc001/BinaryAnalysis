# BinaryAnalysis task backlog

This is the dependency queue for bounded tasks, not a second execution plan. Milestone status and goals live in `EXECUTION_PLAN.md`; task format lives in `TASK_SPEC_TEMPLATE.md`; gate rules live in `CODEX_WORKFLOW.md`; evidence lives in `BUILD_LOG.md`. Active work uses NOT_STARTED, PLANNED, IN_PROGRESS, BLOCKED, IMPLEMENTED, VERIFIED, REVIEWED, APPROVED. `CANCELLED` is an owner withdrawal disposition for B1-GUARD, not an implementation or approval state. Only the project owner records APPROVED. A row is not authorization to start its successor.

| ID | Milestone / priority | Bounded outcome | Dependencies and decision gate | Status | Acceptance / evidence |
|---|---|---|---|---|---|
| R1-A | Research / P1 | Audit local legacy dataflow and map four algorithms to the accepted architecture without code changes | Owner R1-A research scope; local snapshot, runnable checkout for later comparison; implementation still needs C/F/G contract gates | IMPLEMENTED | Overview, detailed audit, migration map, 164-file hash manifest and allowlist drafted; static checks/review pending; owner review before algorithm migration |
| GOV-001 | Pre-B1 / P1 | Establish architecture-first Codex governance in the seven permitted Markdown files | Current A2/B0 documents and user scope | VERIFIED | Seven gates/eight states and new docs checked; `git diff --check` clear; owner review pending |
| B0-TECH-REVIEW | B0 / P0 | Verify reset dependencies, guard behavior, ADR impact and B1 ordering without code changes | A2/B0 documents and current checkout | VERIFIED | `RESET_MANIFEST.md` corrections, 12-row ADR matrix, B1 graph/spec; static coverage and diff checks; owner review pending |
| ADR-REVIEW | A2/B0 / P0 | Record owner’s scoped architecture decisions and remaining contract details | `DECISIONS.md`, `ARCHITECTURE.md`, `ACQUISITION_DESIGN.md`, `RESET_MANIFEST.md` | IMPLEMENTED | ADR-001–008/010–012 Accepted directions; ADR-009 Proposed; C/D/E contracts still need freeze |
| B0-REVIEW | B0 / P0 | Owner reviews reset manifest, protected data and verification policy | `RESET_MANIFEST.md`, GOV-001, B0-TECH-REVIEW | PLANNED | New guard-removal plan awaits owner approval; no B2 deletion or full manifest approval inferred |
| B1-GUARD | B1 / withdrawn | Migration of WriteGuard to package | Owner revoked authorization: auxiliary P1–P7 mechanism is outside target product architecture | CANCELLED | No code was implemented for this task; never mark IMPLEMENTED |
| B1-CLI | B1 / P1 | Remove CLI guard import/install/restore/violation reporting while preserving output preflight, command receipts and normal modes | Approved new B1 cleanup spec; coordinate receipt fields with B1-SOURCE | NOT_STARTED | iCall/taint CLI run into explicit output folder; errors and status remain observable; no guard dependency |
| B1-SOLVER | B1 / P1 | Remove worker guard dependency while preserving request/response subprocess protocol and explicit private output folder | Approved new B1 cleanup spec; no guard package prerequisite | NOT_STARTED | Query response, timeout, failure, request/result/process receipts and cache path verified end to end |
| B1-LEGACY | B1 / P1 | Remove target/child guard and readonly bootstrap dependency while preserving supported legacy mode and any necessary parser/launch behavior | Approved legacy preservation spec; ADR-009 retirement remains Proposed; coordinate source/hash format with B1-SOURCE | NOT_STARTED | Old-Python child launch and legacy CLI mode still work without `_p0b_bootstrap.py` or guard; plan/resume/hash compatibility explicitly resolved |
| B1-ACQUIRE | B1 / P1 | Remove guard use from existing `p7_acquire.py` producer, keeping FunctionStore inputs and output layout | Approved new B1 cleanup spec; no C/D prerequisite for decoupling | NOT_STARTED | Fresh per-function outputs, report and FunctionStore consumption verified; generator retained until D replacement |
| B1-SOURCE | B1 / P1 | Reconcile `source_manifest`, sealed helper lists and legacy plan hashes with retained executable dependencies | B1-CLI, B1-LEGACY, B1-SOLVER, B1-ACQUIRE scope decisions; approved receipt compatibility spec | NOT_STARTED | No hash of removed helper; historical receipts remain interpretable; diagnostic replay handling explicit |
| B2-CLEAN | B2 / P1 | Remove owner-approved obsolete files, including `p1_runtime.py` and `legacy_readonly_bootstrap.py` only after all live dependencies are gone | Verified B1 decoupling, B1-SOURCE, B1-ACQUIRE or D replacement for producer, owner per-file deletion list and data review | NOT_STARTED | No production/CI/CLI/docs refs to removed helpers; Solver/Acquisition/Legacy retained behavior verified; protected files intact |
| B3-ENTRY | B3 / P1 | Consolidate CLI, package metadata and docs around working services | B2-CLEAN, applicable C/D services and owner scope | NOT_STARTED | Current supported commands and new approved commands work; no false CLI promise |

## B1 dependency review

```text
B0-TECH-REVIEW -> owner approval of new B1 cleanup specification
                         |
             +-----------+-----------+------------+
             v           v           v            v
          B1-CLI     B1-SOLVER   B1-LEGACY    B1-ACQUIRE
             \           |           |           /
              +----------+-----------+----------+
                         v
                     B1-SOURCE
                         v
                     B2-CLEAN (per-file owner approval)
```

There is no B1 cycle and no shared guard API to create. B1-CLI/SOLVER/LEGACY/ACQUIRE can be scoped independently; edits to `emtaint/cli.py`, `scripts/legacy_baseline.py` and receipt schemas must be sequenced with B1-SOURCE rather than made concurrently. B1-SOURCE follows executable-path decisions, then B2 can remove obsolete helpers after all references are gone and the owner approves exact deletions. Full Acquisition Service replacement remains D after C; B1-ACQUIRE retains the current producer. ADR-009 does not authorize retirement of the Legacy Backend. If its necessary child-launch/parser behavior cannot be separated from the readonly bootstrap without broader design, stop for owner decision rather than deleting the mode or reintroducing a guard.

### Independent B1 task boundaries

| Task | Scope | Non-Goals | Acceptance |
|---|---|---|---|
| B1-CLI | Remove only guard lifecycle and violation fields from CLI; preserve explicit output-directory validation and ordinary receipt/error handling | No CIR/HIR, algorithm or CLI mode redesign | iCall and taint paths use the selected output folder and still produce success/failure receipts without a guard import |
| B1-SOLVER | Remove guard lifecycle from `p1_solver_worker.py`; keep `process_port.py` request directory, subprocess and result protocol | No solver algorithm or worker relocation required for this removal | One request round-trip, timeout/failure, result receipt and cache location verified |
| B1-LEGACY | Separate necessary old-Python launcher/parser behavior from guard-only bootstrap and remove guard-specific plan/report fields | No Legacy Backend retirement or new sandbox/monkeypatch | Legacy mode, child process, plan/resume and retained evidence work without guard/bootstrap dependency |
| B1-ACQUIRE | Remove guard lifecycle/report condition from current acquisition producer, retaining its explicit fresh folder and function artifact writes | No full D service or producer deletion | Fresh acquisition report/functions remain readable by FunctionStore; errors propagate/report as specified |
| B1-SOURCE | Remove obsolete helper hashes/list entries once executable paths are settled; define historical receipt handling | No universal cache redesign or retroactive rewriting of user data | Source receipt reproducible; retained semantic dependency changes detectable; diagnostic consumers handled |

## B1-GUARD — cancelled owner decision

**Disposition: CANCELLED, 2026-11-10.** The owner withdrew prior migration authorization because WriteGuard, ProbeWriteGuard, ForbiddenMutation and Legacy Readonly Bootstrap are P1–P7 auxiliary controls, outside the target product architecture. The proposed package API, new guard tests, hardening plan and old acceptance criteria are withdrawn. No B1-GUARD production code was implemented; cancellation is not IMPLEMENTED, VERIFIED or APPROVED. This decision does not accept ADR-009 or authorize deletion in this documentation-only round.

The replacement work is removal of guard-only code and dependencies after new B1 task specifications are approved. Do not migrate, rename, or recreate the monkeypatch or turn it into an OS sandbox. Keep independent Solver query execution, Acquisition artifact production, CLI output/receipt handling and supported Legacy Backend behavior. In the future code slice, remove `install()`, `restore()`, `violations`, `guarded_open`, `ForbiddenMutation` handling and guard-only receipt/status fields from each live caller; preserve ordinary exceptions and output-path preflight.

**Current output ownership:** CLI validates an explicit new/resumed `.p7-work` folder and writes cache/command/error receipts there; solver parent creates `.p1-work/solver-requests/<request>` with `cache`, request, process and result receipts; acquisition requires a fresh `.p7-work/<run>` and writes loader, per-function and acquisition reports; legacy uses a physical RunRoot and separate archive. Keep these explicit destinations and exclusive-create behavior where currently used. `TEMP`/`TMP`/`TMPDIR`, `tempfile.tempdir` and `PYTHONDONTWRITEBYTECODE` are process/cache settings with possible independent purpose; evaluate each before removal. They are not a replacement guard.

**Unresolved legacy dependency:** `legacy_readonly_bootstrap.py` contains old-Python actions and PLY parser setup in addition to WriteGuard; `legacy_baseline.py` copies it as `_p0b_bootstrap.py`, launches it, and checks its hash and `violations`. `p7_legacy_reference.py` embeds the bootstrap hash in plan/resume validation. B1-LEGACY must specify the retained child entry, parser behavior, plan/resume compatibility and historical receipt handling before the guard-specific bootstrap is deleted. ADR-009 stays Proposed. `p1_runtime.py` has only the ProbeWriteGuard subclass; it can be deleted after all live and approved historical consumers are removed or retired under B2's exact-file approval.

**Verification gate for later code work:** static search finds no production `WriteGuard`, `ProbeWriteGuard`, `ForbiddenMutation`, `p1_runtime` or `_p0b_bootstrap.py` reference; CLI, Solver, Acquisition and supported Legacy paths execute through their complete data flows with clear output directories and ordinary error reporting. Record exact commands, results, skipped checks, changed files and remaining risk in `BUILD_LOG.md` during implementation. This review ran no tests or Python production code. Stop before implementation until the owner approves the revised B1 cleanup specifications and deletion sequence.
