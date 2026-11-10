# Codex development workflow for BinaryAnalysis

This is the detailed process behind the short rules in `AGENTS.md`. Product intent is in `CODEX_TASK.md`; architecture and artifact contracts are in `ARCHITECTURE.md` and `ACQUISITION_DESIGN.md`; engineering criteria are in `ENGINEERING_STANDARDS.md`. `DECISIONS.md` records proposed/owner-approved architecture decisions. `EXECUTION_PLAN.md` owns milestone dependencies and status. `BACKLOG.md` owns bounded task dependencies; `TASK_SPEC_TEMPLATE.md` is the required format for complex development tasks; `BUILD_LOG.md` records commands, evidence and limitations. `REPOSITORY_AUDIT.md` and `RESET_MANIFEST.md` are evidence/cleanup inputs, not authorization to implement or delete. Do not create another management document without a distinct owner and purpose.

## 1. Authority and status

The owner approves architecture decisions, freezes and milestone scope, and performs or explicitly authorizes Git commit/push. Codex may inspect, propose, implement an authorized task, verify and prepare a reviewable diff. A committed proposal is not an accepted ADR. The user’s explicit current task controls scope; this workflow does not itself authorize later milestones.

Use exactly these milestone/task states in `EXECUTION_PLAN.md` and `BACKLOG.md`:

| State | Meaning and evidence | Who may record |
|---|---|---|
| NOT_STARTED | No authorized work begun | plan maintainer |
| PLANNED | Bounded spec, dependencies and acceptance drafted; approval may still be pending | Codex or owner |
| IN_PROGRESS | Authorized work is active; baseline and task ID recorded | Codex |
| BLOCKED | A concrete prerequisite/decision prevents progress; name it and the responsible owner | Codex or owner |
| IMPLEMENTED | Scoped deliverables exist; implementation is **not** a pass claim | Codex, with diff/artifact references |
| VERIFIED | Acceptance and system-level checks have recorded results; skipped checks remain visible | Codex, with exact evidence |
| REVIEWED | Architecture/diff review completed, findings resolved or accepted, reviewer identified | reviewer or Codex with review record |
| APPROVED | Owner accepts the milestone/ADR and authorizes the next dependency | project owner only |

Normal progression is NOT_STARTED → PLANNED → IN_PROGRESS → IMPLEMENTED → VERIFIED → REVIEWED → APPROVED. BLOCKED is an interruption, not completion; resume to the prior appropriate state after its cause is resolved. A failed check returns work to IN_PROGRESS with a recorded issue. A review rejection returns it to the needed earlier state. For documentation-only tasks, VERIFIED may record static consistency/diff checks and explicitly say no runtime tests were applicable or run. Never infer APPROVED from a commit, passing test, elapsed time or silence.

## 2. Seven development gates

Each task records gate evidence in its spec or `BUILD_LOG.md`. A gate can be marked pending; do not silently skip it. A bounded, explicitly approved exception must name the owner, risk and later closure condition.

| Gate | Entry | Exit evidence |
|---|---|---|
| Repository Baseline | Task request and checkout available | HEAD/branch/worktree status, existing user changes, production entrypoints, exact files and callers, schema/CI references, current behavior and limits recorded; unrelated changes protected |
| Architecture Freeze | Baseline and alternatives available | Owner has resolved affected ADRs, target data flow and uncertainty policy; architecture document version and approved scope identified |
| Data Contract Freeze | Architecture decision recorded | Identity, address spaces, schemas/versioning, typed APIs, provenance/confidence, partial/error behavior and compatibility/invalidation defined with consumer examples; owner approves core-contract boundary |
| Module Boundary Freeze | Contracts and dependency graph available | Ownership, import direction, adapter/runtime boundary, persistence/result/debug separation and migration path agreed; no empty package skeletons |
| Vertical-Slice Development | Approved spec, dependencies and previous gates for affected boundary satisfied | One bounded real input→frontend/representation→shared analysis→persisted result/evidence path implemented or an approved smaller slice with honest partial status; unsupported cases explicit |
| System-Level Verification | Slice implemented | Contract, integration and representative end-to-end checks cover actual data flow, failure/partial behavior, schema reload/invalidation and relevant cross-frontend behavior; exact commands/results/omissions recorded |
| Architecture Compliance Review | Verification evidence and diff ready | Reviewer checks contracts, dependency direction, identities, provenance/confidence, artifact/result separation, scope and user-visible behavior; findings resolved or assigned; owner may then approve |

Local unit tests are useful but cannot substitute for the system-level gate. A one-class or one-function edit is IMPLEMENTED only when it is the complete approved scope; it does not establish a capability or milestone as complete. If a prerequisite is still Proposed, remain PLANNED/BLOCKED for dependent implementation and request a concrete owner decision.

## 3. Issue priority and architecture change control

Classify a new finding before changing code:

- **P0:** unsound result, data loss, security/privacy issue, broken identity/schema/address or frozen architecture contract. Stop affected rollout, preserve evidence, triage root cause and obtain owner decision for any architecture change.
- **P1:** accepted vertical slice or supported product flow fails, including missing persistence, invalidation, interprocedural linkage or partial/unknown propagation. Fix within authorized scope after dependency review; raise an Architecture Change Request if a frozen boundary must change.
- **P2:** localized quality, diagnostics or documentation issue with no contract change. Fix within scope and verify relevant behavior; do not expand to unrelated refactors.

An **Architecture Change Request (ACR)** is required before modifying frozen HIR/CIR or wire schemas, identity/address rules, provenance/confidence semantics, memory/alias contracts, artifact/result boundaries, or module dependency direction. Record: ID and linked ADR/task; triggering evidence and severity; current contract and affected producers/consumers/artifacts; alternatives; recommended change; compatibility/migration/invalidation plan; verification plan; rollback or containment; owner decision and date. Codex may prepare the ACR and non-mutating impact analysis. Until owner approval, do not implement the crossing. ACR approval does not silently approve the whole milestone; update `DECISIONS.md`, `ARCHITECTURE.md`, task spec and plan before coding.

Scope changes that do not cross architecture boundaries still require a revised task spec/backlog dependency and owner approval when they add a new deliverable or irreversible cleanup. Record unrelated defects separately instead of folding them into the active slice.

## 4. Vertical slice and repeated-failure rule

For a complex task, trace the actual path: input identity and acquisition → frontend export → HIR/CIR/provenance → program/memory/analysis query → result/cache/evidence → CLI/debug consumer. Name each required stage and its acceptance witness in `TASK_SPEC_TEMPLATE.md`. A slice may intentionally end earlier only when the task explicitly defines that narrower outcome and downstream limitations. Do not mark an end-to-end feature complete from a parser, class, mock-only test or single local query.

For an acceptance failure, record hypothesis, evidence, exact change and targeted check. If **two targeted modifications for the same issue** do not resolve it, stop local patching. Write a root-cause note in `BUILD_LOG.md`: minimal reproducer/input, expected versus observed, causal path across modules, competing hypotheses, contract assumption, why both fixes failed, and revised plan. Reinspect upstream data and downstream consumers; submit an ACR if the contract is wrong. Resume only with a new evidence-based plan within authorized scope. Do not reset the counter by renaming the symptom.

## 5. Task and verification protocol

Before coding, copy `TASK_SPEC_TEMPLATE.md` into the task description or fill its fields in an approved issue; do not create a new document merely for the copy. Link the task in `BACKLOG.md`, note dependencies and gate state, inspect all affected producers/consumers and record baseline. Prefer one coherent vertical slice and a small reviewable diff. Update the build log with exact commands, exits, artifacts, observed behavior and checks not run. Verify system data flow as well as local semantics. Review the diff, update design/decision/plan docs when behavior or contract changes, and report remaining risk.

Definition of Done is in `ENGINEERING_STANDARDS.md`. Codex can report IMPLEMENTED, VERIFIED and review evidence; only the owner may set APPROVED or authorize B1/B2 or any later milestone. No automatic continuation across milestone gates.

## 6. Git and parallel work

Default: **Codex does not commit or push**. The owner reviews the diff and handles submission unless a task explicitly delegates those operations. Do not reset/restore/clean away user changes. Before handoff, report changed files, verification, skipped checks and working-tree state. Keep unrelated work intact.

Parallel research is allowed when explicitly tasked and independently bounded. Do not let concurrent work edit frozen identities, schemas, address semantics or shared interfaces without one integration owner and an approved ACR. Shared checkout edits must be coordinated. A task marked BLOCKED is not permission to start a later milestone.

## 7. Current transition

A2 architecture and ADR-001–012 remain Proposed unless the owner records approval. B0 produced a reset preflight manifest and documentation changes; that is not B1 authorization. This governance task establishes process only. B1 requires the owner to review `RESET_MANIFEST.md`, resolve relevant ADRs and approve a B1 task spec with its contract/dependency gates.
