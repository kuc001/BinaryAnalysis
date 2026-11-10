# Complex development task specification template

Copy these fields into an approved issue/task description; do not create a separate file for every task unless the owner requests it. Fill with exact paths, symbols and observable evidence. `TBD` in a required contract or dependency keeps the task PLANNED/BLOCKED, not ready to code.

## Identity and authority

- Task ID / title:
- Parent milestone and `BACKLOG.md` link:
- Status: NOT_STARTED / PLANNED / IN_PROGRESS / BLOCKED / IMPLEMENTED / VERIFIED / REVIEWED / APPROVED
- Owner / reviewer / date of scope approval:
- Repository baseline: branch, HEAD, worktree, existing user changes to preserve:
- Priority: P0 / P1 / P2, with reason:

## Goal and boundaries

- **Goal:** one observable user or analysis outcome.
- **Scope:** exact code, data and documentation allowed to change; one bounded vertical slice.
- **Non-Goals:** explicitly excluded behavior, frontends, migrations and cleanup.
- **Current evidence:** producer, consumer, caller and schema paths; current behavior and failure.
- **Dependencies:** prerequisite task IDs, ADR/ACR approvals, environments/fixtures and owner decisions. State each as satisfied or pending.

## Contracts and architecture gates

- Approved architecture/ADR version and affected boundary:
- Input and output records/IDs, typed API, address domains and schema version:
- Error, unsupported, unknown, partial and budget semantics:
- Provenance/confidence and identity mapping:
- Persistence, cache key, dependency invalidation and compatibility:
- Module ownership/import direction; frontend SDK boundary:
- Architecture Change Request ID if a frozen contract must change:
- Gate evidence: Repository Baseline; Architecture Freeze; Data Contract Freeze; Module Boundary Freeze. Name owner approval or a scoped exception for each applicable gate.

## Vertical data path

Trace the real path and name a witness for every required stage:

```text
input/project -> acquisition/frontend -> HIR/CIR + provenance
-> program/memory/dataflow/alias/other shared analysis
-> result/cache/evidence -> CLI/debug consumer
```

- Stage-specific implementation and output artifacts:
- Explicit endpoint if this task is intentionally narrower than an end-to-end capability:
- Downstream behaviors still unavailable after this task:

## Acceptance

Use numbered, falsifiable criteria, including a representative normal case and at least one partial/unsupported/failure case. Include cross-function, persistence/reload, invalidation and cross-frontend cases when the slice crosses those boundaries. A class/function/file existing or a local test passing is not an acceptance criterion by itself.

1.
2.
3.

## Verification and handoff

- Local/contract checks: commands, fixtures, expected observations:
- System-level path: commands, inputs, expected result/evidence and failure observations:
- Architecture compliance review: reviewer, dependency/identity/schema/provenance/cache/scope checklist:
- Checks impossible in this environment and the resulting risk:
- Diff scope, docs to update (`ARCHITECTURE.md`, `ACQUISITION_DESIGN.md`, `DECISIONS.md`, `EXECUTION_PLAN.md` as applicable):
- `BUILD_LOG.md` entry and `BACKLOG.md` status/dependency update:
- Handoff: IMPLEMENTED/VERIFIED/REVIEWED evidence and owner approval requested. Codex does not set APPROVED or commit/push by default.

If the same acceptance issue survives two targeted changes, stop patching, record root cause and a revised plan in `BUILD_LOG.md`, and request an ACR when the frozen contract is implicated.
