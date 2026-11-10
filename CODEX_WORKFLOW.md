# Codex Workflow for BinaryAnalysis

## 1. Document responsibilities

  ----------------------------------------------------------------------------------------------
  File                         Role                     Lifetime               Auto-loaded by
                                                                               Codex?
  ---------------------------- ------------------------ ---------------------- -----------------
  `AGENTS.md`                  Concise durable          Long-lived             Yes, when
                               repository rules                                discovered

  `CODEX_TASK.md`              Goals, scope, non-goals  Long-lived             No; reference it

  `ARCHITECTURE.md`            Approved                 Long-lived/versioned   No
                               architecture/contracts                          

  `ACQUISITION_DESIGN.md`      Artifact/cache lifecycle Long-lived/versioned   No

  `ENGINEERING_STANDARDS.md`   Quality policy           Long-lived             No

  `EXECUTION_PLAN.md`          Living milestone plan    Updated continuously   No

  `REPOSITORY_AUDIT.md`        Evidence-based actual    Updated after audit    No
                               repo audit                                      

  `DECISIONS.md`               Accepted/rejected        Long-lived             No
                               decisions                                       

  `BUILD_LOG.md`               Progress and             Per milestone          No
                               verification evidence                           

  `CODEX_INS.md`               One-time kickoff prompt  Per kickoff            No
  ----------------------------------------------------------------------------------------------

There is no single mandatory official Codex filename convention
requiring every document above. OpenAI guidance supports concise
persistent `AGENTS.md`, self-contained plans for complex multi-hour
work, and optional goal/prompt/context/build-log artifacts when useful.
Right-size the set; do not generate documents without an owner or
purpose.

## 2. Recommended workflow

### A. Ask/Plan first

Ask Codex to inspect the repository and produce an evidence-based audit,
dependency graph, alternatives, risks and unresolved decisions. No code
changes.

### B. Human architecture review

Decide CIR/HIR boundary, CTree exporter boundary, artifact granularity,
fingerprint rules, tests reset policy and Microcode timing. Record
decisions.

### C. Approve one milestone

Give Codex a bounded issue-style task: goal, current evidence, scope,
non-goals, contracts, acceptance, verification and docs.

### D. Implement one vertical slice

Prefer one end-to-end capability (e.g. extract one CTree function,
serialize, load outside IDA, normalize to HIR, lower a supported subset
to CIR, preserve provenance, run one shared query) over empty
scaffolding.

### E. Review and verify

Review semantics, unsupported cases, schema compatibility, dependency
direction, provenance, cache invalidation and diff scope. Report exact
commands/results and skipped checks honestly.

### F. Commit and update

Update `EXECUTION_PLAN.md`, `BUILD_LOG.md`, and `DECISIONS.md` before
the next milestone.

## 3. Parallel sessions

Parallelize independent research (IDA API version research, architecture
review) or isolated adapters after contracts are frozen. Do not allow
concurrent sessions to edit CIR identity, Artifact schema, address
semantics or shared interfaces. Use one integration owner.

## 4. Reusable task prompt

``` text
Read AGENTS.md, CODEX_TASK.md, ARCHITECTURE.md,
ACQUISITION_DESIGN.md, ENGINEERING_STANDARDS.md and the approved
milestone in EXECUTION_PLAN.md.

Task:
[one bounded outcome]

Current evidence:
[exact paths, symbols, behavior]

Scope:
[allowed changes]

Non-goals:
[forbidden changes]

Required contracts:
[interfaces and invariants]

Acceptance:
[observable behavior and edge cases]

Verification:
[exact commands and evidence]

Documentation:
[files to update]

Before editing, summarize impacted modules and plan.
Implement only this milestone. Do not proceed beyond it without approval.
```

## 5. Quality loop

Inspect -\> Plan -\> Implement -\> Verify -\> Review diff -\> Update
docs -\> Commit -\> Record remaining risks.
