# Core allowlist — R1-A research update

Status: **proposed research classification, awaiting owner review**. This file did not exist in the repository baseline. It is a planning allowlist for algorithm ideas and dependencies, not permission to copy legacy code, change frozen contracts or implement a milestone.

| Candidate core responsibility | Local evidence | Allowed research/implementation boundary | Gate |
|---|---|---|---|
| CIR definition and effect dataflow, bounded forward/backward demand | `references/legacy-emtaint/dataflow/data_trace.py:484-567,5154-5188`; `accurate_data_flow.py:2628-2847`; current `emtaint/analysis/dataflow/accurate.py`, `analysis/sse/dag.py` | Shared frontend-independent CIR/SSE/def-use consumer. Legacy `VarExpr`, `TraceExpr`, `SimAction` are research-only. | C contracts, F slice |
| Versioned memory and alias query | Legacy `accurate_data_flow.py:1901-2042,3335-3580`; current `emtaint/memory/{state,query_port,engine}.py`, `analysis/aliasing/query.py` | Memory Object/Access Path/MemoryVersion and explicit Alias Evidence; uncertain outcomes stay May/Unknown. | C memory/identity freeze, F slice |
| Indirect target candidates and CG refinement | Legacy `data_collector.py:363-446`; current `emtaint/orchestration/icall_program.py`, `analysis/controlflow/targets.py` | Candidate/confirmed/ambiguous/unresolved target results with graph revisions; no legacy hard-coded source addresses. | C program/result contract, F slice |
| Context summaries and taint/sink evidence | Legacy `data_trace.py:4174-4684`; `sim_procedure.py:545-702`; current `analysis/framework/summaries.py`, `analysis/taint/demand.py`, `analysis/bugfinder/*` | Shared CIR analysis, versioned summaries, explicit source/sink/demand context and candidate path evidence. | F then G |

Not core imports: `references/legacy-emtaint/*`, IDA SDK objects, old `dataflow` runtime classes, `.bak` procedure files, printed collector conclusions and old scripts. IDA/VEX acquisition stays in frontend adapters; procedure models are policy inputs; result/cache/debug lifecycles stay separate. The full decision and gap matrix is in `ALGORITHM_MIGRATION_MAP.md`.
