"""Session-local ascending may summaries for one immutable CIR/input identity.

Partial reanalysis is not evidence that an earlier may flow disappeared. A
different CIR or analysis input identity explicitly starts a new accumulator.
No scoped memory/APG/SSE IDs are retained in these detached summaries.
"""
from dataclasses import replace
from emtaint.core import ContextId
from .demand import TaintProcedureSummary,dependency_order,sink_order
from .global_outputs import output_order


def dependencies(*groups):
    return tuple(sorted(set(dep for group in groups for dep in group),key=dependency_order))


def semantic_equal(left,right):
    if left is None or right is None:return left is right
    return bool(left.pending)==bool(right.pending) and replace(left,pending=())==replace(right,pending=())


def joined(previous,current):
    if previous.function!=current.function:raise ValueError('Cannot join different functions')
    outputs={}
    for slot,values in previous.outputs+current.outputs:outputs[slot]=dependencies(outputs.get(slot,()),values)
    tables={}
    for root,values in previous.tables+current.tables:tables[root]=dependencies(tables.get(root,()),values)
    sinks={}
    for sink in previous.sinks+current.sinks:
        key=sink_order(sink)
        old=sinks.get(key)
        sinks[key]=sink if old is None else replace(old,dependencies=dependencies(old.dependencies,sink.dependencies),
            length_dependencies=dependencies(old.length_dependencies,sink.length_dependencies))
    scalar=None if previous.scalar_returns is None and current.scalar_returns is None else dependencies(previous.scalar_returns or (),current.scalar_returns or ())
    globals_={}
    for output in (previous.global_outputs or ())+(current.global_outputs or ()):
        key=output_order(output);old=globals_.get(key)
        globals_[key]=output if old is None else replace(old,dependencies=dependencies(old.dependencies,output.dependencies))
    outputs_global=None if previous.global_outputs is None and current.global_outputs is None else tuple(globals_[key] for key in sorted(globals_))
    return TaintProcedureSummary(current.function,dependencies(previous.returns,current.returns),tuple(sorted(outputs.items())),
        tuple(sinks[key] for key in sorted(sinks)),current.pending,tuple(sorted(tables.items(),key=lambda item:repr(item[0]))),scalar,outputs_global)


class SummaryAccumulator:
    def __init__(self) -> None:
        self.entries: dict[tuple[int, ContextId | None], tuple[object, TaintProcedureSummary]] = {}

    def update(self, identity: object, summary: TaintProcedureSummary,
               *, context: ContextId | None = None) -> TaintProcedureSummary:
        """Join only replays with the same function, context, and inputs."""
        key=summary.function,context
        old=self.entries.get(key)
        result=joined(old[1],summary) if old is not None and old[0]==identity else summary
        self.entries[key]=(identity,result)
        return result
