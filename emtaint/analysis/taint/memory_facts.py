"""P5 value/definition-dependent may-flow evidence, without vulnerability rules.

Full program source/sink discovery, summaries and reachability remain P6/P7.
Source bindings are explicit analysis inputs, owned by this tracker/session.
"""
from emtaint.core import Completeness
from emtaint.core.contracts import ValueType
from emtaint.memory import SymbolicOp
from emtaint.memory.query_port import QueryBudget
from emtaint.memory.policies import BudgetExceeded


class MemoryTaintTracker:
    def __init__(self, engine):
        self.engine=engine
        self.sources={}
        self.query_steps=0

    def mark_source(self, value, fact):
        if value not in self.engine.dag.nodes: raise ValueError('Source value must be registered')
        self.engine.add_taint(fact)
        self.sources[value]=fact

    def sink(self, value, state, origin, guard=None, budget=QueryBudget()):
        e=self.engine
        e._origin(origin)
        if state not in e.versions: raise ValueError('Sink needs a registered memory version')
        if guard is not None and e.dag.nodes[guard].type != ValueType.boolean():
            raise ValueError('Sink guard must be boolean')
        if guard is not None and e.dag.constant_value(guard) is False: return ()
        root, resolver=e.resolve(value, budget)
        candidates=[]
        todo=[(root, () if guard is None else (guard,))]
        seen=set()
        steps=0
        while todo:
            ref, conditions=todo.pop()
            if (ref, conditions) in seen: continue
            seen.add((ref, conditions))
            steps+=1
            self.query_steps+=1
            if steps>budget.max_steps:
                raise BudgetExceeded('worklist_iterations', budget.max_steps, steps)
            if any(e.dag.constant_value(g) is False for g in conditions): continue
            if ref in self.sources:
                fact=self.sources[ref]
                guards=conditions+(() if fact.guard is None else (fact.guard,))
                if any(e.dag.constant_value(g) is False for g in guards): continue
                candidates.append({'source':fact.id, 'source_origin':fact.origin, 'sink_origin':origin,
                    'memory_version':state, 'source_memory_version':fact.memory_version,
                    'path':fact.path, 'graph':fact.graph, 'guards':tuple(dict.fromkeys(guards)),
                    'provenance':fact.provenance+('Value/byte-definition dependency reaches sink argument',),
                    'status':'may', 'confirmed':False})
            node=e.dag.nodes[ref]
            if node.op==SymbolicOp.IF:
                g, yes, no=node.operands
                ng=e.dag.operation(SymbolicOp.NOT, ValueType.boolean(), (g,), origin)
                todo.extend(((yes, conditions+(g,)), (no, conditions+(ng,))))
            else: todo.extend((child, conditions) for child in node.operands)
        if any(a.status!=Completeness.COMPLETE for a in resolver.assessments):
            # Havoc/unknown reads cannot erase a previous may-flow or establish
            # a clean sink. Preserve explicit unknown evidence even with no
            # recognized input-expression dependency.
            candidates.append({'source':None, 'source_origin':None, 'sink_origin':origin,
                'memory_version':state, 'source_memory_version':None, 'path':None, 'graph':None,
                'guards':() if guard is None else (guard,),
                'provenance':('Incomplete memory resolution; source dependency may be unknown',),
                'status':'unknown', 'confirmed':False})
        return tuple(candidates)
