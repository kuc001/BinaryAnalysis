"""Finite may-path automata. Repeated contiguous words widen to word*.

The inclusion argument is syntactic: prefix.word^k.suffix is contained in
prefix.word*.suffix for all k>=0. No heap identities or aliases are inferred.
Uncompressible paths exhaust explicitly; they are never silently truncated.
"""
from emtaint.core import Completeness
from emtaint.core.contracts import AccessGraphId, Assessment, Precision
from .access_path import APGNode, APGEdge, APGSummary, AccessGraph
from .policies import Accounting


class AccessGraphArena:
    def __init__(self, scope, budgets,*,graphs=None):
        self.scope = scope
        self.accounting = Accounting(budgets)
        self.graphs = {} if graphs is None else graphs
        self._intern = {}
        for dimension,attribute in (('apg_nodes','nodes'),('apg_edges','edges'),('apg_summaries','summaries')):
            self.accounting.set(dimension,sum(len(getattr(graph,attribute)) for graph in self.graphs.values()))

    def next_id(self):
        index=len(self.graphs)
        while AccessGraphId(self.scope,'apg-'+str(index)) in self.graphs:index+=1
        return AccessGraphId(self.scope,'apg-'+str(index))

    def field_closure(self, root, patterns, trigger):
        """Language (field_1 | ... | field_n)*; caller selects field words.

        Every finite sequence over these exact words is accepted, including all
        left/right tree and next/prev walks. This proves language inclusion only.
        It says nothing about object cycles, CFG edges or call contexts.
        """
        patterns = tuple(dict.fromkeys(tuple(p) for p in patterns))
        if not patterns or any(not p for p in patterns): raise ValueError('Nonempty field words required')
        key = (root,patterns,trigger,'closure')
        if key in self._intern: return self.graphs[self._intern[key]]
        self.accounting.check('apg_nodes',self.accounting.counts['apg_nodes']+1)
        self.accounting.check('apg_summaries',self.accounting.counts['apg_summaries']+len(patterns))
        summaries = tuple(APGSummary('n0','n0',pattern,0,None,trigger,
            'Explicit recursive-field alphabet closure',
            'Each finite field-word sequence is a concatenation of zero or more supplied words',
            'All field combinations/depths retained; infeasible combinations admitted',Completeness.COMPLETE)
            for pattern in patterns)
        graph = AccessGraph(self.next_id(),
            (APGNode('n0',root),),(),summaries,('n0',),('n0',),
            Assessment(Completeness.COMPLETE,Precision.OVER_APPROX,
                ('Recursive-field alphabet closed under arbitrary finite repetition',),diagnostics=()))
        self.accounting.charge('apg_nodes');self.accounting.charge('apg_summaries',len(patterns))
        self.graphs[graph.id]=graph;self._intern[key]=graph.id
        return graph

    def intern(self, path, trigger):
        key = (path.root, path.segments, trigger)
        if key in self._intern:
            return self.graphs[self._intern[key]]
        segments = path.segments
        nodes, edges, summaries = [APGNode('n0', path.root)], [], []
        current = 'n0'
        i = 0
        while i < len(segments):
            repeat = None
            for size in range(1, min(16, (len(segments)-i)//3) + 1):
                pattern = segments[i:i+size]
                k = 1
                while segments[i+k*size:i+(k+1)*size] == pattern:
                    k += 1
                if k >= 3:
                    repeat = (pattern, k)
                    break
            if repeat:
                pattern, k = repeat
                summaries.append(APGSummary(current, current, pattern, 0, None, trigger,
                    'Contiguous repeated field word widened',
                    f'prefix.word^{k}.suffix subset prefix.word*.suffix (word length {len(pattern)})',
                    'Repetition count forgotten; additional paths may be accepted', Completeness.COMPLETE))
                i += len(pattern)*k
            else:
                target = 'n' + str(len(nodes))
                nodes.append(APGNode(target))
                edges.append(APGEdge(current, target, segments[i]))
                current = target
                i += 1
            for dim, count in (('apg_nodes',len(nodes)),('apg_edges',len(edges)),('apg_summaries',len(summaries))):
                self.accounting.check(dim, self.accounting.counts[dim] + count)
        assessment = (Assessment(Completeness.COMPLETE, Precision.OVER_APPROX,
                      ('Repeated field-word count widened to Kleene star',), diagnostics=())
                      if summaries else Assessment.complete())
        graph = AccessGraph(self.next_id(), tuple(nodes),
            tuple(edges),tuple(summaries),('n0',),(current,),assessment)
        for dim, count in (('apg_nodes',len(nodes)),('apg_edges',len(edges)),('apg_summaries',len(summaries))):
            self.accounting.charge(dim,count)
        self.graphs[graph.id] = graph
        self._intern[key] = graph.id
        return graph


def accepts(graph, segments, max_steps=100000):
    """NFA membership for ordinary and finite-word summary transitions."""
    todo = [(x, 0) for x in graph.entries]
    seen = set()
    steps = 0
    while todo:
        node, pos = todo.pop()
        if (node,pos) in seen: continue
        seen.add((node,pos)); steps += 1
        if steps > max_steps:
            raise RuntimeError('APG membership incomplete: query-step budget')
        if pos == len(segments) and node in graph.accepting: return True
        for edge in graph.edges:
            if edge.source == node and pos < len(segments) and segments[pos] == edge.label:
                todo.append((edge.target,pos+1))
        for summary in graph.summaries:
            if summary.source != node: continue
            size, k, end = len(summary.pattern), 0, pos
            while True:
                if k >= summary.minimum_repetitions: todo.append((summary.target,end))
                if summary.maximum_repetitions is not None and k >= summary.maximum_repetitions: break
                if segments[end:end+size] != summary.pattern: break
                end += size; k += 1
    return False
