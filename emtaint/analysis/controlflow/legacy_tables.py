"""Port of Collector.calculate_icall_targets/read_recursive_data.

All byte queries use MemoryQueryPort and the explicitly chosen initial loader
snapshot. These are legacy heuristic candidates, never concrete witnesses.
"""

from dataclasses import dataclass

from emtaint.core.contracts import Record, TypeKind, ValueType
from emtaint.memory import SymbolicOp


@dataclass(frozen=True)
class LegacyTableEvidence(Record):
    """One immutable legacy table-enumeration evidence record.

    Attributes:
        rule: Legacy collector rule that produced the candidates.
        read_type: Whether the table read is interpreted as data or code.
        expression: Stable SSE expression identity evaluated by the collector.
        loader_version: Initial loader-backed MemoryVersion identity.
        indices_examined: Number of table indices evaluated.
        targets: Candidate addresses found by this enumeration.
        unknown_remainder: Whether unenumerated values may remain.
        maximum_address: Optional firmware-specific enumeration bound.
        nested_substitutions: Number of explicitly substituted nested reads.
        provenance: Human-readable explanation of the evidence boundary.
    """

    rule: str
    read_type: str
    expression: str
    loader_version: str
    indices_examined: int
    targets: tuple[int, ...]
    unknown_remainder: bool
    maximum_address: int | None
    nested_substitutions: int
    provenance: str

    def __post_init__(self) -> None:
        """Reject malformed or non-deterministically ordered evidence."""

        super().__post_init__()
        if self.read_type not in ("data", "func"):
            raise ValueError("Legacy table read type must be data or func")
        if self.indices_examined < 1 or self.nested_substitutions < 0:
            raise ValueError("Legacy table evidence counters are invalid")
        if self.maximum_address is not None and self.maximum_address < 0:
            raise ValueError("Legacy table maximum address cannot be negative")
        if self.targets != tuple(sorted(set(self.targets))):
            raise ValueError("Legacy table targets must be sorted and unique")

    def to_legacy_dict(self) -> dict[str, object]:
        """Return the pre-DTO JSON shape used by frozen P6 artifacts."""

        return {
            "rule": self.rule,
            "read_type": self.read_type,
            "expression": self.expression,
            "loader_version": self.loader_version,
            "indices_examined": self.indices_examined,
            "targets": list(self.targets),
            "unknown_remainder": self.unknown_remainder,
            "maximum_address": self.maximum_address,
            "nested_substitutions": self.nested_substitutions,
            "provenance": self.provenance,
        }


class LegacyTableCollector:
    def __init__(self, demand, is_code, is_data, *, max_index=0x1000):
        self.demand=demand
        self.port=demand.port
        self.is_code, self.is_data=is_code, is_data
        self.max_index=max_index
        self.evidence: list[LegacyTableEvidence] = []
        self.unknown=False
        self.queries=0
        self.partial_targets=set()

    def evaluate(self, root, index, overrides=None):
        d=self.port.engine.dag
        cache=dict(overrides or {})
        pending=[(root, False)]
        while pending:
            ref, ready=pending.pop()
            if ref in cache:continue
            n=d.nodes[ref]
            if ref in self.demand.loads:
                address, width, endian, origin=self.demand.loads[ref]
                if not ready:
                    pending.append((ref, True))
                    pending.append((address, False))
                    continue
                absolute=cache[address]
                binding=self.port.engine.address(absolute) if type(absolute) is int else None
                if binding:
                    loc=self.port.engine.location(*binding, width, endian, origin)
                    value=self.port.read(self.demand.initial.memory, loc,
                        self.port.constant(True, ValueType.boolean(), origin), origin).value
                    self.queries+=1
                    cache[ref]=self.port.concrete(value)
                else:cache[ref]=None
                continue
            if not ready and n.operands:
                pending.append((ref, True))
                pending.extend((x, False) for x in n.operands)
                continue
            a=[cache[x] for x in n.operands]
            if n.op==SymbolicOp.CONSTANT:result=n.value
            elif n.op==SymbolicOp.MEMORY_READ:result=self.port.concrete(ref)
            elif n.op==SymbolicOp.SYMBOL and n.value=='i':result=index
            elif n.op==SymbolicOp.IF:
                result=a[1] if a[0] is True else a[2] if a[0] is False else a[1] if a[1]==a[2] else None
            elif n.op==SymbolicOp.COPY:result=a[0]
            elif a and all(x is not None for x in a):result=d._calculate(n, a)
            else:result=None
            if result is not None and n.type.kind!=TypeKind.BOOL:result%=1<<n.type.bits
            cache[ref]=result
        return cache[root]

    def indexed(self, root, overrides=None):
        d=self.port.engine.dag
        seen=set()
        pending=[root]
        while pending:
            ref=pending.pop()
            if overrides and ref in overrides:continue
            if ref in seen:continue
            seen.add(ref)
            n=d.nodes[ref]
            if n.op==SymbolicOp.SYMBOL and n.value=='i':return True
            pending.extend(n.operands)
            if ref in self.demand.loads:pending.append(self.demand.loads[ref][0])
        return False

    def terminal_read(self, root):
        d=self.port.engine.dag
        seen=set()
        while root not in seen:
            seen.add(root)
            if root in self.demand.loads:return root
            node=d.nodes[root]
            if node.op==SymbolicOp.COPY:
                root=node.operands[0]
                continue
            if node.op==SymbolicOp.ADD and self.port.concrete(node.operands[0])==0:
                root=node.operands[1]
                continue
            if node.op in (SymbolicOp.ADD, SymbolicOp.SUB) and self.port.concrete(node.operands[1])==0:
                root=node.operands[0]
                continue
            break
        return None

    def nested_indexed_read(self, root, overrides):
        d=self.port.engine.dag
        top=self.terminal_read(root)
        seen=set()
        pending=[(root, False)]
        while pending:
            ref, ready=pending.pop()
            if ref in overrides or ref in seen:continue
            node=d.nodes[ref]
            children=list(node.operands)
            if ref in self.demand.loads:children.append(self.demand.loads[ref][0])
            if not ready:
                pending.append((ref, True))
                pending.extend((x, False) for x in children)
                continue
            seen.add(ref)
            if ref!=top and ref in self.demand.loads and self.indexed(self.demand.loads[ref][0], overrides):return ref
        return None

    def collect(self, root, *, maximum_address=None, end_flag=None, overrides=None):
        overrides=dict(overrides or {})
        inner=self.nested_indexed_read(root, overrides)
        if inner is not None:
            # Collector.replace_one_load_value enumerates the inner data
            # pointers first, then restarts the outer function-table index.
            # Evaluating every nested Load with the same integer misses the
            # independent outer/inner combinations of the old worklist.
            candidates=self.scan(inner, 'data', 0, None, overrides)
            values=set()
            if len(overrides)>=32:raise RuntimeError('Explicit nested table substitution budget exhausted')
            for value in candidates:
                values.update(self.collect(root, maximum_address=maximum_address, end_flag=end_flag,
                                           overrides={**overrides, inner:value}))
            return tuple(sorted(values))
        return self.scan(root, 'func', end_flag, maximum_address, overrides)

    def scan(self, root, read_type, end_flag, maximum_address, overrides):
        values=set()
        indexed=self.indexed(root, overrides)
        terminal=self.terminal_read(root)
        for index in range(self.max_index if indexed else 1):
            if terminal is not None:
                address=self.evaluate(self.demand.loads[terminal][0], index, overrides)
                if address is None or self.port.engine.address(address) is None:
                    self.unknown=True
                    break
                if maximum_address is not None and address>maximum_address:break
            value=self.evaluate(root, index, overrides)
            if value is None:
                self.unknown=True
                if indexed:continue
                break
            if value>0:
                if (self.is_code if read_type=='func' else self.is_data)(value):
                    values.add(value)
                    if read_type=='func':self.partial_targets.add(value)
                else:break
            elif value==end_flag:break
        else:
            if indexed:self.unknown=True
        self.evidence.append(
            LegacyTableEvidence(
                rule=(
                    "Collector.read_recursive_data"
                    if indexed
                    else "Collector.calculate_icall_targets"
                ),
                read_type=read_type,
                expression=root.key,
                loader_version=self.demand.initial.memory.key,
                indices_examined=index + 1,
                targets=tuple(sorted(values)),
                unknown_remainder=self.unknown,
                maximum_address=maximum_address,
                nested_substitutions=len(overrides),
                provenance=(
                    "Candidate from versioned initial loader bytes; "
                    "writable runtime state can differ"
                ),
            )
        )
        return tuple(sorted(values))
