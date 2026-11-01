"""Pure, immutable P6 states. Memory and values stay scoped stable references."""
from dataclasses import dataclass
from emtaint.core import ProgramPoint,ContextId
from emtaint.core.contracts import Assessment,MemoryVersionId,same_scope


@dataclass(frozen=True)
class FlowState:
    memory: MemoryVersionId
    context: ContextId
    point: ProgramPoint | None = None
    values: tuple = ()
    registers: tuple = ()
    addresses: tuple = ()
    guards: tuple = ()
    apgs: tuple = ()
    assessment: Assessment = Assessment()
    register_epoch: int = 0

    def __post_init__(self):
        if self.context!=self.memory.scope.context:raise ValueError('State context differs from memory scope')
        same_scope(self.memory.scope,*(ref for _,ref in self.values+self.registers),*self.guards,*self.apgs)
        if self.point is not None and self.point.function!=self.memory.scope.function:raise ValueError('Foreign program point')


@dataclass(frozen=True)
class TargetFact:
    site: object
    targets: tuple[int,...]
    kind: str
    certainty: str
    exhaustive: bool
    memory: MemoryVersionId
    guards: tuple
    origin: str
    assessment: Assessment
    evidence: str
