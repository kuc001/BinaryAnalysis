"""Session-owned resource accounting. Exhaustion preserves a visible frontier."""
from collections import deque
from emtaint.core.contracts import SemanticBudgets


class BudgetExceeded(RuntimeError):
    def __init__(self, dimension, limit, observed):
        self.dimension, self.limit, self.observed = dimension, limit, observed
        self.assessment = SemanticBudgets().exhausted(dimension)
        super().__init__(f'{dimension}: {observed} exceeds {limit}; result incomplete')


class Accounting:
    def __init__(self, budgets=SemanticBudgets()):
        self.budgets = budgets
        self.counts = {name: 0 for name in vars(budgets) if name != 'solver_timeout_ms'}
        self.exhaustions = []
        self.observer = None

    def check(self, dimension, observed):
        if observed > getattr(self.budgets, dimension):
            error=BudgetExceeded(dimension, getattr(self.budgets, dimension), observed)
            self.exhaustions.append(error.assessment)
            raise error
        if self.observer is not None:self.observer(dimension,observed)

    def set(self, dimension, observed):
        self.check(dimension, observed)
        self.counts[dimension] = observed

    def charge(self, dimension, amount=1):
        self.set(dimension, self.counts[dimension] + amount)


class BudgetedWorklist:
    """Finite equality-key worklist; no claim of a full-program abstract lattice.

    Transfers must return all successors. Nonconverging transfers raise with the
    current item still queued, rather than returning an empty fixed point.
    """
    def __init__(self, budgets=SemanticBudgets()):
        self.accounting = Accounting(budgets)
        self.pending = deque()
        self.seen = set()

    def run(self, seeds, transfer):
        self.pending.extend(seeds)
        while self.pending:
            item = self.pending[0]
            if item in self.seen:
                self.pending.popleft()
                continue
            self.accounting.charge('worklist_iterations')
            self.accounting.check('worklist_states', len(self.seen) + 1)
            successors = tuple(transfer(item))
            self.seen.add(item)
            self.accounting.set('worklist_states', len(self.seen))
            self.pending.popleft()
            self.pending.extend(successors)
        return frozenset(self.seen)
