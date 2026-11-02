"""Group legacy VEX statements by their originating machine instruction."""

from pyvex.stmt import IMark, IRStmt

from ..visitors import IRVisitor


class IMark(IMark):
    """Mark one instruction address/extent and its associated VEX statements."""

    def __init__(self, addr: int, length: int, delta: int) -> None:
        super().__init__(addr, length, delta)

        self.stmts: list[IRStmt] = []

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this instruction marker to ``visitor.visit_imark``."""

        return visitor.visit_imark(self)

    def get_statements(self) -> list[IRStmt]:
        """Return statements attributed to this exact instruction marker."""

        return self.stmts
