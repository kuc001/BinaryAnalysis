from pyvex.stmt import IMark, IRStmt
from ..visitors import IRVisitor

class IMark(IMark):
    """
    An instruction mark. It marks the start of the statements that represent a single machine instruction (the end of
    those statements is marked by the next IMark or the end of the IRSB).  Contains the address and length of the
    instruction.
    """

    def __init__(self, addr: int, length: int, delta: int):
        super().__init__(addr, length, delta)

        self.statements: list[IRStmt] = []

    def accept(self, visitor: IRVisitor):
        return visitor.visit_imark(self)
