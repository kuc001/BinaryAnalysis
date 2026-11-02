
"""Adapt a pyvex pattern binder to the legacy IR visitor interface."""

from pyvex.expr import Binder

from ..visitors import IRVisitor


class Binder(Binder):
    """Represent a VEX-only pattern binder in legacy visitor traversals."""

    def __init__(self, binder: int):
        super().__init__(binder)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_binder``."""

        return visitor.visit_binder(self)
