"""Adapt VEX memory-bus events to the legacy visitor interface."""

from pyvex.stmt import MBE

from ..visitors import IRVisitor


class MBE(MBE):
    """Represent a VEX memory fence or related memory-bus event."""

    def __init__(self, event: str) -> None:
        super().__init__(event)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this event to ``visitor.visit_mbe``."""

        return visitor.visit_mbe(self)
