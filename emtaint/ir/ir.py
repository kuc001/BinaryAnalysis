from abc import ABC, abstractmethod
from typing import List, Optional, Iterator, Iterable
from collections.abc import Iterable as IterableBase

from pyvex.stmt import IRStmt
from emtaint.assembly.block import Block


class IR(IterableBase[IRStmt], ABC):
    @abstractmethod
    def get_block(self) -> Block:
        pass

    # @abstractmethod
    # def get_this(self) -> Optional['Var']:
    #     pass
    #
    # @abstractmethod
    # def get_params(self) -> List['Var']:
    #     pass
    #
    # @abstractmethod
    # def get_param(self, i: int) -> 'Var':
    #     pass
    #
    # @abstractmethod
    # def get_return_vars(self) -> List['Var']:
    #     pass
    #
    # @abstractmethod
    # def get_var(self, i: int) -> 'Var':
    #     pass
    #
    # @abstractmethod
    # def get_vars(self) -> List['Var']:
    #     pass
    #
    # @abstractmethod
    # def get_stmt(self, i: int) -> 'Stmt':
    #     pass
    #
    @abstractmethod
    def get_statements(self) -> List[IRStmt]:
        pass

    def statements(self) -> Iterator[IRStmt]:
        return iter(self.get_statements())

    # # def invokes(self, include_indy: bool) -> Iterator['Invoke']:
    # #     for stmt in self.get_stmts():
    # #         if isinstance(stmt, Invoke):
    # #             if include_indy or not stmt.is_dynamic():
    # #                 yield stmt

    def __iter__(self) -> Iterator[IRStmt]:
        return iter(self.get_statements())
    #
    # # @abstractmethod
    # # def get_exception_entries(self) -> List['ExceptionEntry']:
    # #     pass