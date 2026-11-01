"""Legacy EmProgram facade; native builders remain opt-in and instance-owned."""
from emtaint.core import (AnalysisSession, Program, Function, BasicBlock, FunctionId,
                          BlockId, Completeness)


class EmProgram:
    def __init__(self):
        self._functions = []
        self._ir_builder = None
        self._builder = None

    @classmethod
    def get_em_program(cls):
        """Compatibility factory. Callers retain the instance; no global current program."""
        return cls()

    @classmethod
    def build(cls, binary, *, builder_factory=None):
        if builder_factory is None:
            from emtaint.frontend.angr.angr_builder import AngrBuilder
            builder_factory = AngrBuilder
        program = cls()
        builder = builder_factory(binary, program, cfg_generate_mode='fast', auto_load_libs=False)
        builder.build()
        program._builder = builder
        return program

    def add_function(self, function):
        if type(function.addr) is not int or function.addr < 0:
            raise ValueError('Function requires a non-negative address')
        if self.get_function(function.addr) is not None:
            raise ValueError('Duplicate legacy function address')
        self._functions.append(function)

    def get_function(self, addr):
        return next((function for function in self._functions if function.addr == addr), None)

    @property
    def functions(self):
        return list(self._functions)

    @functions.setter
    def functions(self, new_functions):
        if type(new_functions) is not list:
            raise TypeError('Functions must be a list')
        addresses = [function.addr for function in new_functions]
        if any(type(a) is not int or a < 0 for a in addresses) or len(set(addresses)) != len(addresses):
            raise ValueError('Invalid or duplicate legacy function addresses')
        self._functions = list(new_functions)

    def set_ir_builder(self, ir_builder):
        self._ir_builder = ir_builder

    def get_ir_builder(self):
        return self._ir_builder

    def to_session(self, binary, architecture, abi, *, image_base=0, budgets=None):
        """Copy metadata, not frontend objects/IR. Missing graph coverage is explicit.

        Caller provides the verified image digest, mapping, architecture and ABI.
        P4 will import actual callsites, effects and graph provenance.
        """
        records = []
        for source in self._functions:
            identity = FunctionId(binary, source.addr - image_base)
            blocks = tuple(BasicBlock(BlockId(identity, block.addr - image_base,
                mode='thumb' if getattr(block, 'thumb', False) else 'default'), block.size)
                for block in source.blocks())
            entries = [block.id for block in blocks if block.id.rva == identity.rva]
            entry = entries[0] if len(entries) == 1 else None
            records.append(Function(identity, source.name if source.name is not None else '', blocks, entry,
                returning=source._returning,
                is_syscall=source.syscall, is_simprocedure=source.is_simprocedure))
        program = Program(binary, architecture, abi, tuple(records), image_base=image_base,
            status=Completeness.INCOMPLETE,
            diagnostics=('Legacy facade metadata snapshot only; function coverage is unverified',
                         'Callsite, CFG/CG edge and IR coverage not imported'))
        return AnalysisSession(program, budgets)
