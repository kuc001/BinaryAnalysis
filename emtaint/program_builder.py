
from frontend.angr.angr_builder import AngrBuilder
# from frontend.angr.ir_builder import IRBuilder

class EmProgram:
    """

    """
    _em_program = None

    def __init__(self):

        self._functions = []
        self._ir_builder = None

    @classmethod
    def get_em_program(cls):
        """

        """
        if cls._em_program is None:
            cls._em_program = EmProgram()
        return cls._em_program

    @staticmethod
    def build(binary):
        em_program = EmProgram.get_em_program()
        # em_program.set_ir_builder(IRBuilder())
        builder = AngrBuilder(binary, em_program, cfg_generate_mode="fast", auto_load_libs=False)
        builder.build()

        return em_program

    def add_function(self, function):
        self._functions.append(function)

    def get_function(self, addr):
        pass

    @property
    def functions(self):
        return self._functions

    @functions.setter
    def functions(self, new_functions):
        if not isinstance(new_functions, list):
            raise TypeError("Functions must be a list")
        self._functions = new_functions

    def set_ir_builder(self, ir_builder):
        """

        """
        self._ir_builder = ir_builder

    def get_ir_builder(self):
        """

        """
        return self._ir_builder