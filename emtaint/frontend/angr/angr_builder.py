
import logging
from angr import Project
from .converter import Converter
from .ir_builder import IRBuilder
from emtaint.analysis.graph.cfg.default_cfg_builder import CFGBuilder
# from emtaint.emtaint.program_builder import EmProgram


l = logging.getLogger(name=__name__)


class AngrBuilder:
    """

    """
    def __init__(self, binary,
                 em_program,
                 cfg_generate_mode: str = None,
                 default_analysis_mode=None,
                 auto_load_libs: bool = False):
        """

        """
        self._binary = binary
        self._em_program = em_program
        self._cfg_generate_mode = cfg_generate_mode
        self._default_analysis_mode = default_analysis_mode
        self._auto_load_libs = auto_load_libs

        self._project = None
        self._arch = None

    def build(self):
        """

        """
        self._em_program.set_ir_builder(IRBuilder())
        # em_program = EmProgram()
        self.run_angr()

        # Construct control flow grph (CFG) for each function
        # The node in CFG is BlockNode
        block_cfg_builder = CFGBuilder()
        block_cfg_builder.analyze(self._em_program)

    def run_angr(self) -> None:
        """

        """
        project = Project(self._binary,
                          default_analysis_mode=self._default_analysis_mode,
                          auto_load_libs=self._auto_load_libs)

        self._project = project
        self._arch = project.arch

        if self._cfg_generate_mode is None or self._cfg_generate_mode == "fast":
            cfg = project.analyses.CFGFast()

        elif self._cfg_generate_mode == "emulated":
            cfg = project.analyses.CFGEmulated()

        else:
            print(f"Error, not support {self._cfg_generate_mode} for building CFG")
            exit(-1)

        converter = Converter(project, cfg)
        ir_builder = self._em_program.get_ir_builder()
        for func in cfg.kb.functions.values():
            if not func.binary.is_default:
                l.debug(f"skip external function: {func.name}")
                continue
            # if func.addr != 0x700000:
            #     continue
            # print(func, func.binary.is_default)
            em_func = converter.convert_function(func)
            self._em_program.add_function(em_func)
            em_func.set_frontend_graph(func.graph)
            
            for block in func.blocks:
                # print(block)
                em_block = converter.convert_block(block, ir_builder)
                # ir_builder.build(block)
                em_func.add_block(em_block)
                # break

            # break
            # func_graph = func.func.graph
