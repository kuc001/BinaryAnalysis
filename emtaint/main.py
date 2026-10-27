
from emtaint.program_builder import EmProgram
from emtaint.analysis.pag.ir_graph_builder import IRGraphBuilder

def main():
    """
    """
    binary = ""

    # em_program = EmProgram.get_em_program()

    em_program = EmProgram.build(binary)

    IRGraphBuilder().build(em_program)


if __name__ == "__main__":
    main()

    world = EmProgram.get_em_program()
    # print(world.functions)
    