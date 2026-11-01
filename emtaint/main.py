
from emtaint.program_builder import EmProgram
from emtaint.analysis.pag.ir_graph_builder import IRGraphBuilder

def main():
    """
    """
    binary = ""

    # em_program = EmProgram.get_em_program()

    em_program = EmProgram.build(binary)

    IRGraphBuilder().build(em_program)
    return em_program


if __name__ == "__main__":
    world = main()
    # print(world.functions)
