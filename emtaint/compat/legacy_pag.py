"""Preserved experimental PAG native expression helper; not a P2 core engine."""


def execute_edge(edge):
    from angr.engines.vex.claripy.irop import operations, vexop_to_simop
    import claripy
    use_node = edge.get_src()
    print(use_node)
    size = use_node.var.size
    op_args = []
    print(operations)
    for arg in use_node.var.args:
        print(arg)
        if isinstance(arg.get_literal(), str):
            op_args.append(claripy.BVS(arg.get_literal(), size))
        elif isinstance(arg.get_literal(), int):
            op_args.append(claripy.BVV(arg.get_literal(), size))
        else:
            return None
    irop = vexop_to_simop(use_node.var.op)
    print(irop)
    return irop.calculate(*op_args)
