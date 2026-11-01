"""Characterization of legacy entry points retained by P2; no native imports."""
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from emtaint.assembly.function import Function
from emtaint.program_builder import EmProgram
from emtaint.analysis.pag.ir_graph import IRGraph
from emtaint.analysis.pag.ir_graph_builder import IRGraphBuilder
from emtaint.analysis.pag.var_node import VarNode
from emtaint.core import BinaryId, Architecture, ABI, Endian, Completeness


class FacadeTests(unittest.TestCase):
    def test_function_fields_are_scalar_and_preserve_flags(self):
        function = Function(0, 'zero', syscall=True, is_simprocedure=True)
        self.assertEqual(function.name, 'zero')
        self.assertIs(function.syscall, True)
        self.assertIs(function.is_simprocedure, True)

    def test_function_can_store_a_block_at_zero(self):
        function = Function(0)
        block = SimpleNamespace(addr=0, size=4)
        function.add_block(block)
        self.assertIs(function.get_block(0), block)
        self.assertEqual(list(function.blocks()), [block])

    def test_unimplemented_serialization_still_fails_explicitly(self):
        for operation in (lambda: Function(0).serialize(), lambda: Function.parse(b''),
                          lambda: Function._get_cmsg(), lambda: Function.parse_from_cmessage(None)):
            with self.subTest(operation=operation), self.assertRaises(NotImplementedError):
                operation()

    def test_getter_and_two_builds_do_not_reuse_a_singleton(self):
        class Builder:
            def __init__(self, binary, program, **kwargs):
                self.program, self.binary = program, binary
            def build(self):
                self.program.add_function(Function(0, self.binary))
        a = EmProgram.build('first', builder_factory=Builder)
        b = EmProgram.build('second', builder_factory=Builder)
        self.assertIsNot(a, b)
        self.assertEqual([f.name for f in a.functions], ['first'])
        self.assertEqual([f.name for f in b.functions], ['second'])
        self.assertIsNot(EmProgram.get_em_program(), EmProgram.get_em_program())
        self.assertIs(a.get_function(0), a.functions[0])
        self.assertIsNone(a.get_function(16))

    def test_function_setter_and_getter_do_not_share_mutable_lists(self):
        program = EmProgram()
        functions = [Function(0)]
        program.functions = functions
        functions.clear()
        program.functions.clear()
        self.assertEqual(len(program.functions), 1)
        with self.assertRaises(ValueError):
            program.add_function(Function(0))

    def test_snapshot_preserves_metadata_and_marks_missing_coverage(self):
        facade = EmProgram()
        function = Function(0x1000, 'entry', returning=True)
        function.add_block(SimpleNamespace(addr=0x1000, size=4, thumb=False))
        facade.add_function(function)
        session = facade.to_session(BinaryId.from_bytes(b'image'),
            Architecture('fixture32', 32, 32, Endian.BIG), ABI('unknown'), image_base=0x1000)
        record = session.program.function_at(0x1000)
        self.assertEqual((record.name, record.returning, record.blocks[0].size), ('entry', True, 4))
        self.assertEqual(record.id.rva, 0)
        self.assertIsNone(record.is_syscall)
        self.assertIsNone(record.is_simprocedure)
        self.assertEqual(session.status, Completeness.INCOMPLETE)
        self.assertTrue(any('Callsite' in text for text in session.program.diagnostics))
        function.name = 'mutated facade'
        self.assertEqual(record.name, 'entry')
        self.assertFalse(session.cfg(record.id).edges)


class EntrySelectionTests(unittest.TestCase):
    def test_node_allocation_is_graph_owned_and_cannot_cross_graphs(self):
        a, b = IRGraph(), IRGraph()
        a0, a1 = a.new_node('a0', 0), a.new_node('a1', 1)
        b0 = b.new_node('b0', 0)
        self.assertEqual((a0.id, a1.id, b0.id), (0, 1, 0))
        a.add_node(a0.id, a0)
        a.add_node(a1.id, a1)
        b.add_node(b0.id, b0)
        with self.assertRaises(ValueError):
            a.add_node(b0.id, b0)
        with self.assertRaises(ValueError):
            a.add_node(a0.id, VarNode('conflict', 0, node_id=a0.id))
        self.assertEqual(a.node_num, 2)
        self.assertNotEqual(VarNode('standalone', 0).id, VarNode('standalone', 0).id)

    def test_builder_visits_all_functions_and_explicit_filter(self):
        class FakeCFG:
            def get_nodes(self):
                return ()
        class Graph:
            def analyze_graph(self, entries=None):
                self.entries = entries
        class Visitor:
            def __init__(self, graph):
                pass
        program = EmProgram()
        for address in (0, 16):
            program.add_function(Function(address, str(address), cfg=FakeCFG()))
        # Recording get_nodes tests the actual build loop, not a copied filter.
        seen = []
        for function in program.functions:
            function.cfg.get_nodes = lambda f=function: seen.append(f.addr) or ()
        builder = IRGraphBuilder(graph=Graph(), visitor_factory=Visitor)
        builder.build(program)
        self.assertEqual(seen, [0, 16])
        seen.clear()
        builder.build(program, function_addrs=(16,))
        self.assertEqual(seen, [16])
        with self.assertRaises(ValueError):
            builder.build(program, function_addrs=(99,))

    def test_graph_traverses_declared_entries_including_disconnected_cycle(self):
        class Node:
            def __init__(self):
                self.out_edges = []
        graph = IRGraph()
        a, b, c = Node(), Node(), Node()
        a.out_edges = [SimpleNamespace(get_flow_node=lambda: b)]
        b.out_edges = [SimpleNamespace(get_flow_node=lambda: a)]
        graph.add_block_entry_node(0, a)
        graph.add_block_entry_node(4, c)
        self.assertEqual(graph.analyze_graph(), frozenset((a, b, c)))
        self.assertEqual(graph.analyze_graph((0,)), frozenset((a, b)))
        with self.assertRaises(KeyError):
            graph.analyze_graph((99,))
        self.assertEqual(IRGraph().analyze_graph(), frozenset())


if __name__ == '__main__':
    unittest.main()
