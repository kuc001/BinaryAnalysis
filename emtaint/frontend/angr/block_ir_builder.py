import pyvex
import logging
from angr.block import Block as AngrBlock

from emtaint.ir.statements.imark import IMark
from emtaint.ir.statements.store import Store
from emtaint.ir.statements.rstore_tmp import RegStoreTmp
from emtaint.ir.statements.rstore_cons import RegStoreCons
from emtaint.ir.statements.gstore_tmp import GlobalStoreTmp
from emtaint.ir.statements.gstore_cons import GlobalStoreCons
from emtaint.ir.statements.put import Put
from emtaint.ir.statements.put_tmp import PutTmp
from emtaint.ir.statements.put_const import PutConst
from emtaint.ir.statements.loadg import LoadG
from emtaint.ir.statements.storeg import StoreG
from emtaint.ir.statements.exit import Exit
from emtaint.ir.statements.wr_tmp import WrTmp
from emtaint.ir.statements.wr_get import WrGet
from emtaint.ir.statements.wr_binop import WrBinop
from emtaint.ir.statements.wr_loadc import WrLoadCons
from emtaint.ir.statements.wr_loadt import WrLoadTmp
from emtaint.ir.statements.wr_ite import WrITE
from emtaint.ir.statements.wr_unop import WrUnop

from emtaint.ir.expressions.get import Get
from emtaint.ir.expressions.binop import Binop
from emtaint.ir.expressions.rd_tmp import RdTmp
from emtaint.ir.expressions.load import Load
from emtaint.ir.expressions.const import Const
from emtaint.ir.expressions.unop import Unop
from emtaint.ir.expressions.ite import ITE

from emtaint.assembly.block import Block
from emtaint.ir.vex_ir import VexIR

l = logging.getLogger(name=__name__)


class BlockIRBuilder():
    """

    """
    def __init__(self, block: Block):
        self.block = block

    def build(self):
        """

        """
        bb: AngrBlock = self.block.get_block_source()
        vex = bb.vex
        arch = bb.arch
        if vex is None:
            l.warning("The %s has no VEX IR", bb)
            return None

        # DEBUG
        # if self.block.addr == 0x16FD8:
        #     vex.pp()

        stmts, imarks = self.build_stmts(vex, arch)
        return VexIR(self.block, stmts, imarks=imarks, vex=vex)

    def build_stmts(self, vex, arch):
        """
        :param vex: The VEX IR from Angr
        :param arch: The architecture of the block
        """
        imark_with_stmts = []
        new_stmts, new_imarks = [], []
        for ss in vex.statements:
            # print(ss)
            new_addr, new_data, new_stmt = None, None, None

            if isinstance(ss, pyvex.stmt.IMark):
                new_stmt = IMark(ss.addr, ss.len, ss.delta)
                imark_with_stmts = new_stmt.get_statements()
                new_imarks.append(new_stmt)
                new_stmts.append(new_stmt)
                continue

            if isinstance(ss, pyvex.stmt.WrTmp):
                data = ss.data
                if isinstance(data, pyvex.expr.Get):
                    reg_name = arch.register_names[data.offset]
                    new_data = Get(data.offset, reg_name, data.ty, data.ty_int)
                    new_stmt = WrGet(ss.tmp, new_data)

                elif isinstance(data, pyvex.expr.Binop):
                    new_args = []
                    for arg in data.args:
                        if isinstance(arg, pyvex.expr.RdTmp):
                            new_args.append(RdTmp(arg.tmp))
                        elif isinstance(arg, pyvex.expr.Const):
                            new_args.append(Const(arg.con))
                        else:
                            l.error("The VEX IR %s conversion error.\n with type: %s", ss, type(arg))
                            exit(0)
                    new_data = Binop(data.op, new_args, data.op_int)
                    new_stmt = WrBinop(ss.tmp, new_data)

                elif isinstance(data, pyvex.expr.Load):
                    addr = data.addr
                    if isinstance(addr, pyvex.expr.RdTmp):
                        new_addr = RdTmp(addr.tmp)
                        new_data = Load(data.end, data.ty, new_addr)
                        new_stmt = WrLoadTmp(ss.tmp, new_data)
                    elif isinstance(addr, pyvex.expr.Const):
                        new_addr = Const(addr.con)
                        new_data = Load(data.end, data.ty, new_addr)
                        new_stmt = WrLoadCons(ss.tmp, new_data)
                    else:
                        l.error("The VEX IR %s conversion error.\n with type: %s", ss, type(addr))
                        continue
                    # new_data = Load(data.end, data.ty, new_addr)
                    # new_stmt = WrLoad(ss.tmp, new_data)

                elif isinstance(data, pyvex.expr.RdTmp):
                    new_data = RdTmp(data.tmp)
                    new_stmt = WrTmp(ss.tmp, new_data)

                elif isinstance(data, pyvex.expr.Unop):
                    new_args = []
                    for arg in data.args:
                        if isinstance(arg, pyvex.expr.RdTmp):
                            new_args.append(RdTmp(arg.tmp))
                        elif isinstance(arg, pyvex.expr.Const):
                            new_args.append(Const(arg.con))
                        else:
                            l.error("The VEX IR %s conversion error.\n with type: %s", ss, type(arg))
                            exit(0)
                    new_data = Unop(data.op, new_args)
                    new_stmt = WrUnop(ss.tmp, new_data)

                elif isinstance(data, pyvex.expr.ITE):
                    cond = data.cond
                    iffalse = data.iffalse
                    iftrue = data.iftrue

                    if isinstance(cond, pyvex.expr.RdTmp):
                        new_cond = RdTmp(cond.tmp)
                    else:
                        l.error("The VEX IR %s conversion error.\n with type: %s", ss, type(cond))
                        continue

                    if isinstance(iffalse, pyvex.expr.RdTmp):
                        new_iffalse = RdTmp(iffalse.tmp)
                    else:
                        l.error("The VEX IR %s conversion error.\n with type: %s", ss, type(iffalse))
                        continue

                    if isinstance(iftrue, pyvex.expr.RdTmp):
                        new_iftrue = RdTmp(iftrue.tmp)
                    else:
                        l.error("The VEX IR %s conversion error.\n with type: %s", ss, type(iftrue))
                        continue

                    new_data = ITE(new_cond, new_iffalse, new_iftrue)
                    new_stmt = WrITE(ss.tmp, new_data)

                if new_data is None:
                    l.error("The VEX IR %s conversion error.\n with type: %s", ss, type(data))
                    continue

                # new_stmt = WrTmp(ss.tmp, new_data)

            elif isinstance(ss, pyvex.stmt.Put):
                data = ss.data
                reg_name = arch.register_names[ss.offset]

                if isinstance(data, pyvex.expr.RdTmp):
                    new_data = RdTmp(data.tmp)
                    new_stmt = PutTmp(new_data, ss.offset, reg_name)

                elif isinstance(data, pyvex.expr.Const):
                    new_data = Const(data.con)
                    new_stmt = PutConst(new_data, ss.offset, reg_name)

                if new_data is None:
                    l.error("The VEX IR %s conversion error", ss)
                    continue
                
                # reg_name = arch.register_names[ss.offset]
                # new_stmt = Put(new_data, ss.offset, reg_name)

            elif isinstance(ss, pyvex.stmt.Store):
                addr = ss.addr
                data = ss.data

                if isinstance(addr, pyvex.expr.RdTmp):
                    new_addr = RdTmp(addr.tmp)

                    if isinstance(data, pyvex.expr.RdTmp):
                        new_data = RdTmp(data.tmp)
                        new_stmt = RegStoreTmp(new_addr, new_data, ss.end)

                    elif isinstance(data, pyvex.expr.Const):
                        new_data = Const(data.con)
                        new_stmt = RegStoreCons(new_addr, new_data, ss.end)

                if new_addr is None or new_data is None:
                    l.error("The VEX IR %s conversion error", ss)
                    continue

                # new_stmt = Store(new_addr, new_data, ss.end)

            elif isinstance(ss, pyvex.stmt.LoadG):
                addr = ss.addr
                alt = ss.alt
                guard = ss.guard
                new_alt, new_guard = None, None

                if isinstance(addr, pyvex.expr.RdTmp):
                    new_addr = RdTmp(addr.tmp)

                if isinstance(alt, pyvex.expr.RdTmp):
                    new_alt = RdTmp(alt.tmp)

                if isinstance(guard, pyvex.expr.RdTmp):
                    new_guard = RdTmp(guard.tmp)

                if new_addr is None or new_alt is None or new_guard is None:
                    l.error("The VEX IR %s conversion error", ss)
                    continue

                new_stmt = LoadG(ss.end, ss.cvt, ss.dst, new_addr, new_alt, new_guard)

            elif isinstance(ss, pyvex.stmt.StoreG):
                addr = ss.addr
                data = ss.data
                guard = ss.guard
                new_guard = None

                if isinstance(addr, pyvex.expr.RdTmp):
                    new_addr = RdTmp(addr.tmp)

                if isinstance(data, pyvex.expr.RdTmp):
                    new_data = RdTmp(data.tmp)

                elif isinstance(data, pyvex.expr.Const):
                    new_data = Const(data.con)

                if isinstance(guard, pyvex.expr.RdTmp):
                    new_guard = RdTmp(guard.tmp)

                if new_addr is None or new_data is None or new_guard is None:
                    l.error("The VEX IR %s conversion error", ss)
                    continue

                new_stmt = StoreG(ss.end, new_addr, new_data, new_guard)

            elif isinstance(ss, pyvex.stmt.Exit):
                guard = ss.guard
                new_guard = None
                if isinstance(guard, pyvex.expr.RdTmp):
                    new_guard = RdTmp(guard.tmp)

                if new_guard is None:
                    l.error("The VEX IR %s conversion error.\n with type %s", ss, type(guard))
                    continue

                new_stmt = Exit(new_guard, ss.dst, ss.jk, ss.offsIP)

            else:
                l.error("The VEX IR %s conversion error.\n with type %s", ss, type(ss))
                continue

            # print(f"New stmt: {new_stmt}")
            imark_with_stmts.append(new_stmt)
            new_stmts.append(new_stmt)

        return new_stmts, new_imarks