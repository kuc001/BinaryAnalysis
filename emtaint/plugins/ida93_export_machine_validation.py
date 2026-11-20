"""Export pinned ARM machine evidence from an open IDA 9.3 database.

Run with File > Script file in IDA. The script reads the IDB and input file
and creates a new JSON in .f1-input/machine-validation. It does not save the IDB.
"""
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import ida_allins
import ida_auto
import ida_bytes
import ida_funcs
import ida_gdl
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_loader
import ida_nalt
import ida_segregs
import ida_ua
import ida_xref
import idautils

SCHEMA = "IDA-Machine-Validation-v1"
BINARY_SHA256 = "334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787"
ENTRY = 0x632F8
BASE = 0x8000
OUTPUT_DIR = Path(__file__).resolve().parents[2] / ".f1-input" / "machine-validation"


def _mode(ea: int, register: int) -> str:
    value = ida_segregs.get_sreg(ea, register) if register >= 0 else None
    return {0: "arm", 1: "thumb"}.get(value, "unknown")


def _direct_target(operands) -> int | None:
    targets = [int(op.addr) for op in operands if op.type in {ida_ua.o_near, ida_ua.o_far}
               and int(op.addr) != ida_idaapi.BADADDR]
    return targets[0] if len(targets) == 1 else None


def _raw_byte(value: int | str | bytes) -> int:
    return (ord(value) if isinstance(value, (str, bytes)) else int(value)) & 0xFF


def _instruction(ea: int, limit: int, image: bytes, t_register: int, diagnostics: list[dict]) -> dict | None:
    insn = ida_ua.insn_t()
    size = ida_ua.decode_insn(insn, ea)
    if size <= 0 or ea + size > limit:
        diagnostics.append({"ea": hex(ea), "reason": "Instruction missing or crosses chunk boundary"})
        return None
    mode = _mode(ea, t_register)
    raw = ida_bytes.get_bytes(ea, size)
    offset = ida_loader.get_fileregion_offset(ea)
    last_offset = ida_loader.get_fileregion_offset(ea + size - 1)
    file_offset = int(offset) if 0 <= offset <= len(image) - size and last_offset == offset + size - 1 else None
    binary_matches = file_offset is not None and raw is not None and raw == image[file_offset:file_offset + size]
    if not binary_matches:
        diagnostics.append({"ea": hex(ea), "reason": "IDB bytes or file offset could not be verified"})
    if mode == "unknown":
        diagnostics.append({"ea": hex(ea), "reason": "IDA T register mode unavailable"})

    operands = [op for op in insn if op.type != ida_ua.o_void]
    operand_evidence = []
    for op in operands:
        fact = {"index": int(op.n), "ida_type": int(op.type), "ida_dtype": int(op.dtype)}
        if op.type == ida_ua.o_reg:
            fact["ida_register"] = int(op.reg)
        if op.type in {ida_ua.o_phrase, ida_ua.o_displ}:
            fact.update(raw_phrase=int(op.phrase), raw_address=int(op.addr),
                        raw_flags=[_raw_byte(flag) for flag in
                                   (op.specflag1, op.specflag2, op.specflag3, op.specflag4)])
        operand_evidence.append(fact)
    target = _direct_target(operands)
    jump_types = {ida_xref.fl_JF, ida_xref.fl_JN}
    call_types = {ida_xref.fl_CF, ida_xref.fl_CN}
    refs = [{"target_ea": hex(ref.to), "type": int(ref.type), "user": bool(ref.user)}
            for ref in idautils.XrefsFrom(ea) if ref.iscode and ref.to != ida_idaapi.BADADDR]
    refs.sort(key=lambda row: (int(row["target_ea"], 16), row["type"], row["user"]))
    call = ida_idp.is_call_insn(insn)
    returns = not call and ida_idp.is_ret_insn(insn, ida_idp.IRI_RET_LITERALLY)
    jumps = not call and not returns and (ida_idp.is_indirect_jump_insn(insn)
                                          or insn.itype in {ida_allins.ARM_b, ida_allins.ARM_bx}
                                          or any(ref["type"] in jump_types for ref in refs))
    category = "call" if call else "return" if returns else "branch" if jumps else "ordinary"
    if category == "ordinary":
        target = None
    register_transfer = any(op.type == ida_ua.o_reg for op in operands)
    transfer = ("direct" if target is not None else "indirect" if register_transfer or
                ida_idp.is_indirect_jump_insn(insn) else "unresolved") if call or jumps else None
    opcode = {ida_allins.ARM_bl: "BL", ida_allins.ARM_blx1: "BLX",
              ida_allins.ARM_blx2: "BLX"}.get(insn.itype) if call else None
    call_class = None
    thunk = None
    if call:
        destination = ida_funcs.get_func(target) if target is not None else None
        thunk = (bool(destination.flags & ida_funcs.FUNC_THUNK)
                 if destination is not None and destination.start_ea == target else None)
        call_class = ("register_indirect" if register_transfer and target is None else
                      "direct" if target is not None else "unresolved")
    is_conditional = None
    if category in {"branch", "return", "call"} and mode == "arm" and raw is not None and size == 4:
        is_conditional = (int.from_bytes(raw, "little") >> 28) < 0xE
    elif jumps and target is not None:
        is_conditional = any(ref["type"] == ida_xref.fl_F for ref in refs)

    return {
        "ea": hex(ea), "rva": hex(ea - BASE), "file_offset": file_offset,
        "raw_bytes": raw.hex() if raw is not None else None, "binary_bytes_match": binary_matches,
        "size": size, "mode": mode, "mnemonic": ida_ua.print_insn_mnem(ea),
        "operands": [ida_lines.tag_remove(ida_ua.print_operand(ea, op.n) or "") for op in operands],
        "operand_evidence": operand_evidence,
        "category": category, "transfer": transfer, "conditional": is_conditional,
        "direct_target_ea": hex(target) if target is not None else None, "code_refs": refs,
        "call_opcode": opcode, "call_class": call_class, "target_is_ida_thunk": thunk,
        "ida_call_xrefs": [ref["target_ea"] for ref in refs if ref["type"] in call_types],
    }


def _blocks(function, instructions: dict, diagnostics: list[dict]) -> list[dict]:
    flow = list(ida_gdl.FlowChart(function, flags=ida_gdl.FC_NOEXT))
    records = []
    assigned = set()
    for block in flow:
        block_instructions = sorted(ea for ea in instructions if block.start_ea <= ea < block.end_ea)
        if assigned.intersection(block_instructions):
            diagnostics.append({"ea": hex(block.start_ea), "reason": "Instruction belongs to multiple IDA blocks"})
        assigned.update(block_instructions)
        last = instructions[block_instructions[-1]] if block_instructions else None
        succs = sorted({int(succ.start_ea) for succ in block.succs()})
        preds = sorted({int(pred.start_ea) for pred in block.preds()})
        is_return = bool(ida_gdl.is_ret_block(block.type)) or bool(last and last["category"] == "return")
        direct_target = int(last["direct_target_ea"], 16) if last and last["direct_target_ea"] else None
        outside = last and last["category"] == "branch" and direct_target is not None and direct_target not in succs
        unknown = (last is None or bool(outside) or
                   last["category"] == "branch" and last["transfer"] in {"indirect", "unresolved"}
                   or not succs and not is_return and not ida_gdl.is_noret_block(block.type))
        if unknown:
            diagnostics.append({"ea": hex(block.start_ea), "reason": "Machine CFG successor boundary unresolved"})
        records.append({
            "start_ea": hex(block.start_ea), "end_ea": hex(block.end_ea), "ida_block_type": int(block.type),
            "instruction_eas": [hex(ea) for ea in block_instructions],
            "successors": [hex(ea) for ea in succs], "predecessors": [hex(ea) for ea in preds],
            "entry": block.start_ea == function.start_ea, "exit": not succs, "return": is_return,
            "tail": last["category"] if last else None, "transfer": last["transfer"] if last else None,
            "conditional": last["conditional"] if last else None, "unknown_successor": bool(unknown),
        })
    if len(assigned) != len(instructions):
        diagnostics.append({"ea": hex(function.start_ea), "reason": "Some IDA code heads are outside the FlowChart"})
    return sorted(records, key=lambda row: int(row["start_ea"], 16))


def export_machine_validation() -> Path:
    """Read and publish one IDA-side evidence export with pinned input identity."""
    version = ida_kernwin.get_kernel_version()
    processor = ida_ida.inf_get_procname()
    if version.split(".")[:2] != ["9", "3"] or processor.upper() != "ARM":
        raise ValueError(f"Expected IDA 9.3 ARM, got {version} {processor}")
    if not ida_auto.auto_wait():
        raise RuntimeError("IDA autoanalysis did not complete")
    image = Path(ida_nalt.get_input_file_path()).read_bytes()
    database_hash = ida_nalt.retrieve_input_file_sha256()
    if (not database_hash or database_hash.hex() != BINARY_SHA256
            or sha256(image).hexdigest() != BINARY_SHA256 or ida_nalt.get_imagebase() != BASE):
        raise ValueError("IDA database, file SHA-256 or expected image base mismatch")
    function = ida_funcs.get_func(ENTRY)
    if function is None or function.start_ea != ENTRY:
        raise ValueError(f"No exact IDA function entry at {ENTRY:#x}")

    diagnostics: list[dict] = []
    t_register = ida_idp.str2reg("T")
    chunks = sorted(idautils.Chunks(ENTRY))
    instructions = {}
    for start, end in chunks:
        cursor = start
        for ea in idautils.Heads(start, end):
            if ea != cursor:
                diagnostics.append({"ea": hex(cursor), "reason": f"Uncovered chunk bytes up to {ea:#x}"})
            cursor = ida_bytes.get_item_end(ea)
            if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                diagnostics.append({"ea": hex(ea), "reason": "Non-code head inside function chunk"})
                continue
            row = _instruction(ea, end, image, t_register, diagnostics)
            if row is not None:
                instructions[ea] = row
                if row["size"] != cursor - ea:
                    diagnostics.append({"ea": hex(ea), "reason": "IDA item size differs from decoder"})
        if cursor != end:
            diagnostics.append({"ea": hex(cursor), "reason": f"Uncovered chunk tail ending at {end:#x}"})
    if ENTRY not in instructions:
        raise ValueError("IDA function entry has no decoded code head")
    blocks = _blocks(function, instructions, diagnostics)
    if not any(block["entry"] for block in blocks):
        raise ValueError("IDA FlowChart omitted the function entry")
    ordered = [instructions[ea] for ea in sorted(instructions)]
    payload = {
        "schema_version": SCHEMA, "exported_at_utc": datetime.now(timezone.utc).isoformat(),
        "function": {
            "binary_sha256": BINARY_SHA256, "ida_version": version, "processor": processor,
            "image_base": hex(BASE), "entry_ea": hex(ENTRY), "end_ea": hex(function.end_ea),
            "rva": hex(ENTRY - BASE), "mode": _mode(ENTRY, t_register),
            "size": sum(end - start for start, end in chunks),
            "chunks": [{"start_ea": hex(start), "end_ea": hex(end)} for start, end in chunks],
        },
        "instructions": ordered, "machine_cfg": {"blocks": blocks},
        "calls": [row for row in ordered if row["category"] == "call"], "diagnostics": diagnostics,
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / f"machine-validation-{ENTRY:x}-{uuid4().hex}.json"
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False, allow_nan=False)
        handle.write("\n")
    return path


if __name__ == "__main__":
    print(f"IDA machine evidence exported to {export_machine_validation()}")
