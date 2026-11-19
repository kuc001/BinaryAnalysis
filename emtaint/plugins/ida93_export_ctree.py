# -*- coding: utf-8 -*-
"""Read-only structured Hex-Rays CTree exporter for IDA Pro 9.3.

Run INSIDE IDA with File -> Script file, with the cursor inside a function.
Do not execute this in the BinaryAnalysis CPython virtual environment.

The output is a raw CTree source artifact, NOT HIR, CIR, or a claim of
lossless IDA type serialization. Default target is 0x11EB8 in the loaded
ARM firmware. Fingerprints exclude export time and local input path. Unsupported nodes are marked explicitly.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from uuid import uuid4

import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_nalt
import ida_typeinf
import idaapi


# Select an export mode. Explicit TARGET_FUNCTION_EAS takes precedence.
TARGET_FUNCTION_EAS = [0x632F8]  # Verified in IDA at runtime; exact EA, not RVA.
EXPORT_ALL_FUNCTIONS = False  # True: attempt every discovered IDA function.
MAX_ALL_FUNCTIONS = 2000  # Fail rather than silently truncate an all-functions export.
OUTPUT_DIR = os.path.join("D:\\Codes", "ctrees")

EXPORT_SCHEMA = "IDA-CTree-Source-F1-draft-v2"
MAX_NODES = 100_000
MAX_DEPTH = 300
MAX_JSON_BYTES = 80 * 1024 * 1024
MAX_STRING_CHARS = 4096
MAX_TYPE_DEPTH = 5
MAX_UDT_MEMBERS = 256
MAX_TYPES = 20000


def compact_json(record):
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def hex_ea(value):
    """Return an explicit VA/EA text; synthetic BADADDR stays null."""
    if type(value) is not int or value == idaapi.BADADDR or value < 0:
        return None
    return hex(value)


def call_optional(obj, name, default=None):
    """Best-effort extraction for descriptive fields, never structural edges."""
    try:
        member = getattr(obj, name)
        return member() if callable(member) else member
    except (AttributeError, ValueError, TypeError, RuntimeError):
        return default


def safe_text(value, maximum=MAX_STRING_CHARS):
    try:
        text = str(value)
    except Exception as error:
        return "<unprintable: {}>".format(type(error).__name__)
    return text[:maximum] + ("...[truncated]" if len(text) > maximum else "")


def op_names():
    """Build an opcode-name map from THIS installed IDA, not a hardcoded SDK."""
    result = {}
    for name in dir(ida_hexrays):
        if not name.startswith(("cot_", "cit_")):
            continue
        value = getattr(ida_hexrays, name)
        if type(value) is int:
            result.setdefault(value, name)
    return result


def iter_ida_vector(vector):
    """Convert IDAPython's qvector or cblock wrapper to an ordered list."""
    try:
        return list(vector)
    except TypeError:
        if hasattr(vector, "size"):
            return [vector[i] for i in range(vector.size())]
        raise


class TypeTable:
    """Bounded *structured hints* from tinfo_t; never claim lossless types.

    Parent type identifiers contain child type identifiers.  Recursion is
    deliberately capped, including self-referential struct/pointer types.
    A collapsed/truncated type has an explicit, machine-readable reason.
    """

    def __init__(self):
        self.records = {}

    def add(self, tif, origin, depth=0):
        if tif is None:
            return None
        if len(self.records) >= MAX_TYPES:
            raise ValueError("Too many type descriptors in one export")
        type_text = call_optional(tif, "dstr")
        facts = {
            "display": safe_text(type_text if type_text is not None else tif),
            "source": origin,
            "representation": "bounded_structural_hints_not_lossless_tinfo",
            "structure_status": "descriptive",
        }
        for method in ("is_ptr", "is_array", "is_udt", "is_func", "is_funcptr",
                       "is_integral", "is_signed", "is_void", "is_float", "is_enum"):
            value = call_optional(tif, method)
            if type(value) is bool:
                facts[method] = value
        size = call_optional(tif, "get_size")
        if type(size) is int and 0 <= size < 1 << 32:
            facts["size_bytes"] = size

        if depth >= MAX_TYPE_DEPTH:
            facts["structure_status"] = "partial"
            facts["structure_reason"] = "MAX_TYPE_DEPTH"
        else:
            try:
                if facts.get("is_ptr"):
                    target = call_optional(tif, "get_pointed_object")
                    if target is not None and not call_optional(target, "empty", False):
                        facts["pointed_type_id"] = self.add(target, origin, depth + 1)
                        facts["structure_status"] = "bounded"
                    else:
                        facts["structure_status"] = "partial"
                        facts["structure_reason"] = "POINTER_TARGET_UNAVAILABLE"
                elif facts.get("is_array"):
                    count = call_optional(tif, "get_array_nelems")
                    if type(count) is int and count >= 0:
                        facts["array_count"] = count
                    target = call_optional(tif, "get_array_element")
                    if target is not None and not call_optional(target, "empty", False):
                        facts["element_type_id"] = self.add(target, origin, depth + 1)
                        facts["structure_status"] = "bounded"
                    else:
                        facts["structure_status"] = "partial"
                        facts["structure_reason"] = "ARRAY_ELEMENT_UNAVAILABLE"
                elif facts.get("is_func"):
                    nargs = call_optional(tif, "get_nargs")
                    if type(nargs) is int and 0 <= nargs <= 256:
                        args = []
                        for i in range(nargs):
                            try:
                                t = tif.get_nth_arg(i)
                            except (AttributeError, TypeError, ValueError, RuntimeError):
                                t = None
                            args.append(self.add(t, origin, depth + 1))
                        facts["argument_type_ids"] = args
                        facts["structure_status"] = "bounded"
                    elif type(nargs) is int and nargs > 256:
                        facts["structure_status"] = "partial"
                        facts["structure_reason"] = "TOO_MANY_FUNCTION_ARGUMENTS"
                    r = call_optional(tif, "get_rettype")
                    if r is not None:
                        facts["return_type_id"] = self.add(r, origin, depth + 1)
                    varargs = call_optional(tif, "is_vararg_cc")
                    if type(varargs) is bool:
                        facts["variadic"] = varargs
                elif facts.get("is_udt"):
                    udt = ida_typeinf.udt_type_data_t()
                    if tif.get_udt_details(udt):
                        members = iter_ida_vector(udt)
                        facts["total_member_count"] = len(members)
                        facts["members"] = []
                        for member in members[:MAX_UDT_MEMBERS]:
                            m = {"name": safe_text(call_optional(member, "name", ""))}
                            off = call_optional(member, "offset")
                            width = call_optional(member, "size")
                            if type(off) is int and off >= 0:
                                m["offset_bits"] = off
                            if type(width) is int and width >= 0:
                                m["size_bits"] = width
                            m["type_id"] = self.add(call_optional(member, "type"), origin, depth + 1)
                            facts["members"].append(m)
                        if len(members) > MAX_UDT_MEMBERS:
                            facts["structure_status"] = "partial"
                            facts["structure_reason"] = "MAX_UDT_MEMBERS"
                        else:
                            facts["structure_status"] = "bounded"
                    else:
                        facts["structure_status"] = "partial"
                        facts["structure_reason"] = "UDT_DETAILS_UNAVAILABLE"
            except (AttributeError, TypeError, ValueError, RuntimeError) as error:
                facts["structure_status"] = "partial"
                facts["structure_reason"] = type(error).__name__ + ": " + safe_text(error)

        digest = hashlib.sha256(compact_json(facts)).hexdigest()
        key = "type:" + digest
        self.records[key] = facts
        return key


class ExportTree:
    """Traverse actual CTree ownership fields and preserve child slot order."""

    def __init__(self, cfunc):
        self.cfunc = cfunc  # Keep Hex-Rays reference alive while traversing.
        self.names = op_names()
        self.nodes = {}
        self.diagnostics = []
        self.op_counts = Counter()
        self.type_table = TypeTable()
        self.opaque_count = 0

    def problem(self, path, reason):
        self.diagnostics.append({"node_path": path, "reason": reason})

    def _field(self, obj, field, path):
        """Structural getter: failures make the export incomplete."""
        try:
            return getattr(obj, field)
        except Exception as error:
            self.problem(path, "Cannot read {}: {}: {}".format(
                field, type(error).__name__, safe_text(error)))
            return None

    def _children(self, node, slots, path, depth):
        for role, items, required in slots:
            if items is None:
                if required:
                    self.problem(path, "Required child missing: " + role)
                    node["status"] = "partial-structure"
                continue
            if not isinstance(items, (list, tuple)):
                items = [items]
            if required and not items:
                self.problem(path, "Required child sequence empty: " + role)
                node["status"] = "partial-structure"
            for index, item in enumerate(items):
                if item is None:
                    self.problem(path, "Null child in {}[{}]".format(role, index))
                    node["status"] = "partial-structure"
                    continue
                if not isinstance(item, (ida_hexrays.cinsn_t, ida_hexrays.cexpr_t)):
                    self.problem(path, "Non-CTree child in {}[{}]".format(role, index))
                    node["status"] = "partial-structure"
                    continue
                child_path = "{}/{}[{}]".format(path, role, index)
                child_id = self.walk(item, child_path, depth + 1)
                node["children"].append({"role": role, "index": index, "id": child_id})

    def _insn_slots(self, item, name, path, node):
        """Use IDA's owned cinsn/cexpr fields, not pseudocode text."""
        slot = lambda role, item, required=True: (role, item, required)
        if isinstance(item, ida_hexrays.ccase_t):
            # A case is itself a cit_block statement with extra case values.
            try:
                raw_values = iter_ida_vector(item.values)
                node["attributes"]["case_values_hex"] = [hex(int(v)) for v in raw_values]
                node["attributes"]["is_default_case"] = not bool(raw_values)
            except Exception as error:
                self.problem(path, "Cannot serialize switch case values: " + safe_text(error))
                node["status"] = "partial-structure"
        if name == "cit_block":
            block = self._field(item, "cblock", path)
            if block is None:
                return [slot("statement", None)]
            try:
                return [slot("statement", iter_ida_vector(block), False)]
            except Exception as error:
                self.problem(path, "Cannot enumerate cblock: " + safe_text(error))
                return [slot("statement", None)]
        if name == "cit_expr":
            return [slot("expression", self._field(item, "cexpr", path))]
        if name == "cit_if":
            info = self._field(item, "cif", path)
            if info is None:
                return [slot("condition", None), slot("then", None)]
            return [slot("condition", self._field(info, "expr", path)),
                    slot("then", self._field(info, "ithen", path)),
                    slot("else", self._field(info, "ielse", path), False)]
        if name in ("cit_for", "cit_while", "cit_do"):
            info = self._field(item, "c" + name[4:], path)
            if info is None:
                return [slot("body", None)]
            if name == "cit_for":
                # For-loop execution visits init, condition, body, step;
                # the header retains init/condition/step syntax roles.
                node["attributes"]["execution_order"] = ["init", "condition", "body", "step"]
                return [slot("init", self._field(info, "init", path), False),
                        slot("condition", self._field(info, "expr", path), False),
                        slot("step", self._field(info, "step", path), False),
                        slot("body", self._field(info, "body", path))]
            if name == "cit_do":
                node["attributes"]["execution_order"] = ["body", "condition"]
                return [slot("body", self._field(info, "body", path)),
                        slot("condition", self._field(info, "expr", path))]
            node["attributes"]["execution_order"] = ["condition", "body"]
            return [slot("condition", self._field(info, "expr", path)),
                    slot("body", self._field(info, "body", path))]
        if name == "cit_switch":
            info = self._field(item, "cswitch", path)
            if info is None:
                return [slot("selector", None)]
            cases = self._field(info, "cases", path)
            if cases is None:
                return [slot("selector", self._field(info, "expr", path)),
                        slot("case", None)]
            try:
                case_items = iter_ida_vector(cases)
            except Exception as error:
                self.problem(path, "Cannot enumerate switch cases: " + safe_text(error))
                case_items = None
            return [slot("selector", self._field(info, "expr", path)),
                    slot("case", case_items)]
        if name in ("cit_return", "cit_throw"):
            info = self._field(item, "c" + name[4:], path)
            return [] if info is None else [slot("value", self._field(info, "expr", path), False)]
        if name == "cit_goto":
            info = self._field(item, "cgoto", path)
            if info is not None:
                target = call_optional(info, "label_num")
                if type(target) is int:
                    node["attributes"]["target_label"] = target
            return []
        if name == "cit_try":
            info = self._field(item, "ctry", path)
            if info is None:
                return [slot("try_statement", None)]
            try:
                statements = iter_ida_vector(info)
                handlers = iter_ida_vector(info.catchs)
            except Exception as error:
                self.problem(path, "Cannot enumerate try/catch: " + safe_text(error))
                return [slot("try_statement", None)]
            slots = [slot("try_statement", statements, False)]
            node["attributes"]["catch_handlers"] = []
            for i, catch in enumerate(handlers):
                detail = {"index": i, "is_catch_all": call_optional(catch, "is_catch_all"),
                          "is_finally": call_optional(catch, "is_finally")}
                node["attributes"]["catch_handlers"].append(detail)
                try:
                    catch_exprs = iter_ida_vector(catch.exprs)
                    for j, expr in enumerate(catch_exprs):
                        fake_type = call_optional(expr, "fake_type", "")
                        if fake_type:
                            detail.setdefault("fake_types", []).append(safe_text(fake_type))
                        slots.append(slot("catch_{}_expr_{}".format(i, j),
                                          self._field(expr, "obj", path)))
                    slots.append(slot("catch_{}_statement".format(i),
                                      iter_ida_vector(catch), False))
                except Exception as error:
                    self.problem(path, "Cannot enumerate catch #{}: {}".format(i, safe_text(error)))
                    node["status"] = "partial-structure"
            return slots
        if name == "cit_asm":
            # Native asm instruction list is not itself a CTree child list.
            raw = self._field(item, "casm", path)
            try:
                node["attributes"]["assembly_eas"] = [hex(int(v)) for v in iter_ida_vector(raw)]
            except Exception as error:
                self.problem(path, "Inline assembly payload unavailable: " + safe_text(error))
                node["status"] = "partial-structure"
            return []
        if name in ("cit_empty", "cit_break", "cit_continue", "cit_end"):
            return []
        self.problem(path, "Opaque/unhandled statement opcode " + name)
        node["status"] = "opaque"
        self.opaque_count += 1
        return []

    def _expr_slots(self, item, name, path, node):
        attrs = node["attributes"]
        slot = lambda role, item, required=True: (role, item, required)
        if name == "cot_var":
            reference = self._field(item, "v", path)
            if reference is not None:
                index = call_optional(reference, "idx")
                if type(index) is int:
                    attrs["lvar_index"] = index
                else:
                    self.problem(path, "Variable index not accessible")
                    node["status"] = "partial-structure"
        elif name == "cot_num":
            number = self._field(item, "n", path)
            if number is not None:
                try:
                    attrs["numeric_value_hex"] = hex(number.value(item.type))
                except Exception as error:
                    self.problem(path, "Numeric constant unavailable: " + safe_text(error))
                    node["status"] = "partial-constant"
        elif name == "cot_obj":
            attrs["object_ea"] = hex_ea(call_optional(item, "obj_ea"))
        elif name == "cot_str":
            literal = call_optional(item, "string")
            if literal is None:
                self.problem(path, "String payload unavailable")
                node["status"] = "partial-string"
            else:
                if isinstance(literal, bytes):
                    attrs["raw_bytes_length"] = len(literal)
                    attrs["raw_bytes_hex"] = literal[:MAX_STRING_CHARS].hex()
                    if len(literal) > MAX_STRING_CHARS:
                        self.problem(path, "String bytes exceed export limit")
                        node["status"] = "partial-string"
                    literal = literal.decode("utf-8", errors="replace")
                else:
                    literal = str(literal)
                attrs["string_length_ch"] = len(literal)
                if len(literal) > MAX_STRING_CHARS:
                    self.problem(path, "String literal exceeds export limit")
                    node["status"] = "partial-string"
                attrs["string"] = literal[:MAX_STRING_CHARS]
        elif name == "cot_helper":
            attrs["helper_name"] = safe_text(call_optional(item, "helper", ""))
        elif name == "cot_fnum":
            self.problem(path, "Floating constant requires fnumber_t exact codec")
            node["status"] = "opaque"
            self.opaque_count += 1
        elif name in ("cot_memref", "cot_memptr"):
            raw = call_optional(item, "m")
            if type(raw) is int:
                attrs["raw_member_value"] = raw
                # For union members this is an index, NOT a byte offset.
                attrs["raw_member_semantics"] = "offset_or_union_member_index_unresolved"
        if name in ("cot_ptr", "cot_memptr"):
            size = call_optional(item, "ptrsize")
            if type(size) is int and size > 0:
                attrs["pointer_access_size_bytes"] = size
        if name == "cot_call":
            attrs["call_target_role"] = "x"
            args = self._field(item, "a", path)
            if args is None:
                self.problem(path, "Call argument list unavailable")
                node["status"] = "partial-structure"
                return [slot("callee", self._field(item, "x", path))]
            try:
                arguments = iter_ida_vector(args)
            except Exception as error:
                self.problem(path, "Cannot enumerate call args: " + safe_text(error))
                node["status"] = "partial-structure"
                return [slot("callee", self._field(item, "x", path))]
            return [slot("callee", self._field(item, "x", path)),
                    slot("argument", arguments, False)]
        if name == "cot_insn":
            self.problem(path, "Embedded cinsn in expression; unexpected at CMAT_FINAL")
            node["status"] = "partial-structure"
            return [slot("embedded_statement", self._field(item, "insn", path))]

        size = call_optional(item, "refwidth")
        if type(size) is int and size > 0:
            attrs["reference_width_bytes"] = size
        slots = []
        for field in ("x", "y", "z"):
            checker = getattr(ida_hexrays, "op_uses_" + field, None)
            if checker is None:
                self.problem(path, "Missing op_uses_{} API".format(field))
                node["status"] = "partial-structure"
                continue
            try:
                used = checker(item.op)
            except Exception as error:
                self.problem(path, "Cannot determine {} operand: {}".format(field, safe_text(error)))
                node["status"] = "partial-structure"
                continue
            if used:
                slots.append(slot(field, self._field(item, field, path)))
        return slots

    def walk(self, item, path="root", depth=0):
        if depth > MAX_DEPTH or len(self.nodes) >= MAX_NODES:
            raise ValueError("CTree traversal exceeds configured depth/node limits")
        kind = "expression" if isinstance(item, ida_hexrays.cexpr_t) else "statement"
        opcode = int(item.op)
        name = self.names.get(opcode, "unrecognized_opcode_{}".format(opcode))
        identifier = "node:" + path
        node = {
            "id": identifier,
            "path": path,
            "category": kind,
            "opcode": name,
            "opcode_value": opcode,
            "ea": hex_ea(call_optional(item, "ea")),
            "label": call_optional(item, "label_num"),
            "children": [],
            "attributes": {},
            "status": "represented",
        }
        self.nodes[identifier] = node
        self.op_counts[name] += 1
        if kind == "expression":
            node["type_id"] = self.type_table.add(
                self._field(item, "type", path), "hexrays_inferred_or_user")
            exflags = call_optional(item, "exflags")
            if type(exflags) is int:
                node["attributes"]["exflags"] = exflags
                if exflags & getattr(ida_hexrays, "EXFL_PARTIAL", 0):
                    node["status"] = "partial-type"
            slots = self._expr_slots(item, name, path, node)
        else:
            slots = self._insn_slots(item, name, path, node)
        self._children(node, slots, path, depth)
        return identifier


def visitor_counts(cfunc):
    """Independent CTree walk: detect known/unknown traversal gaps."""

    class CounterVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.insns = 0
            self.exprs = 0

        def visit_insn(self, insn):
            self.insns += 1
            return 0

        def visit_expr(self, expr):
            self.exprs += 1
            return 0

    visitor = CounterVisitor()
    status = visitor.apply_to(cfunc.body, None)
    return {"status": status, "statements": visitor.insns,
            "expressions": visitor.exprs, "total": visitor.insns + visitor.exprs}


def variables(cfunc, types):
    entries = []
    lvars = cfunc.get_lvars()
    for index, local in enumerate(iter_ida_vector(lvars)):
        locator = {"kind": "unknown"}
        for predicate, kind in (("is_stk_var", "stack"), ("is_reg_var", "register"),
                                ("is_scattered", "scattered")):
            if call_optional(local, predicate) is True:
                locator["kind"] = kind
                break
        if locator["kind"] == "stack":
            offset = call_optional(local, "get_stkoff")
            if type(offset) is int:
                locator["raw_stack_offset"] = offset
                delta = call_optional(cfunc, "get_stkoff_delta")
                if type(delta) is int:
                    locator["ida_frame_offset"] = offset - delta
        elif locator["kind"] == "register":
            reg = call_optional(local, "get_reg1")
            if type(reg) is int:
                locator["micro_register"] = reg
        tif = call_optional(local, "tif")
        if tif is None:
            tif = call_optional(local, "type")
        entries.append({
            "lvar_index": index,
            "name": safe_text(call_optional(local, "name", "")),
            "type_id": types.add(tif, "decompiler_or_user_annotation"),
            "size_bytes": call_optional(local, "width"),
            "argument": call_optional(local, "is_arg_var"),
            "user_name": call_optional(local, "has_user_name"),
            "user_type": call_optional(local, "has_user_type"),
            "storage": locator,
            "definition_ea": hex_ea(call_optional(local, "defea")),
        })
    return entries


def environment():
    input_path = call_optional(ida_nalt, "get_input_file_path")
    input_path = str(input_path) if input_path else None
    input_digest = None
    if input_path and os.path.isfile(input_path):
        h = hashlib.sha256()
        with open(input_path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                h.update(chunk)
        input_digest = h.hexdigest()
    imagebase = call_optional(ida_nalt, "get_imagebase")
    if imagebase is None:
        imagebase = call_optional(idaapi, "get_imagebase")
    return {
        "ida_version": safe_text(call_optional(idaapi, "get_kernel_version", "unknown")),
        "hexrays_version": safe_text(call_optional(ida_hexrays, "get_hexrays_version", "unknown")),
        "python_version": sys.version.split(" ")[0],
        "processor": safe_text(call_optional(ida_ida, "inf_get_procname", "unknown")),
        "input_file_path": input_path,
        "input_file_sha256": input_digest,
        "ida_image_base_ea": hex_ea(imagebase),
        "source_address_domain": "IDA_EA",
        "no_ea_marker": "null",
        "type_encoding": "bounded_structural_hints_not_lossless",
        "decompiler_ctree_maturity": "recorded_per_function_in_decompilation",
    }


def export_one(ea, outdir):
    env = environment()
    func = ida_funcs.get_func(ea)
    if func is None:
        raise ValueError("No IDA function contains EA " + hex(ea))
    entry = func.start_ea
    if entry != ea:
        raise ValueError("Selected EA {} lies inside a function starting at {}; "
                         "set TARGET_FUNCTION_EAS to the actual entry".format(hex(ea), hex(entry)))
    try:
        cfunc = ida_hexrays.decompile(entry)
    except Exception as error:
        raise RuntimeError("Hex-Rays cannot decompile {}: {}".format(hex(entry), error)) from error
    if not cfunc:
        raise RuntimeError("Hex-Rays decompile returned no cfunc at " + hex(entry))

    tree = ExportTree(cfunc)
    root = tree.walk(cfunc.body)
    local_vars = variables(cfunc, tree.type_table)
    try:
        counted = visitor_counts(cfunc)
    except Exception as error:
        counted = {"error": type(error).__name__ + ": " + safe_text(error)}
        tree.problem("root", "ctree_visitor_t independent count unavailable")

    counted_struct = {
        "statements": sum(n["category"] == "statement" for n in tree.nodes.values()),
        "expressions": sum(n["category"] == "expression" for n in tree.nodes.values()),
        "total": len(tree.nodes),
    }
    if "total" in counted and (counted["total"] != counted_struct["total"] or
                               counted.get("status") != 0):
        tree.problem("root", "Structural node count differs from independent Hex-Rays visitor")
    bad_lvars = sorted(set(n["attributes"].get("lvar_index") for n in tree.nodes.values()
                           if n["opcode"] == "cot_var") - set(range(len(local_vars))),
                       key=lambda x: str(x))
    if bad_lvars:
        tree.problem("root", "Invalid local-variable indexes: " + safe_text(bad_lvars))

    observed_maturity = call_optional(cfunc, "maturity")
    observed_maturity_name = None
    if type(observed_maturity) is int:
        for candidate in dir(ida_hexrays):
            if candidate.startswith("CMAT_") and getattr(ida_hexrays, candidate) == observed_maturity:
                observed_maturity_name = candidate
                break
    payload = {
        "schema_version": EXPORT_SCHEMA,
        "exported_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": env,
        "decompilation": {
            "maturity_value": observed_maturity if type(observed_maturity) is int else None,
            "maturity_name": observed_maturity_name,
        },
        "function": {
            "entry_ea": hex(entry),
            "name": safe_text(ida_funcs.get_func_name(entry)),
            "end_ea": hex_ea(func.end_ea),
            "root_node": root,
        },
        "nodes": tree.nodes,
        "local_variables": local_vars,
        "types": tree.type_table.records,
        "op_histogram": dict(sorted(tree.op_counts.items())),
        "verification": {
            "structural": counted_struct,
            "ida_visitor": counted,
            "diagnostic_count": len(tree.diagnostics),
            "opaque_node_count": tree.opaque_count,
            "structural_status": "partial" if tree.diagnostics else "covered",
            "type_serialization_status": "bounded_structural_hints_not_lossless",
            "partial_type_count": sum(
                facts.get("structure_status") == "partial"
                for facts in tree.type_table.records.values()
            ),
        },
        "diagnostics": tree.diagnostics,
        "scope": "CTree source representation only; not HIR or CIR; unverified high-level type semantics",
    }
    # Identity excludes wall clock and local input path.  Content changes,
    # producer version, source identity or diagnostics change the digest.
    payload["export_fingerprint_algorithm"] = "sha256-canonical-ctree-semantic-v2"
    payload["export_fingerprint"] = hashlib.sha256(compact_json({
        key: value for key, value in payload.items()
        if key not in ("exported_at_utc", "export_fingerprint")
        and key != "environment"
    } | {"environment": {
        key: value for key, value in payload["environment"].items()
        if key != "input_file_path"
    }})).hexdigest()
    encoded = json.dumps(payload, indent=2, ensure_ascii=False,
                         sort_keys=True, allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_JSON_BYTES:
        raise ValueError("Export JSON exceeds configured file size limit")
    outdir.mkdir(parents=True, exist_ok=True)
    filename = "ctree_{:x}_{}.json".format(entry, uuid4().hex[:10])
    destination = outdir / filename
    with destination.open("xb") as result:
        result.write(encoded)
    return destination, len(tree.nodes), tree.diagnostics


def main():
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is unavailable for this processor/license")
    outdir = Path(OUTPUT_DIR)
    if TARGET_FUNCTION_EAS:
        selected = list(TARGET_FUNCTION_EAS)
    elif EXPORT_ALL_FUNCTIONS:
        import idautils
        selected = list(idautils.Functions())
        if len(selected) > MAX_ALL_FUNCTIONS:
            raise ValueError("Function count {} exceeds MAX_ALL_FUNCTIONS; "
                             "increase the limit deliberately".format(len(selected)))
    else:
        selected = [ida_kernwin.get_screen_ea()]
    print("[F1/CTree] Selected functions:", len(selected))
    failures = []
    for address in selected:
        try:
            file_path, count, diagnostics = export_one(int(address), outdir)
            print("[F1/CTree] Exported:", file_path)
            print("[F1/CTree] Nodes:", count, "Diagnostics:", len(diagnostics))
            print("[F1/CTree] File SHA256:", hashlib.sha256(file_path.read_bytes()).hexdigest())
        except Exception as error:
            failures.append((address, safe_text(error)))
            print("[F1/CTree] FAILED {}: {}".format(hex(int(address)), error))
    if failures:
        raise RuntimeError("{} function(s) could not be exported; see IDA output".format(len(failures)))


if __name__ == "__main__":
    main()
