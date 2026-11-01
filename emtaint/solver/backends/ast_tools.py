"""Python 3.7-compatible AST contracts shared by isolated old/new probes.

Raw objects stay inside this boundary. Portable export is a P1 BV query DTO,
not CIR/Heap/SSE. Annotated or unsupported nodes fail explicitly.
"""
import hashlib
import json


class UnsupportedAST(ValueError):
    pass


def _base(claripy):
    return claripy.ast.Base


def children(claripy, root, unique=False, max_visits=10000):
    """Preorder descendants, preserving legacy occurrence order by default."""
    stack = [iter(root.args)]
    seen = set()
    count = 0
    while stack:
        try:
            child = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if not isinstance(child, _base(claripy)):
            continue
        count += 1
        if count > max_visits:
            raise UnsupportedAST("AST traversal budget exceeded")
        if unique:
            key = structural_key(claripy, child)
            if key in seen:
                continue
            seen.add(key)
        yield child
        stack.append(iter(child.args))


def leaves(claripy, root, max_visits=10000):
    stack, seen = [root], set()
    count = 0
    while stack:
        node = stack.pop()
        count += 1
        if count > max_visits:
            raise UnsupportedAST("AST leaf traversal budget exceeded")
        key = structural_key(claripy, node)
        if key in seen:
            continue
        seen.add(key)
        args = [a for a in node.args if isinstance(a, _base(claripy))]
        if not args:
            yield node
        else:
            stack.extend(args)  # Same LIFO order as legacy Base.leaf_asts.


_ALIASES = {"__add__": "Add", "__sub__": "Sub", "__mul__": "Mul",
            "__and__": "AndBits", "__or__": "OrBits", "__xor__": "XorBits",
            "__eq__": "Eq", "Eq": "Eq", "Eq_": "Eq", "Add": "Add",
            "Sub": "Sub", "Mul": "Mul"}
_SUPPORTED = {"Add", "Sub", "Mul", "AndBits", "OrBits", "XorBits", "Eq",
              "ULT", "ULE", "SLT", "SLE", "And", "Or", "Not", "Extract",
              "ZeroExt", "SignExt", "Concat", "If"}


def export(claripy, root, allow_legacy_memory=False, depth=0, budget=None):
    if budget is None:
        budget = [10000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 64:
        raise UnsupportedAST("AST export budget exceeded")
    if not isinstance(root, _base(claripy)):
        raise ValueError("Expected a Claripy AST")
    if root.annotations:
        raise UnsupportedAST("Annotated AST needs an explicit portable annotation policy")
    op = root.op
    width = root.size() if isinstance(root, claripy.ast.BV) else None
    if op == "BVS":
        # Reject legacy VSA bounds instead of silently exporting only its name.
        if len(root.args) == 7:
            if (any(a is not None for a in root.args[1:4])
                    or root.args[4] not in (None, False) or root.args[5] is not False
                    or root.args[6] is not None):
                raise UnsupportedAST("Legacy bounded/flagged BVS needs a VSA contract")
        elif len(root.args) != 2 or root.args[1] != width:
            raise UnsupportedAST("Unrecognized BVS argument contract")
        args = [root.args[0]]
    elif op == "BVV":
        args = [root.args[0]]
    elif op == "BoolV":
        args = [root.args[0]]
    else:
        op = _ALIASES.get(op, op)
        if op in ("Load", "Store"):
            if not allow_legacy_memory or len(root.args) != 1:
                raise UnsupportedAST("Legacy memory marker requires P5 semantic lowering")
        elif op not in _SUPPORTED:
            raise UnsupportedAST("Unsupported AST operation: " + op)
        args = [export(claripy, a, allow_legacy_memory, depth + 1, budget)
                if isinstance(a, _base(claripy)) else a for a in root.args]
    if any(not isinstance(a, (dict, str, int, bool)) for a in args):
        raise UnsupportedAST("Nonportable AST argument")
    return {"op": op, "width": width, "args": args}


def structural_key(claripy, root):
    data = export(claripy, root)
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def replace(claripy, root, old, new):
    if not all(isinstance(a, _base(claripy)) for a in (root, old, new)):
        raise TypeError("Replacement operands must be ASTs")
    old_bv, new_bv = isinstance(old, claripy.ast.BV), isinstance(new, claripy.ast.BV)
    if type(old) is not type(new) or old_bv != new_bv or (old_bv and old.size() != new.size()):
        raise ValueError("Replacement requires equal sort/width; use explicit Extract/Ext")
    method = getattr(root, "replace", None)
    return method(old, new) if method is not None else claripy.replace(root, old, new)
