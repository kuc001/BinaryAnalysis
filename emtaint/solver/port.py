"""P1 solver boundary DTOs; these are not the P3 CIR or a memory model."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, Self


class SolverStatus(str, Enum):
    """Explicit solver outcomes; unknown and failure are never false UNSAT."""

    SAT = "SAT"
    UNSAT = "UNSAT"
    UNKNOWN = "UNKNOWN"
    TIMEOUT = "TIMEOUT"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"
    CRASH = "CRASH"


@dataclass(frozen=True)
class Term:
    """Small pure-BV query protocol, deliberately independent of Claripy classes."""
    op: str
    width: int | None = None
    args: tuple[Term | str | int | bool, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Serialize the pure value tree without native solver objects."""

        return {"op": self.op, "width": self.width,
                "args": [a.to_dict() if isinstance(a, Term) else a for a in self.args]}

    @classmethod
    def from_dict(cls, value: object, depth: int = 0) -> Self:
        """Decode a bounded value tree and reject malformed containers."""

        if depth > 64 or not isinstance(value, dict) or set(value) != {"op", "width", "args"}:
            raise ValueError("Malformed or over-deep solver term")
        if not isinstance(value["args"], list):
            raise ValueError("Term args must be a list")
        return cls(value["op"], value["width"], tuple(
            cls.from_dict(a, depth + 1) if isinstance(a, dict) else a for a in value["args"]))


class UnsupportedQuery(ValueError):
    """The query is valid input but outside the supported pure-BV protocol."""


def validate_term(term: Term) -> None:
    """Type-check before importing a solver; reject legacy memory markers everywhere."""
    stack = [(term, 0)]
    nodes = 0
    widths = {}
    while stack:
        node, depth = stack.pop()
        if not isinstance(node, Term):
            raise ValueError("Expected a solver Term")
        nodes += 1
        if nodes > 10000 or depth > 64:
            raise UnsupportedQuery("Solver protocol node/depth budget exceeded")
        if type(node.op) is not str:
            raise ValueError("Term operation must be text")
        if not isinstance(node.args, tuple):
            raise ValueError("Term arguments must be an immutable tuple")
        if node.op in ("Load", "Store", "MemoryRead", "Select", "ArrayStore"):
            raise UnsupportedQuery("Memory operation requires P5 semantic lowering: " + node.op)
        if node.width is not None and (type(node.width) is not int or not 1 <= node.width <= 4096):
            raise ValueError("Bit width must be an integer from 1 to 4096")
        op, args, width = node.op, node.args, node.width
        if op == "BVS":
            if width is None or len(args) != 1 or type(args[0]) is not str or not args[0]:
                raise ValueError("BVS needs a name and bit width")
            if args[0] in widths and widths[args[0]] != width:
                raise ValueError("Conflicting widths for one symbol")
            widths[args[0]] = width
        elif op == "BVV":
            if width is None or len(args) != 1 or type(args[0]) is not int or not 0 <= args[0] < (1 << width):
                raise ValueError("BVV value must already be truncated to its bit width")
        elif op == "BoolV":
            if width is not None or len(args) != 1 or type(args[0]) is not bool:
                raise ValueError("BoolV needs one boolean")
        elif op in ("Add", "Sub", "AndBits", "OrBits", "XorBits", "Mul"):
            if width is None or len(args) != 2 or any(not isinstance(a, Term) or a.width != width for a in args):
                raise ValueError("Binary BV operands must have equal widths")
        elif op in ("Eq", "ULT", "ULE", "SLT", "SLE"):
            if width is not None or len(args) != 2 or any(not isinstance(a, Term) for a in args):
                raise ValueError("Comparison needs two terms and a boolean result")
            if args[0].width != args[1].width or (op != "Eq" and args[0].width is None):
                raise ValueError("Comparison operand sort/width mismatch")
        elif op in ("And", "Or", "Not"):
            if width is not None or len(args) != (1 if op == "Not" else 2) or any(not isinstance(a, Term) or a.width is not None for a in args):
                raise ValueError("Boolean operand mismatch")
        elif op == "Extract":
            if len(args) != 3 or type(args[0]) is not int or type(args[1]) is not int or not isinstance(args[2], Term):
                raise ValueError("Extract requires high, low, BV")
            high, low, source = args
            if source.width is None or not 0 <= low <= high < source.width or width != high - low + 1:
                raise ValueError("Invalid extract bounds")
        elif op in ("ZeroExt", "SignExt"):
            if len(args) != 2 or type(args[0]) is not int or args[0] < 0 or not isinstance(args[1], Term) or args[1].width is None or width != args[1].width + args[0]:
                raise ValueError("Invalid extension")
        elif op == "Concat":
            if len(args) < 2 or any(not isinstance(a, Term) or a.width is None for a in args) or width != sum(a.width for a in args):
                raise ValueError("Invalid concatenation")
        elif op == "If":
            if len(args) != 3 or any(not isinstance(a, Term) for a in args) or args[0].width is not None or args[1].width != args[2].width or width != args[1].width:
                raise ValueError("Invalid conditional")
        else:
            raise UnsupportedQuery("Unsupported P1 pure-BV operation: " + op)
        stack.extend((a, depth + 1) for a in args if isinstance(a, Term))


@dataclass(frozen=True)
class SolverQuery:
    """Bounded, portable solver request with explicit operation and deadline."""

    constraints: tuple[Term, ...]
    expression: Term | None = None
    operation: str = "check"
    timeout_ms: int = 1000
    limit: int = 1
    origin: str = ""

    def validate(self) -> None:
        """Validate sorts, widths, resource bounds, and operation contracts."""

        if not isinstance(self.constraints, tuple) or not isinstance(self.origin, str):
            raise ValueError("Constraints must be a tuple; origin must be text")
        if self.operation not in ("check", "eval", "min", "max"):
            raise UnsupportedQuery("Unsupported solver query operation")
        if type(self.timeout_ms) is not int or not 1 <= self.timeout_ms <= 300000:
            raise ValueError("Invalid solver timeout")
        if type(self.limit) is not int or not 1 <= self.limit <= 64:
            raise ValueError("Invalid evaluation limit")
        if not self.constraints:
            raise ValueError("Supply at least one explicit constraint (BoolV(True) allowed)")
        # Validate together, including symbol-width conflicts across constraints.
        # Balanced validation tree avoids an artificial depth limit on a flat
        # constraint batch. Original constraints remain unchanged for lowering.
        batch = list(self.constraints)
        if len(batch) > 10000:
            raise UnsupportedQuery("Constraint batch budget exceeded")
        while len(batch) > 1:
            batch = [Term("And", None, (batch[i], batch[i + 1])) if i + 1 < len(batch)
                     else batch[i] for i in range(0, len(batch), 2)]
        combined = batch[0]
        validate_term(combined)
        if any(c.width is not None for c in self.constraints):
            raise ValueError("Constraints must be boolean")
        if self.expression is not None:
            validate_term(self.expression)
            # Also check symbol consistency with the constraints.
            validate_term(Term("If", self.expression.width, (combined, self.expression, self.expression)))
        if self.operation != "check" and (self.expression is None or self.expression.width is None):
            raise ValueError("BV expression required for eval/min/max")

    def to_dict(self) -> dict[str, object]:
        """Validate and serialize the complete solver request."""

        self.validate()
        return {"protocol": "p1-pure-bv-1", "constraints": [c.to_dict() for c in self.constraints],
                "expression": self.expression.to_dict() if self.expression else None,
                "operation": self.operation, "timeout_ms": self.timeout_ms,
                "limit": self.limit, "origin": self.origin}

    @classmethod
    def from_dict(cls, value: object) -> Self:
        """Decode an exact request payload from an untrusted process boundary."""

        expected = {
            "protocol", "constraints", "expression", "operation",
            "timeout_ms", "limit", "origin",
        }
        if type(value) is not dict or set(value) != expected:
            raise ValueError("Malformed solver query payload")
        if value.get("protocol") != "p1-pure-bv-1":
            raise ValueError("Unknown solver protocol")
        if type(value["constraints"]) is not list:
            raise ValueError("Solver constraints must be a list")
        if value["expression"] is not None and type(value["expression"]) is not dict:
            raise ValueError("Solver expression must be a term object or null")
        query = cls(tuple(Term.from_dict(c) for c in value["constraints"]),
                    Term.from_dict(value["expression"]) if value["expression"] else None,
                    value["operation"], value["timeout_ms"], value["limit"], value["origin"])
        query.validate()
        return query


@dataclass(frozen=True)
class SolverResult:
    """Portable solver outcome with explicit status, evidence, and exit code."""

    status: SolverStatus
    values: tuple[int, ...] = ()
    reason: str = ""
    backend: str = "claripy"
    origin: str = ""
    evidence: str = ""
    exit_code: int | None = None

    def __bool__(self) -> bool:
        raise TypeError("SolverResult has no truth value; inspect its explicit status")

    def to_dict(self) -> dict[str, object]:
        """Serialize a result while preserving unknown/failure evidence."""

        return {"status": self.status.value, "values": list(self.values), "reason": self.reason,
                "backend": self.backend, "origin": self.origin, "evidence": self.evidence,
                "exit_code": self.exit_code}

    @classmethod
    def from_dict(cls, value: object) -> Self:
        """Decode a worker result and reject wrong container/value types."""

        allowed = {"status", "values", "reason", "backend", "origin", "evidence", "exit_code"}
        if type(value) is not dict or "status" not in value or not set(value) <= allowed:
            raise ValueError("Malformed solver result payload")
        values = value.get("values", [])
        if type(values) is not list or any(type(item) is not int for item in values):
            raise ValueError("Solver result values must be a list of integers")
        for name in ("reason", "backend", "origin", "evidence"):
            if type(value.get(name, "")) is not str:
                raise ValueError("Solver result text fields must be strings")
        exit_code = value.get("exit_code")
        if exit_code is not None and type(exit_code) is not int:
            raise ValueError("Solver result exit code must be an integer or null")
        return cls(SolverStatus(value["status"]), tuple(value.get("values", [])),
                   value.get("reason", ""), value.get("backend", "claripy"),
                   value.get("origin", ""), value.get("evidence", ""), value.get("exit_code"))


class SolverPort(Protocol):
    """Protocol implemented by in-process and isolated solver adapters."""

    def solve(self, query: SolverQuery) -> SolverResult:
        """Return one explicit solver outcome for a validated portable query."""

        ...
