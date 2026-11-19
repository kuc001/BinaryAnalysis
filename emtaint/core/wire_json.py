"""Bounded canonical JSON primitives for versioned interchange records."""
import json
import re
from typing import Any


def canonical_json(value: object) -> bytes:
    """Encode deterministic UTF-8 JSON while preserving array order."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_number(value: str) -> None:
    raise ValueError(f"Unsupported JSON number: {value}")


def read_record(data: bytes, *, max_bytes: int = 80 * 1024 * 1024) -> dict[str, Any]:
    """Reject duplicate keys, non-integers, excessive bytes and invalid UTF-8."""
    if type(data) is not bytes or len(data) > max_bytes:
        raise ValueError("JSON byte budget exceeded or input is not bytes")
    try:
        record = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs,
                            parse_constant=_invalid_number, parse_float=_invalid_number)
    except RecursionError as error:
        raise ValueError("JSON nesting exceeds the parser limit") from error
    if type(record) is not dict:
        raise ValueError("Expected a JSON object")
    return record


def hex_address(value: object) -> int:
    """Parse a hexadecimal address in the unsigned 64-bit domain."""
    if type(value) is not str or not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", value):
        raise ValueError("Invalid hexadecimal address")
    return int(value, 16)


def digest_text(value: object) -> str:
    """Validate a lowercase SHA-256 digest."""
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ValueError("Invalid SHA-256 digest")
    return value


def fields(record: object, names: set[str]) -> None:
    """Require exactly the declared fields on a JSON record."""
    if type(record) is not dict or set(record) != names:
        raise ValueError("Unexpected or missing record fields")


def table(value: object, limit: int) -> dict:
    """Validate a keyed table and its item budget."""
    if type(value) is not dict or len(value) > limit:
        raise ValueError("Invalid or over-budget table")
    return value
