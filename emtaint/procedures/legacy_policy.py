"""Explicit coverage exclusions from original FastSearch, never clean proofs."""

RV130_SHA256='334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787'


def excluded_functions(binary_sha256):
    # dataflow/data_trace.py ignore_function and both scheduling checks. The
    # original addresses are meaningful only for the characterized firmware.
    return frozenset((0x12194,0x1607c)) if binary_sha256==RV130_SHA256 else frozenset()
