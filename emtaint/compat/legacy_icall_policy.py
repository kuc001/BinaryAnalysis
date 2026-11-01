"""Explicit firmware-specific bound from the old Collector, not a proof.

Reference: EmTaint/dataflow/data_collector.py::parse_icall_targets_v1, which
appends 0xa590c for sites 0x2120c and 0x2115c. Kept only for fidelity runs on
the identified rv130 image. No expected target address/list is encoded here.
"""
RV130_SHA256='334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787'

def legacy_maximum_address(binary_sha256,site):
    return 0xa590c if binary_sha256==RV130_SHA256 and site in (0x2120c,0x2115c) else None
