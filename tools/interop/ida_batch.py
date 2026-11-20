"""IDA-only batch entry point for the existing machine evidence exporter."""
import json
import os
from pathlib import Path
import runpy
import sys
import traceback

import ida_pro


def main() -> int:
    """Write the script receipt separately from IDA's process exit status."""
    run = Path(os.environ["BINARYANALYSIS_IDA_RUN"])
    try:
        source = Path(__file__).resolve().parents[2] / "emtaint/plugins/ida93_export_machine_validation.py"
        export = runpy.run_path(str(source))["export_machine_validation"]
        export.__globals__["OUTPUT_DIR"] = run
        machine = export()
        receipt = {"status": "exported", "machine": machine.name,
                   "idapython_version": sys.version.split()[0]}
        code = 0
    except Exception:
        receipt = {"status": "failed", "traceback": traceback.format_exc()}
        code = 1
    with (run / "ida-script-receipt.json").open("x", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2)
    return code


if __name__ == "__main__":
    ida_pro.qexit(main())
