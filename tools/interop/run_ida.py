"""Launch IDA in autonomous mode on an isolated copy of the pinned ELF."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BINARY_PIN = "334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787"


def record(path: Path, data: dict) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def main() -> int:
    """Record both native process exit and IDAPython script receipt."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida-exe", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    exe = args.ida_exe.resolve(strict=True)
    data = binary.read_bytes()
    if sha256(data).hexdigest() != BINARY_PIN:
        parser.error("The ELF does not match the fixed BinaryId")
    if not exe.is_file() or exe.name.lower() not in {"ida.exe", "idat.exe"}:
        parser.error("Expected an installed IDA 9.3 Windows executable")
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="run-", dir=root))
    print(f"ida_run={run}", flush=True)
    copy = run / "httpd"
    with copy.open("xb") as stream:
        stream.write(data)
    user_dir = run / "ida-user"
    user_dir.mkdir()
    wrapper = ROOT / "tools/interop/ida_batch.py"
    exporter = ROOT / "emtaint/plugins/ida93_export_machine_validation.py"
    argv = [str(exe), "-A", f"-L{run / 'ida.log'}", f"-S{wrapper}", str(copy)]
    record(run / "process.json", {"argv": argv, "cwd": str(run), "source_binary": str(binary),
                                  "binary_sha256": BINARY_PIN, "strategy": "fresh isolated ELF copy",
                                  "wrapper_sha256": sha256(wrapper.read_bytes()).hexdigest(),
                                  "exporter_sha256": sha256(exporter.read_bytes()).hexdigest()})
    env = os.environ.copy()
    env.update(BINARYANALYSIS_IDA_RUN=str(run), IDAUSR=str(user_dir), TEMP=str(run), TMP=str(run))
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    exit_code = None
    detail = None
    evidence = None
    try:
        with (run / "ida-stdout.log").open("xb") as stream:
            exit_code = subprocess.run(argv, cwd=run, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                       timeout=args.timeout, startupinfo=startup).returncode
        if exit_code == 0:
            receipt = json.loads((run / "ida-script-receipt.json").read_bytes())
            name = receipt["machine"]
            if receipt["status"] != "exported" or Path(name).name != name or ":" in name:
                raise ValueError("Invalid IDAPython success receipt")
            machine = run / name
            evidence = {"path": str(machine), "sha256": sha256(machine.read_bytes()).hexdigest()}
    except (OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        detail = str(error)
    result = {"exit_code": exit_code, "evidence": evidence, "error": detail}
    record(run / "ida-exit.json", result)
    print(json.dumps(result))
    return 0 if evidence is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
