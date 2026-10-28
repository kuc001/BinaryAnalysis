"""Read-only full inventory; reuse scandir metadata and hash independent files concurrently."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import stat


def full_inventory(root, workers=8):
    root = Path(root)
    pending = [root]
    jobs = []

    def record(path, info):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return {"path": path.relative_to(root).as_posix(), "size": info.st_size,
                "mtime_ns": info.st_mtime_ns, "sha256": digest.hexdigest()}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        while pending:
            base = pending.pop()
            with os.scandir(base) as scan:
                entries = sorted(scan, key=lambda entry: entry.name)
            directories = []
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 1024:
                    raise RuntimeError("Reparse point is prohibited: " + entry.path)
                if stat.S_ISDIR(info.st_mode):
                    directories.append(Path(entry.path))
                elif stat.S_ISREG(info.st_mode):
                    jobs.append(pool.submit(record, Path(entry.path), info))
                else:
                    raise RuntimeError("Unsupported file kind: " + entry.path)
            pending.extend(reversed(directories))
        return [job.result() for job in jobs]
