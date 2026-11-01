"""P1-only file isolation; the Windows null device is not a writable file."""
import os
from legacy_readonly_bootstrap import WriteGuard


class ProbeWriteGuard(WriteGuard):
    def check(self, path, operation):
        if os.name == "nt" and not isinstance(path, int) and operation in ("os.open", "open:w", "open:wb", "open:r+"):
            name = os.fsdecode(path).replace("/", "\\").upper()
            if name in ("NUL", "\\\\.\\NUL", "\\\\?\\NUL"):
                return
        return super(ProbeWriteGuard, self).check(path, operation)
