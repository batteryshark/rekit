"""pyscylla — Python bindings for libscylla.

Public API entry points::

    import pyscylla as ps

    procs   = ps.process.list_processes()
    region  = ps.iat.search(pid, search_start=0x401000)
    parsed  = ps.iat.parse_live(pid, region.address, region.size)
    parsed.invalidate_suspect()
    ps.dump.process(pid, "out.dmp", image_base=0x400000, entry_point=0x1000)
    ps.iat.fix("out.dmp", "out_fixed.exe", parsed)

For an x64dbg / Ghidra driven flow see :mod:`pyscylla.debugger_bridge`.
"""

from __future__ import annotations

# Version of the Python package itself; the native DLL version is
# queried via ``version()``.
__version__ = "0.1.0"


def version() -> str:
    """Return the underlying libscylla version string."""
    from ._native import get_native

    nat = get_native()
    return nat.ScyllaVersionInformationA().decode("utf-8", errors="replace")


def version_dword() -> int:
    """Return the libscylla version as a packed DWORD (major/minor in high bits)."""
    from ._native import get_native

    return int(get_native().ScyllaVersionInformationDword())


# Public submodule re-exports
from . import (  # noqa: E402
    debugger_bridge,
    dump,
    iat,
    process,
    rebuild,
    reference_scan,
    tree,
)
from .errors import (  # noqa: E402
    DllNotFoundError,
    FileIoError,
    IatNotFoundError,
    IatSearchError,
    IatWriteError,
    InvalidArgumentError,
    OutOfMemoryError,
    ParseError,
    PidNotFoundError,
    ProcessOpenError,
    ScyllaError,
)
from .types import (  # noqa: E402
    Arch,
    IATReference,
    IATRegion,
    ImportModule,
    ImportThunk,
    ProcessInfo,
    RebuildOptions,
    RefType,
    TreeMeta,
)

__all__ = [
    "Arch",
    "DllNotFoundError",
    "FileIoError",
    "IATReference",
    "IATRegion",
    "IatNotFoundError",
    "IatSearchError",
    "IatWriteError",
    "ImportModule",
    "ImportThunk",
    "InvalidArgumentError",
    "OutOfMemoryError",
    "ParseError",
    "PidNotFoundError",
    "ProcessInfo",
    "ProcessOpenError",
    "RebuildOptions",
    "RefType",
    "ScyllaError",
    "TreeMeta",
    "debugger_bridge",
    "dump",
    "iat",
    "process",
    "rebuild",
    "reference_scan",
    "tree",
    "version",
    "version_dword",
]
