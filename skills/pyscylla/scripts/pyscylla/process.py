"""Process enumeration and lookup."""

from __future__ import annotations

import ctypes

from ._native import _ScyllaProcess, get_native
from .errors import raise_for_status
from .types import ProcessInfo


def list_processes() -> list[ProcessInfo]:
    """Enumerate all visible processes on the system.

    Requires SeDebugPrivilege to see protected processes. The caller
    can ``elevate`` before invoking this for full coverage.
    """
    nat = get_native()
    arr_ptr = ctypes.POINTER(_ScyllaProcess)()
    count = ctypes.c_size_t(0)
    rc = nat.ScyllaEnumProcessesW(ctypes.byref(arr_ptr), ctypes.byref(count))
    raise_for_status(rc, "ScyllaEnumProcessesW")
    try:
        items = [ProcessInfo.from_ffi(arr_ptr[i]) for i in range(count.value)]
    finally:
        nat.ScyllaFreeProcessList(arr_ptr)
    return items


def get_by_pid(pid: int) -> ProcessInfo:
    """Look up a single process by PID. Raises ``PidNotFoundError`` if absent."""
    nat = get_native()
    pod = _ScyllaProcess()
    rc = nat.ScyllaFindProcessByPid(int(pid), ctypes.byref(pod))
    raise_for_status(rc, "ScyllaFindProcessByPid")
    return ProcessInfo.from_ffi(pod)


def get_by_name(name: str) -> ProcessInfo:
    """Case-insensitive lookup by filename (e.g. ``"notepad.exe"``)."""
    nat = get_native()
    pod = _ScyllaProcess()
    rc = nat.ScyllaFindProcessByNameW(name, ctypes.byref(pod))
    raise_for_status(rc, "ScyllaFindProcessByNameW")
    return ProcessInfo.from_ffi(pod)
