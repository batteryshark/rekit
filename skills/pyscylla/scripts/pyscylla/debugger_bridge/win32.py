"""Win32 adapter — calls ``OpenProcess`` + ``ReadProcessMemory`` directly.

This is Scylla's native data path: no debugger required, just
sufficient privilege to read the target process's memory.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

from . import DebuggerFeed, ModuleInfo

_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ = 0x0010

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.OpenProcess.restype = wintypes.HANDLE
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
_k32.ReadProcessMemory.restype = wintypes.BOOL


class Win32Feed(DebuggerFeed):
    """Read memory and module info from a live process via Win32."""

    def __init__(self, pid: int) -> None:
        self._pid = int(pid)
        self._handle = _k32.OpenProcess(
            _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ, False, self._pid
        )
        if not self._handle:
            raise OSError(f"OpenProcess(pid={pid}) failed: GLE={ctypes.get_last_error()}")

    def __del__(self) -> None:
        try:
            if getattr(self, "_handle", 0):
                _k32.CloseHandle(self._handle)
        except Exception:
            pass

    def read_memory(self, address: int, size: int) -> bytes:
        buf = (ctypes.c_ubyte * size)()
        read = ctypes.c_size_t(0)
        ok = _k32.ReadProcessMemory(
            self._handle, ctypes.c_void_p(address), buf, size, ctypes.byref(read)
        )
        if not ok:
            raise OSError(
                f"ReadProcessMemory({address:#x}, {size}) failed: "
                f"GLE={ctypes.get_last_error()}"
            )
        return bytes(buf[: read.value])

    def modules(self) -> list[ModuleInfo]:
        # Use EnumProcessModulesEx for full fidelity
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.EnumProcessModulesEx.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
        ]
        psapi.EnumProcessModulesEx.restype = wintypes.BOOL
        psapi.GetModuleFileNameExW.argtypes = [
            wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD,
        ]
        psapi.GetModuleFileNameExW.restype = wintypes.DWORD
        psapi.GetModuleInformation.argtypes = [
            wintypes.HANDLE, wintypes.HMODULE,
            ctypes.c_void_p, wintypes.DWORD,
        ]
        psapi.GetModuleInformation.restype = wintypes.BOOL

        class _MODULEINFO(ctypes.Structure):
            _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", wintypes.DWORD),
                        ("EntryPoint", ctypes.c_void_p)]

        LIST_MODULES_ALL = 0x03
        needed = wintypes.DWORD(0)
        psapi.EnumProcessModulesEx(
            self._handle, None, 0, ctypes.byref(needed), LIST_MODULES_ALL
        )
        count = needed.value // ctypes.sizeof(wintypes.HMODULE)
        hmods = (wintypes.HMODULE * count)()
        psapi.EnumProcessModulesEx(
            self._handle, hmods, needed.value, ctypes.byref(needed), LIST_MODULES_ALL
        )

        out: list[ModuleInfo] = []
        name_buf = ctypes.create_unicode_buffer(260)
        info = _MODULEINFO()
        for i in range(count):
            n = psapi.GetModuleFileNameExW(self._handle, hmods[i], name_buf, 260)
            if not n:
                continue
            path = name_buf.value
            if not psapi.GetModuleInformation(
                self._handle, hmods[i], ctypes.byref(info), ctypes.sizeof(info)
            ):
                continue
            out.append(ModuleInfo(
                base=int(info.lpBaseOfDll or 0),
                size=int(info.SizeOfImage),
                name=path.rsplit("\\", 1)[-1],
                path=path,
            ))
        return out

    def image_base(self) -> int:
        mods = self.modules()
        if not mods:
            raise OSError("no modules visible in target")
        return mods[0].base

    def image_size(self) -> int:
        mods = self.modules()
        if not mods:
            raise OSError("no modules visible in target")
        return mods[0].size
