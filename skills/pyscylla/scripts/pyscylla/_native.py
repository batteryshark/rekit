"""ctypes signatures for every export in ScyllaCApi.h.

One signature per export, configured lazily on first access via
:func:`get_native`. The public Python modules call into ``get_native()``
rather than touching ctypes directly so the binding logic stays here.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

from ._loader import load_dll

# ----- POD struct definitions ------------------------------------------------

MAX_PATH = 260


class _ScyllaProcess(ctypes.Structure):
    _fields_ = [
        ("PID", wintypes.DWORD),
        ("sessionId", wintypes.DWORD),
        ("imageBase", ctypes.c_size_t),
        ("pebAddress", ctypes.c_size_t),
        ("entryPointRva", wintypes.DWORD),
        ("imageSize", wintypes.DWORD),
        ("filename", ctypes.c_wchar * MAX_PATH),
        ("fullPath", ctypes.c_wchar * MAX_PATH),
        ("arch", ctypes.c_int),
    ]


class _ScyllaModule(ctypes.Structure):
    _fields_ = [
        ("moduleName", ctypes.c_wchar * MAX_PATH),
        ("firstThunk", ctypes.c_size_t),
        ("thunkCount", ctypes.c_size_t),
    ]


class _ScyllaThunk(ctypes.Structure):
    _fields_ = [
        ("moduleName", ctypes.c_wchar * MAX_PATH),
        ("name", ctypes.c_char * MAX_PATH),
        ("va", ctypes.c_size_t),
        ("rva", ctypes.c_size_t),
        ("ordinal", wintypes.WORD),
        ("hint", wintypes.WORD),
        ("iatAddressVA", ctypes.c_size_t),
        ("valid", ctypes.c_int),
        ("suspect", ctypes.c_int),
    ]


class _ScyllaIatRef(ctypes.Structure):
    _fields_ = [
        ("addressVA", ctypes.c_size_t),
        ("targetPointer", ctypes.c_size_t),
        ("targetAddressInIat", ctypes.c_size_t),
        ("instructionSize", ctypes.c_ubyte),
        ("type", ctypes.c_int),
    ]


class _ScyllaTreeMeta(ctypes.Structure):
    _fields_ = [
        ("addressOEP", ctypes.c_size_t),
        ("addressIAT", ctypes.c_size_t),
        ("sizeIAT", wintypes.DWORD),
        ("imageBase", ctypes.c_size_t),
        ("imageSize", wintypes.DWORD),
        ("processName", ctypes.c_wchar * MAX_PATH),
    ]


class _ScyllaRebuildOptions(ctypes.Structure):
    _fields_ = [
        ("useOFT", ctypes.c_int),
        ("newIatInSection", ctypes.c_int),
        ("newIatAddress", ctypes.c_size_t),
        ("newIatSize", wintypes.DWORD),
        ("buildDirectImportsJumpTable", ctypes.c_int),
        ("removeDosStub", ctypes.c_int),
        ("updatePeHeaderChecksum", ctypes.c_int),
        ("createBackup", ctypes.c_int),
    ]


# Opaque handle types
SCYLLA_IAT_LIST = ctypes.c_void_p
SCYLLA_REF_SCAN = ctypes.c_void_p

PP_ScyllaProcess = ctypes.POINTER(_ScyllaProcess)


class _Native:
    """Holds the bound ctypes function signatures. Built once per DLL load."""

    __slots__ = (
        "ScyllaDumpCurrentProcessW",
        "ScyllaDumpProcessW",
        "ScyllaEnumProcessesW",
        "ScyllaFindProcessByNameW",
        "ScyllaFindProcessByPid",
        "ScyllaFreeProcessList",
        "ScyllaIatFixAutoW",
        "ScyllaIatListAddModule",
        "ScyllaIatListAddThunk",
        "ScyllaIatListCreate",
        "ScyllaIatListFree",
        "ScyllaIatListGetModule",
        "ScyllaIatListGetThunk",
        "ScyllaIatListInvalidThunkCount",
        "ScyllaIatListInvalidateSuspect",
        "ScyllaIatListInvalidateThunk",
        "ScyllaIatListModuleCount",
        "ScyllaIatListRemoveThunk",
        "ScyllaIatListSetThunk",
        "ScyllaIatListSuspectThunkCount",
        "ScyllaIatListThunkCount",
        "ScyllaIatListTotalThunkCount",
        "ScyllaIatParseBytesW",
        "ScyllaIatParseLiveW",
        "ScyllaIatSearchLiveW",
        "ScyllaRebuildFileW",
        "ScyllaRebuildIatExW",
        "ScyllaRefScanDirectApisNotInIatCount",
        "ScyllaRefScanDirectCount",
        "ScyllaRefScanDirectUniqueCount",
        "ScyllaRefScanFree",
        "ScyllaRefScanGetDirect",
        "ScyllaRefScanGetNormal",
        "ScyllaRefScanNormalCount",
        "ScyllaRefScanPatchDirectMemory",
        "ScyllaRefScanStartBytes",
        "ScyllaRefScanStartLiveW",
        "ScyllaTreeLoadW",
        "ScyllaTreeSaveW",
        "ScyllaVersionInformationA",
        "ScyllaVersionInformationDword",
        "dll",
    )

    def __init__(self, dll: ctypes.WinDLL) -> None:
        self.dll = dll
        # Helper to bind signature
        def b(name: str, restype, argtypes):
            fn = getattr(dll, name)
            fn.restype = restype
            fn.argtypes = argtypes
            setattr(self, name, fn)

        # version
        b("ScyllaVersionInformationA", ctypes.c_char_p, [])
        b("ScyllaVersionInformationDword", wintypes.DWORD, [])

        # process enumeration
        b("ScyllaEnumProcessesW", ctypes.c_int,
          [ctypes.POINTER(PP_ScyllaProcess), ctypes.POINTER(ctypes.c_size_t)])
        b("ScyllaFreeProcessList", None, [PP_ScyllaProcess])
        b("ScyllaFindProcessByPid", ctypes.c_int,
          [wintypes.DWORD, ctypes.POINTER(_ScyllaProcess)])
        b("ScyllaFindProcessByNameW", ctypes.c_int,
          [wintypes.LPCWSTR, ctypes.POINTER(_ScyllaProcess)])

        # dump
        b("ScyllaDumpProcessW", ctypes.c_int,
          [ctypes.c_size_t, wintypes.LPCWSTR, ctypes.c_size_t,
           ctypes.c_size_t, wintypes.LPCWSTR])
        b("ScyllaDumpCurrentProcessW", ctypes.c_int,
          [wintypes.LPCWSTR, ctypes.c_size_t, ctypes.c_size_t, wintypes.LPCWSTR])

        # rebuild
        b("ScyllaRebuildFileW", ctypes.c_int,
          [wintypes.LPCWSTR, wintypes.BOOL, wintypes.BOOL, wintypes.BOOL])

        # iat search
        b("ScyllaIatSearchLiveW", ctypes.c_int,
          [wintypes.DWORD,
           ctypes.POINTER(ctypes.c_size_t),
           ctypes.POINTER(wintypes.DWORD),
           ctypes.c_size_t, wintypes.BOOL])

        # iat parse / lifecycle
        b("ScyllaIatParseLiveW", SCYLLA_IAT_LIST,
          [wintypes.DWORD, ctypes.c_size_t, wintypes.DWORD])
        b("ScyllaIatParseBytesW", SCYLLA_IAT_LIST,
          [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, wintypes.DWORD])
        b("ScyllaIatListCreate", SCYLLA_IAT_LIST, [])
        b("ScyllaIatListFree", None, [SCYLLA_IAT_LIST])
        b("ScyllaIatListModuleCount", ctypes.c_size_t, [SCYLLA_IAT_LIST])
        b("ScyllaIatListGetModule", ctypes.c_int,
          [SCYLLA_IAT_LIST, ctypes.c_size_t, ctypes.POINTER(_ScyllaModule)])
        b("ScyllaIatListThunkCount", ctypes.c_size_t,
          [SCYLLA_IAT_LIST, ctypes.c_size_t])
        b("ScyllaIatListGetThunk", ctypes.c_int,
          [SCYLLA_IAT_LIST, ctypes.c_size_t, ctypes.c_size_t,
           ctypes.POINTER(_ScyllaThunk)])
        b("ScyllaIatListTotalThunkCount", ctypes.c_size_t, [SCYLLA_IAT_LIST])
        b("ScyllaIatListInvalidThunkCount", ctypes.c_size_t, [SCYLLA_IAT_LIST])
        b("ScyllaIatListSuspectThunkCount", ctypes.c_size_t, [SCYLLA_IAT_LIST])

        # iat edits
        b("ScyllaIatListInvalidateThunk", ctypes.c_int,
          [SCYLLA_IAT_LIST, ctypes.c_size_t, ctypes.c_size_t])
        b("ScyllaIatListInvalidateSuspect", ctypes.c_int, [SCYLLA_IAT_LIST])
        b("ScyllaIatListSetThunk", ctypes.c_int,
          [SCYLLA_IAT_LIST, ctypes.c_size_t, ctypes.c_size_t,
           ctypes.POINTER(_ScyllaThunk)])
        b("ScyllaIatListAddModule", ctypes.c_int,
          [SCYLLA_IAT_LIST, wintypes.LPCWSTR, ctypes.c_size_t,
           ctypes.POINTER(ctypes.c_size_t)])
        b("ScyllaIatListAddThunk", ctypes.c_int,
          [SCYLLA_IAT_LIST, ctypes.c_size_t, ctypes.POINTER(_ScyllaThunk),
           ctypes.POINTER(ctypes.c_size_t)])
        b("ScyllaIatListRemoveThunk", ctypes.c_int,
          [SCYLLA_IAT_LIST, ctypes.c_size_t, ctypes.c_size_t])

        # xml tree
        b("ScyllaTreeLoadW", ctypes.c_int,
          [wintypes.LPCWSTR,
           ctypes.POINTER(SCYLLA_IAT_LIST),
           ctypes.POINTER(_ScyllaTreeMeta)])
        b("ScyllaTreeSaveW", ctypes.c_int,
          [wintypes.LPCWSTR, SCYLLA_IAT_LIST,
           ctypes.POINTER(_ScyllaTreeMeta)])

        # rebuild
        b("ScyllaRebuildIatExW", ctypes.c_int,
          [wintypes.LPCWSTR, wintypes.LPCWSTR,
           SCYLLA_IAT_LIST, ctypes.POINTER(_ScyllaRebuildOptions)])
        b("ScyllaIatFixAutoW", ctypes.c_int,
          [ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD,
           wintypes.LPCWSTR, wintypes.LPCWSTR])

        # reference scan
        b("ScyllaRefScanStartLiveW", SCYLLA_REF_SCAN,
          [wintypes.DWORD, ctypes.c_size_t, wintypes.DWORD,
           ctypes.c_size_t, wintypes.DWORD, ctypes.c_int, ctypes.c_int])
        b("ScyllaRefScanStartBytes", SCYLLA_REF_SCAN,
          [ctypes.c_void_p, ctypes.c_size_t,
           ctypes.c_size_t, wintypes.DWORD, ctypes.c_int, ctypes.c_int])
        b("ScyllaRefScanFree", None, [SCYLLA_REF_SCAN])
        b("ScyllaRefScanDirectCount", ctypes.c_size_t, [SCYLLA_REF_SCAN])
        b("ScyllaRefScanNormalCount", ctypes.c_size_t, [SCYLLA_REF_SCAN])
        b("ScyllaRefScanDirectUniqueCount", ctypes.c_size_t, [SCYLLA_REF_SCAN])
        b("ScyllaRefScanDirectApisNotInIatCount", ctypes.c_size_t, [SCYLLA_REF_SCAN])
        b("ScyllaRefScanGetDirect", ctypes.c_int,
          [SCYLLA_REF_SCAN, ctypes.c_size_t, ctypes.POINTER(_ScyllaIatRef)])
        b("ScyllaRefScanGetNormal", ctypes.c_int,
          [SCYLLA_REF_SCAN, ctypes.c_size_t, ctypes.POINTER(_ScyllaIatRef)])
        b("ScyllaRefScanPatchDirectMemory", ctypes.c_int,
          [SCYLLA_REF_SCAN, ctypes.c_int])


_native: _Native | None = None


def get_native() -> _Native:
    """Return the singleton ``_Native`` instance, loading the DLL if needed."""
    global _native
    if _native is None:
        dll = load_dll()
        _native = _Native(dll)
    return _native


def is_native_loaded() -> bool:
    return _native is not None
