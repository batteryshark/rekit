"""IAT search, parse, edit, and rebuild.

The ``IatList`` class wraps the opaque ``SCYLLA_IAT_LIST`` handle.
It owns native memory and frees it on ``close()`` / GC. Use it as a
context manager:

    with ps.iat.parse_live(pid, region.address, region.size) as lst:
        lst.invalidate_suspect()
        ps.iat.fix("dump.dmp", "fixed.exe", lst)
"""

from __future__ import annotations

import ctypes
import weakref
from collections.abc import Iterator
from pathlib import Path

from ._native import (
    _ScyllaModule,
    _ScyllaRebuildOptions,
    _ScyllaThunk,
    get_native,
)
from .errors import InvalidArgumentError, raise_for_status
from .types import IATRegion, ImportModule, ImportThunk, RebuildOptions


def search(
    pid: int,
    *,
    search_start: int,
    advanced: bool = False,
) -> IATRegion:
    """Search a live process for the IAT.

    ``search_start`` is typically the image base or the OEP. Returns
    the located region on success; raises ``IatNotFoundError`` if
    nothing matched.
    """
    nat = get_native()
    start = ctypes.c_size_t(0)
    size = ctypes.c_uint32(0)
    rc = nat.ScyllaIatSearchLiveW(
        int(pid),
        ctypes.byref(start),
        ctypes.byref(size),
        int(search_start),
        bool(advanced),
    )
    raise_for_status(rc, "ScyllaIatSearchLiveW")
    return IATRegion(address=start.value, size=size.value)


def parse_live(pid: int, iat_address: int, iat_size: int) -> IatList:
    """Parse the IAT of a live process, resolving VAs to API names."""
    nat = get_native()
    handle = nat.ScyllaIatParseLiveW(int(pid), int(iat_address), int(iat_size))
    if not handle:
        raise InvalidArgumentError("ScyllaIatParseLiveW returned null (openProcess failed?)")
    return IatList._from_handle(handle)


def parse_bytes(image: bytes, iat_address: int, iat_size: int) -> IatList:
    """Parse the IAT from a buffer. Best-effort API resolution uses
    the *current* process's loaded modules; for full cross-build
    resolution use :func:`parse_live`.
    """
    nat = get_native()
    buf = ctypes.create_string_buffer(image, len(image))
    handle = nat.ScyllaIatParseBytesW(
        ctypes.cast(buf, ctypes.c_void_p),
        len(image),
        int(iat_address),
        int(iat_size),
    )
    if not handle:
        raise InvalidArgumentError("ScyllaIatParseBytesW returned null")
    return IatList._from_handle(handle)


def fix(
    dump_file: str | Path,
    out_file: str | Path,
    iat_list: IatList,
    options: RebuildOptions | None = None,
) -> None:
    """Rebuild the import table of ``dump_file`` using ``iat_list``'s
    thunks, writing the result to ``out_file``.

    ``options`` defaults to GUI-equivalent settings (OFT support on,
    no new IAT section, no direct-import jump table).
    """
    nat = get_native()
    opts = options if options is not None else RebuildOptions()
    pod = _options_to_pod(opts)
    rc = nat.ScyllaRebuildIatExW(
        str(dump_file),
        str(out_file),
        iat_list._handle,
        ctypes.byref(pod),
    )
    raise_for_status(rc, "ScyllaRebuildIatExW")


def fix_auto(
    pid: int,
    *,
    iat_address: int,
    iat_size: int,
    dump_file: str | Path,
    out_file: str | Path,
) -> None:
    """One-shot convenience: parse the live IAT then rebuild.

    Equivalent to ``parse_live`` + ``fix`` with default options.
    """
    nat = get_native()
    rc = nat.ScyllaIatFixAutoW(
        int(iat_address),
        int(iat_size),
        int(pid),
        str(dump_file),
        str(out_file),
    )
    raise_for_status(rc, "ScyllaIatFixAutoW")


def _options_to_pod(opts: RebuildOptions) -> _ScyllaRebuildOptions:
    return _ScyllaRebuildOptions(
        useOFT=int(opts.use_oft),
        newIatInSection=int(opts.new_iat_in_section),
        newIatAddress=int(opts.new_iat_address),
        newIatSize=int(opts.new_iat_size),
        buildDirectImportsJumpTable=int(opts.build_direct_imports_jump_table),
        removeDosStub=int(opts.remove_dos_stub),
        updatePeHeaderChecksum=int(opts.update_pe_header_checksum),
        createBackup=int(opts.create_backup),
    )


def _thunk_from_pod(p: _ScyllaThunk) -> ImportThunk:
    return ImportThunk(
        module_name=p.moduleName,
        name=p.name.decode("utf-8", errors="replace"),
        va=int(p.va),
        rva=int(p.rva),
        ordinal=int(p.ordinal),
        hint=int(p.hint),
        iat_address_va=int(p.iatAddressVA),
        valid=bool(p.valid),
        suspect=bool(p.suspect),
    )


def _thunk_to_pod(t: ImportThunk) -> _ScyllaThunk:
    return _ScyllaThunk(
        moduleName=t.module_name,
        name=t.name.encode("utf-8"),
        va=t.va,
        rva=t.rva,
        ordinal=t.ordinal,
        hint=t.hint,
        iatAddressVA=t.iat_address_va,
        valid=int(t.valid),
        suspect=int(t.suspect),
    )


class IatList:
    """Wraps the opaque ``SCYLLA_IAT_LIST`` handle.

    Use ``close()`` to release native memory eagerly; otherwise it is
    freed on garbage collection via ``__del__``.
    """

    __slots__ = ("__weakref__", "_finalizer", "_handle")
    _handle: int

    def __init__(self) -> None:
        nat = get_native()
        h = nat.ScyllaIatListCreate()
        if not h:
            raise InvalidArgumentError("ScyllaIatListCreate returned null")
        self._handle = h
        # weakref.finalize invokes _close_handle exactly once: either when
        # close() calls self._finalizer() or when the object is GC'd.
        # Calling it twice (manually + via GC) is what weakref.finalize
        # prevents via its `alive` flag.
        self._finalizer = weakref.finalize(self, _close_handle, h)

    @classmethod
    def _from_handle(cls, handle: int) -> IatList:
        obj = cls.__new__(cls)
        obj._handle = handle
        obj._finalizer = weakref.finalize(obj, _close_handle, handle)
        return obj

    def close(self) -> None:
        """Release the native handle. Safe to call multiple times."""
        # Invoking the finalizer runs _close_handle and marks it dead so
        # GC won't fire it again — no double-free.
        if self._finalizer.alive:
            self._finalizer()

    @property
    def closed(self) -> bool:
        return not self._finalizer.alive

    def __enter__(self) -> IatList:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- inspection ----

    @property
    def module_count(self) -> int:
        nat = get_native()
        return int(nat.ScyllaIatListModuleCount(self._handle))

    @property
    def total_thunk_count(self) -> int:
        nat = get_native()
        return int(nat.ScyllaIatListTotalThunkCount(self._handle))

    @property
    def invalid_thunk_count(self) -> int:
        nat = get_native()
        return int(nat.ScyllaIatListInvalidThunkCount(self._handle))

    @property
    def suspect_thunk_count(self) -> int:
        nat = get_native()
        return int(nat.ScyllaIatListSuspectThunkCount(self._handle))

    def thunk_count(self, module_idx: int) -> int:
        nat = get_native()
        return int(nat.ScyllaIatListThunkCount(self._handle, module_idx))

    def get_module(self, module_idx: int) -> ImportModule:
        nat = get_native()
        pod = _ScyllaModule()
        rc = nat.ScyllaIatListGetModule(self._handle, module_idx, ctypes.byref(pod))
        raise_for_status(rc, "ScyllaIatListGetModule")
        thunks = tuple(self.get_thunk(module_idx, i) for i in range(pod.thunkCount))
        return ImportModule(
            module_name=pod.moduleName,
            first_thunk=int(pod.firstThunk),
            thunks=thunks,
        )

    def get_thunk(self, module_idx: int, thunk_idx: int) -> ImportThunk:
        nat = get_native()
        pod = _ScyllaThunk()
        rc = nat.ScyllaIatListGetThunk(
            self._handle, module_idx, thunk_idx, ctypes.byref(pod)
        )
        raise_for_status(rc, "ScyllaIatListGetThunk")
        return _thunk_from_pod(pod)

    def modules(self) -> Iterator[ImportModule]:
        for i in range(self.module_count):
            yield self.get_module(i)

    # ---- edits ----

    def invalidate_thunk(self, module_idx: int, thunk_idx: int) -> None:
        nat = get_native()
        rc = nat.ScyllaIatListInvalidateThunk(self._handle, module_idx, thunk_idx)
        raise_for_status(rc, "ScyllaIatListInvalidateThunk")

    def invalidate_suspect(self) -> int:
        """Invalidate every thunk flagged as suspect. Returns count affected."""
        before = self.invalid_thunk_count
        nat = get_native()
        rc = nat.ScyllaIatListInvalidateSuspect(self._handle)
        raise_for_status(rc, "ScyllaIatListInvalidateSuspect")
        return self.invalid_thunk_count - before

    def set_thunk(self, module_idx: int, thunk_idx: int, thunk: ImportThunk) -> None:
        nat = get_native()
        pod = _thunk_to_pod(thunk)
        rc = nat.ScyllaIatListSetThunk(
            self._handle, module_idx, thunk_idx, ctypes.byref(pod)
        )
        raise_for_status(rc, "ScyllaIatListSetThunk")

    def add_module(self, module_name: str, first_thunk: int) -> int:
        """Add a new module. Returns its index."""
        nat = get_native()
        out = ctypes.c_size_t(0)
        rc = nat.ScyllaIatListAddModule(
            self._handle, module_name, int(first_thunk), ctypes.byref(out)
        )
        raise_for_status(rc, "ScyllaIatListAddModule")
        return int(out.value)

    def add_thunk(self, module_idx: int, thunk: ImportThunk) -> int:
        """Add a thunk to an existing module. Returns the new thunk index."""
        nat = get_native()
        pod = _thunk_to_pod(thunk)
        out = ctypes.c_size_t(0)
        rc = nat.ScyllaIatListAddThunk(
            self._handle, module_idx, ctypes.byref(pod), ctypes.byref(out)
        )
        raise_for_status(rc, "ScyllaIatListAddThunk")
        return int(out.value)

    def remove_thunk(self, module_idx: int, thunk_idx: int) -> None:
        nat = get_native()
        rc = nat.ScyllaIatListRemoveThunk(self._handle, module_idx, thunk_idx)
        raise_for_status(rc, "ScyllaIatListRemoveThunk")


def _close_handle(handle: int) -> None:
    """Module-level finalizer — safe to call after the IatList is gone."""
    try:
        nat = get_native()
        nat.ScyllaIatListFree(handle)
    except Exception:
        # DLL may already be unloaded at interpreter shutdown
        pass


# Public helpers exported via __init__.py
__all__ = [
    "IatList",
    "fix",
    "fix_auto",
    "parse_bytes",
    "parse_live",
    "search",
]
