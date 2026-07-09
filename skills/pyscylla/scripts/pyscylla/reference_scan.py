"""IAT reference scanning — finds code references to the IAT.

This is the engine for "tracing bad imports": it walks the target's
code pages, decodes each instruction with diStorm, and reports every
``CALL/JMP/MOV/PUSH/LEA`` that references either an IAT slot (normal
indirect) or an API VA directly (the bad-import case).
"""

from __future__ import annotations

import ctypes
import weakref
from collections.abc import Iterator

from ._native import _ScyllaIatRef, get_native
from .errors import InvalidArgumentError
from .types import IATReference


def scan_live(
    pid: int,
    *,
    image_base: int,
    image_size: int,
    iat_address: int,
    iat_size: int,
    scan_direct: bool = True,
    scan_normal: bool = True,
) -> ReferenceScan:
    """Scan a live process's memory for IAT references."""
    nat = get_native()
    handle = nat.ScyllaRefScanStartLiveW(
        int(pid),
        int(image_base),
        int(image_size),
        int(iat_address),
        int(iat_size),
        int(bool(scan_direct)),
        int(bool(scan_normal)),
    )
    if not handle:
        raise InvalidArgumentError("ScyllaRefScanStartLiveW returned null")
    return ReferenceScan._from_handle(handle)


def scan_bytes(
    image: bytes,
    *,
    iat_address: int,
    iat_size: int,
    scan_direct: bool = True,
    scan_normal: bool = True,
) -> ReferenceScan:
    """Offline scan: ``image`` is a full PE image buffer.

    v0.1 limitation: the upstream Scylla code reads code pages from a
    live process; the bytes-based path returns an empty result set.
    Use :func:`scan_live` for now, or feed bytes via a
    :mod:`pyscylla.debugger_bridge` adapter once the C API exposes a
    buffer-driven scanner.
    """
    nat = get_native()
    buf = ctypes.create_string_buffer(image, len(image))
    handle = nat.ScyllaRefScanStartBytes(
        ctypes.cast(buf, ctypes.c_void_p),
        len(image),
        int(iat_address),
        int(iat_size),
        int(bool(scan_direct)),
        int(bool(scan_normal)),
    )
    if not handle:
        raise InvalidArgumentError("ScyllaRefScanStartBytes returned null")
    return ReferenceScan._from_handle(handle)


class ReferenceScan:
    """Wraps the opaque ``SCYLLA_REF_SCAN`` handle."""

    __slots__ = ("__weakref__", "_finalizer", "_handle")
    _handle: int

    def __init__(self) -> None:
        raise TypeError("Use scan_live() or scan_bytes() to construct a ReferenceScan")

    @classmethod
    def _from_handle(cls, handle: int) -> ReferenceScan:
        obj = cls.__new__(cls)
        obj._handle = handle
        obj._finalizer = weakref.finalize(obj, _close_handle, handle)
        return obj

    def close(self) -> None:
        if self._finalizer.alive:
            self._finalizer()

    @property
    def closed(self) -> bool:
        return not self._finalizer.alive

    def __enter__(self) -> ReferenceScan:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- counts ----

    @property
    def direct_count(self) -> int:
        nat = get_native()
        return int(nat.ScyllaRefScanDirectCount(self._handle))

    @property
    def normal_count(self) -> int:
        nat = get_native()
        return int(nat.ScyllaRefScanNormalCount(self._handle))

    @property
    def direct_unique_count(self) -> int:
        nat = get_native()
        return int(nat.ScyllaRefScanDirectUniqueCount(self._handle))

    @property
    def direct_apis_not_in_iat_count(self) -> int:
        """The "bad imports" count — direct refs whose VA is not in the IAT."""
        nat = get_native()
        return int(nat.ScyllaRefScanDirectApisNotInIatCount(self._handle))

    # ---- enumeration ----

    def get_direct(self, idx: int) -> IATReference:
        nat = get_native()
        pod = _ScyllaIatRef()
        rc = nat.ScyllaRefScanGetDirect(self._handle, idx, ctypes.byref(pod))
        if rc != 0:
            raise InvalidArgumentError(f"index {idx} out of range")
        return IATReference.from_ffi(pod)

    def get_normal(self, idx: int) -> IATReference:
        nat = get_native()
        pod = _ScyllaIatRef()
        rc = nat.ScyllaRefScanGetNormal(self._handle, idx, ctypes.byref(pod))
        if rc != 0:
            raise InvalidArgumentError(f"index {idx} out of range")
        return IATReference.from_ffi(pod)

    def iter_direct(self) -> Iterator[IATReference]:
        for i in range(self.direct_count):
            yield self.get_direct(i)

    def iter_normal(self) -> Iterator[IATReference]:
        for i in range(self.normal_count):
            yield self.get_normal(i)

    # ---- patching ----

    def patch_direct_memory(self, *, junk_byte_after_instruction: bool = False) -> None:
        """Patch direct imports in the live target's memory in place."""
        nat = get_native()
        rc = nat.ScyllaRefScanPatchDirectMemory(
            self._handle, int(bool(junk_byte_after_instruction))
        )
        if rc != 0:
            raise InvalidArgumentError("ScyllaRefScanPatchDirectMemory failed")


def _close_handle(handle: int) -> None:
    try:
        nat = get_native()
        nat.ScyllaRefScanFree(handle)
    except Exception:
        pass


__all__ = ["ReferenceScan", "scan_bytes", "scan_live"]
