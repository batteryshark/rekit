"""XML tree load/save — Scylla GUI compatible.

Trees produced by these functions load and display correctly in the
upstream Scylla GUI tool, and vice versa.
"""

from __future__ import annotations

import ctypes
from pathlib import Path

from ._native import _ScyllaTreeMeta, get_native
from .errors import raise_for_status
from .iat import IatList
from .types import TreeMeta


def load(path: str | Path) -> tuple[IatList, TreeMeta]:
    """Load an Scylla-format XML tree file.

    Returns ``(IatList, TreeMeta)``. The caller owns the IatList
    lifetime (use ``with`` or ``.close()``).
    """
    nat = get_native()
    handle = ctypes.c_void_p(0)
    meta = _ScyllaTreeMeta()
    rc = nat.ScyllaTreeLoadW(str(path), ctypes.byref(handle), ctypes.byref(meta))
    raise_for_status(rc, "ScyllaTreeLoadW")
    lst = IatList._from_handle(handle.value)
    tm = TreeMeta(
        address_oep=int(meta.addressOEP),
        address_iat=int(meta.addressIAT),
        size_iat=int(meta.sizeIAT),
        image_base=int(meta.imageBase),
        image_size=int(meta.imageSize),
        process_name=meta.processName,
    )
    return lst, tm


def save(
    path: str | Path,
    iat_list: IatList,
    meta: TreeMeta | None = None,
) -> None:
    """Write ``iat_list`` to ``path`` in Scylla XML format."""
    nat = get_native()
    if meta is None:
        meta = TreeMeta()
    pod = _ScyllaTreeMeta(
        addressOEP=int(meta.address_oep),
        addressIAT=int(meta.address_iat),
        sizeIAT=int(meta.size_iat),
        imageBase=int(meta.image_base),
        imageSize=int(meta.image_size),
        processName=meta.process_name,
    )
    rc = nat.ScyllaTreeSaveW(str(path), iat_list._handle, ctypes.byref(pod))
    raise_for_status(rc, "ScyllaTreeSaveW")


__all__ = ["load", "save"]
