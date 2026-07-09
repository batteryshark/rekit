"""Rebuild / realign a dumped PE file (strip DOS stub, fix checksum)."""

from __future__ import annotations

from pathlib import Path

from ._native import get_native
from .errors import raise_for_status


def file(
    path: str | Path,
    *,
    remove_dos_stub: bool = False,
    update_pe_header_checksum: bool = True,
    create_backup: bool = False,
) -> None:
    """Realign section sizes/addresses to file alignment, optionally
    stripping the DOS stub and updating the PE header checksum.

    Operates in place; pass ``create_backup=True`` to leave a
    ``.bak`` copy of the original.
    """
    nat = get_native()
    rc = nat.ScyllaRebuildFileW(
        str(path),
        bool(remove_dos_stub),
        bool(update_pe_header_checksum),
        bool(create_backup),
    )
    raise_for_status(rc, "ScyllaRebuildFileW")
