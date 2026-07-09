"""Dump a live process's memory image to disk."""

from __future__ import annotations

from pathlib import Path

from ._native import get_native
from .errors import raise_for_status


def process(
    pid: int,
    save_path: str | Path,
    *,
    image_base: int,
    entry_point: int,
    file_to_dump: str | Path | None = None,
) -> None:
    """Dump ``pid``'s primary image to ``save_path``.

    If ``file_to_dump`` is supplied, Scylla parses the PE layout from
    that on-disk file but reads section bytes from the live process.
    Otherwise it parses from the process's memory at ``image_base``.

    ``entry_point`` is an absolute VA (not RVA).
    """
    nat = get_native()
    file_to_dump_w = None if file_to_dump is None else str(file_to_dump)
    rc = nat.ScyllaDumpProcessW(
        int(pid),
        file_to_dump_w,
        int(image_base),
        int(entry_point),
        str(save_path),
    )
    raise_for_status(rc, "ScyllaDumpProcessW")


def current_process(
    save_path: str | Path,
    *,
    image_base: int,
    entry_point: int,
    file_to_dump: str | Path | None = None,
) -> None:
    """Same as :func:`process` but for the calling process itself.

    Useful when running inside the target (e.g. an injected agent).
    """
    nat = get_native()
    file_to_dump_w = None if file_to_dump is None else str(file_to_dump)
    rc = nat.ScyllaDumpCurrentProcessW(
        file_to_dump_w,
        int(image_base),
        int(entry_point),
        str(save_path),
    )
    raise_for_status(rc, "ScyllaDumpCurrentProcessW")
