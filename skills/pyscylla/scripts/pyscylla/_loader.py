"""Discovery and loading of the libscylla native DLL.

Search order (first hit wins):

1. ``PYSCYLLA_DLL`` environment variable — absolute path to a DLL.
2. ``<skill>/bin/libscylla-<arch>.dll`` — private, Git-ignored local copy.
3. ``libscylla-<arch>.dll`` on ``PATH`` — operator-managed install.
4. ``libscylla.dll`` on ``PATH`` — generic fallback.

The module exposes :func:`load_dll`, :func:`is_loaded`, and
:func:`unload_dll`. ``load_dll`` is idempotent; subsequent calls
return the cached handle.
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

# Avoid a circular import at module load time: errors.py doesn't import
# _loader.py, but _loader.py imports errors for the public base class.
from .errors import DllNotFoundError

_ARCH_SUFFIX = "x64" if sys.maxsize > 2**32 else "x86"
_DLL_CANDIDATES = (
    f"libscylla-{_ARCH_SUFFIX}.dll",
    "libscylla.dll",
)


class LoadError(DllNotFoundError):
    """Raised when no libscylla DLL can be located or loaded."""


def _skill_bin_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "bin"


def _candidate_paths() -> list[Path]:
    paths: list[Path] = []

    env = os.environ.get("PYSCYLLA_DLL")
    if env:
        paths.append(Path(env))

    for name in _DLL_CANDIDATES:
        paths.append(_skill_bin_dir() / name)

    for name in _DLL_CANDIDATES:
        # Rely on the operator-managed Windows DLL search path by basename.
        paths.append(Path(name))

    return paths


_dll: ctypes.WinDLL | None = None
_dll_path: Path | None = None


def is_loaded() -> bool:
    return _dll is not None


def loaded_path() -> Path | None:
    return _dll_path


def load_dll(path: str | os.PathLike[str] | None = None) -> ctypes.WinDLL:
    """Load libscylla and return the cached ``WinDLL`` handle.

    If ``path`` is provided it is used directly; otherwise the search
    order above runs. Subsequent calls return the cached handle unless
    ``unload_dll`` was called in between.
    """
    global _dll, _dll_path

    if _dll is not None:
        return _dll

    searched: list[Path] = [Path(path)] if path is not None else _candidate_paths()

    last_err: Exception | None = None
    for candidate in searched:
        try:
            dll = ctypes.WinDLL(str(candidate))
            _dll = dll
            _dll_path = candidate.resolve()
            return dll
        except OSError as exc:
            last_err = exc
            continue

    msg = "libscylla DLL not found. Searched:\n" + "\n".join(f"  - {p}" for p in searched)
    if last_err is not None:
        msg += f"\nLast error: {last_err}"
    raise LoadError(msg)


def unload_dll() -> None:
    """Drop the cached DLL handle. The OS frees the actual module only
    after all references are released (which may not happen until
    interpreter shutdown)."""
    global _dll, _dll_path
    _dll = None
    _dll_path = None
