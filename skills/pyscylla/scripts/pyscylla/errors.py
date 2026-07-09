"""Exception hierarchy for pyscylla.

Maps the ``ScyllaStatus`` codes from ``ScyllaCApi.h`` to Python
exceptions so callers can ``except`` on the failure mode that
matters rather than inspecting integer return codes.
"""

from __future__ import annotations


class ScyllaError(Exception):
    """Base class for all pyscylla errors."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ProcessOpenError(ScyllaError):
    """Failed to OpenProcess the target."""


class IatWriteError(ScyllaError):
    """ImportRebuilder failed to write the fixed file."""


class IatSearchError(ScyllaError):
    """IAT search itself errored (distinct from IatNotFoundError)."""


class IatNotFoundError(ScyllaError):
    """IAT search ran but found nothing at the given start address."""


class PidNotFoundError(ScyllaError):
    """PID was not present in the process snapshot."""


class InvalidArgumentError(ScyllaError):
    """Bad pointer / out-of-range index passed to the C API."""


class FileIoError(ScyllaError):
    """File open / read / write failed."""


class ParseError(ScyllaError):
    """XML tree or PE parse failure."""


class OutOfMemoryError(ScyllaError):
    """The C runtime ran out of memory."""


class DllNotFoundError(ScyllaError):
    """libscylla DLL could not be located by the loader."""


class NotLoadedError(ScyllaError):
    """API called before the DLL was successfully loaded."""


# Status code -> exception class. Mirrors ScyllaStatus in ScyllaCApi.h.
_STATUS_MAP: dict[int, type[ScyllaError]] = {
    -1: ProcessOpenError,
    -2: IatWriteError,
    -3: IatSearchError,
    -4: IatNotFoundError,
    -5: PidNotFoundError,
    -6: InvalidArgumentError,
    -7: FileIoError,
    -8: ParseError,
    -9: OutOfMemoryError,
}


def status_to_exception(status: int, context: str = "") -> ScyllaError:
    """Translate a ``ScyllaStatus`` integer to the matching exception instance.

    Unknown codes fall back to generic ``ScyllaError``.
    """
    cls = _STATUS_MAP.get(status, ScyllaError)
    msg = f"Scylla status {status}"
    if context:
        msg += f" ({context})"
    return cls(msg, status=status)


def raise_for_status(status: int, context: str = "") -> None:
    """Raise the matching exception unless ``status`` is SCY_E_SUCCESS (0)."""
    if status != 0:
        raise status_to_exception(status, context)
