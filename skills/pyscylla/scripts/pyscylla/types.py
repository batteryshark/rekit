"""Public data types for pyscylla.

All types are immutable ``dataclass(frozen=True, slots=True)`` so they
can be safely shared across threads and used as dict keys. They mirror
the POD structs in ``ScyllaCApi.h``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

MAX_PATH = 260


class Arch(IntEnum):
    """Process architecture as reported by ``ProcessInfo.arch``."""

    UNKNOWN = 0
    X86 = 32
    X64 = 64


class RefType(IntEnum):
    """Kind of code reference to the IAT. Mirrors ``ScyllaRefType``."""

    PTR_JMP = 0
    PTR_CALL = 1
    DIRECT_JMP = 2
    DIRECT_CALL = 3
    DIRECT_MOV = 4
    DIRECT_PUSH = 5
    DIRECT_LEA = 6


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """A row from ``ScyllaEnumProcessesW``."""

    pid: int
    session_id: int
    image_base: int
    peb_address: int
    entry_point_rva: int
    image_size: int
    filename: str
    full_path: str
    arch: Arch = Arch.UNKNOWN

    @classmethod
    def from_ffi(cls, p: object) -> ProcessInfo:
        return cls(
            pid=int(p.PID),
            session_id=int(p.sessionId),
            image_base=int(p.imageBase),
            peb_address=int(p.pebAddress),
            entry_point_rva=int(p.entryPointRva),
            image_size=int(p.imageSize),
            filename=p.filename,
            full_path=p.fullPath,
            arch=Arch(int(p.arch)),
        )


@dataclass(frozen=True, slots=True)
class ImportThunk:
    """One entry in the IAT — an API in a module."""

    module_name: str
    name: str
    va: int
    rva: int
    ordinal: int
    hint: int
    iat_address_va: int
    valid: bool
    suspect: bool


@dataclass(frozen=True, slots=True)
class ImportModule:
    """A DLL row in the parsed IAT — owns a list of ``ImportThunk``."""

    module_name: str
    first_thunk: int
    thunks: tuple[ImportThunk, ...] = field(default_factory=tuple)

    @property
    def valid_count(self) -> int:
        return sum(1 for t in self.thunks if t.valid)

    @property
    def invalid_count(self) -> int:
        return sum(1 for t in self.thunks if not t.valid)

    @property
    def suspect_count(self) -> int:
        return sum(1 for t in self.thunks if t.suspect)


@dataclass(frozen=True, slots=True)
class IATRegion:
    """Result of an IAT search: where the IAT lives in the target process."""

    address: int
    size: int


@dataclass(frozen=True, slots=True)
class IATReference:
    """A single code reference to the IAT (or directly to an API VA)."""

    address_va: int
    target_pointer: int
    target_address_in_iat: int
    instruction_size: int
    type: RefType

    @classmethod
    def from_ffi(cls, r: object) -> IATReference:
        return cls(
            address_va=int(r.addressVA),
            target_pointer=int(r.targetPointer),
            target_address_in_iat=int(r.targetAddressInIat),
            instruction_size=int(r.instructionSize),
            type=RefType(int(r.type)),
        )


@dataclass(frozen=True, slots=True)
class TreeMeta:
    """Metadata captured alongside an XML tree export."""

    address_oep: int = 0
    address_iat: int = 0
    size_iat: int = 0
    image_base: int = 0
    image_size: int = 0
    process_name: str = ""


@dataclass(slots=True)
class RebuildOptions:
    """Options bag for ``pyscylla.iat.fix``.

    Mirrors ``ScyllaRebuildOptions``. Mutable so callers can do
    ``opts.use_oft = True`` after construction.
    """

    use_oft: bool = True
    new_iat_in_section: bool = False
    new_iat_address: int = 0
    new_iat_size: int = 0
    build_direct_imports_jump_table: bool = False
    remove_dos_stub: bool = False
    update_pe_header_checksum: bool = True
    create_backup: bool = False


__all__ = [
    "Arch",
    "IATReference",
    "IATRegion",
    "ImportModule",
    "ImportThunk",
    "ProcessInfo",
    "RebuildOptions",
    "RefType",
    "TreeMeta",
]
