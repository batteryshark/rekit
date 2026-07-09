"""Debugger-agnostic feed for pyscylla's offline analysis.

The :class:`DebuggerFeed` protocol lets ``pyscylla`` consume memory
snapshots from any source — direct Win32 ``OpenProcess`` reads, the
x64dbg MCP, the Ghidra MCP, or a recorded dump file. The analysis
(IAT parsing, reference scanning) is debugger-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class ModuleInfo:
    """A loaded module in the debuggee's address space."""

    base: int
    size: int
    name: str
    path: str


@runtime_checkable
class DebuggerFeed(Protocol):
    """Minimal contract every debugger adapter must satisfy."""

    def read_memory(self, address: int, size: int) -> bytes:
        """Read ``size`` bytes from ``address``. Raises on failure."""
        ...

    def modules(self) -> list[ModuleInfo]:
        """List loaded modules in the debuggee."""
        ...

    def image_base(self) -> int:
        """Convenience: base address of the debuggee's primary image."""
        ...

    def image_size(self) -> int:
        """Convenience: size of the debuggee's primary image."""
        ...


from .ghidra import GhidraMcpFeed  # noqa: E402
from .win32 import Win32Feed  # noqa: E402  (re-export)
from .x64dbg import X64DbgMcpFeed  # noqa: E402

__all__ = ["DebuggerFeed", "GhidraMcpFeed", "ModuleInfo", "Win32Feed", "X64DbgMcpFeed"]
