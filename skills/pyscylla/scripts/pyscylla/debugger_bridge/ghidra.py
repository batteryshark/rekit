"""Ghidra MCP adapter.

Wraps calls to Ghidra MCP tools supplied by the host. Use this for
static analysis flows where you have an imported Ghidra project but
no live process.
"""

from __future__ import annotations

from . import DebuggerFeed, ModuleInfo


class GhidraMcpFeed(DebuggerFeed):
    """Read memory and module info from a Ghidra project via MCP.

    Like :class:`X64DbgMcpFeed`, this does not own the bridge; the
    caller must bind the MCP tool callables via :meth:`bind_tools`.
    """

    def __init__(self) -> None:
        self._tools: dict[str, object] = {}

    def bind_tools(self, **tools: object) -> None:
        """Inject Ghidra MCP tool callables by name.

        Required tools: ``read_memory``, ``list_segments`` (or
        ``get_metadata``). ``image_base`` and ``image_size`` are
        inferred from the first executable segment.
        """
        self._tools.update(tools)

    def _tool(self, name: str) -> object:
        if name not in self._tools:
            raise RuntimeError(
                f"Ghidra MCP tool {name!r} not bound. "
                f"Call feed.bind_tools({name}=...) first."
            )
        return self._tools[name]

    def read_memory(self, address: int, size: int) -> bytes:
        read = self._tool("read_memory")
        result = read(address=hex(address), length=size)
        if isinstance(result, dict) and "bytes" in result:
            data = result["bytes"]
            if isinstance(data, str):
                return bytes.fromhex(data)
            return bytes(data)
        if isinstance(result, (bytes, bytearray)):
            return bytes(result)
        raise RuntimeError(f"unexpected read_memory return: {result!r}")

    def modules(self) -> list[ModuleInfo]:
        try:
            listing = self._tool("list_segments")
        except RuntimeError:
            return []
        segs = listing()
        out: list[ModuleInfo] = []
        rows = segs if isinstance(segs, list) else segs.get("segments", [])
        for row in rows:
            out.append(ModuleInfo(
                base=int(row.get("base", row.get("address", 0)), 0)
                      if isinstance(row.get("base", row.get("address", 0)), str)
                      else int(row.get("base", row.get("address", 0))),
                size=int(row.get("size", 0)),
                name=row.get("name", ""),
                path="",
            ))
        return out

    def image_base(self) -> int:
        meta = self._tool("get_metadata") if "get_metadata" in self._tools else None
        if meta:
            r = meta()
            if isinstance(r, dict) and "image_base" in r:
                val = r["image_base"]
                return int(val, 16) if isinstance(val, str) else int(val)
        mods = self.modules()
        return mods[0].base if mods else 0

    def image_size(self) -> int:
        mods = self.modules()
        return mods[0].size if mods else 0
