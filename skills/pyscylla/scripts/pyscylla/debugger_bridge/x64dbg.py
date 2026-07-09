"""x64dbg MCP adapter.

Wraps calls to the x64dbg MCP tools that ship with this workspace
(``x64dbgMCP/``). The MCP server must be reachable; pyscylla does
not manage the x64dbg lifecycle.
"""

from __future__ import annotations

from . import DebuggerFeed, ModuleInfo


class X64DbgMcpFeed(DebuggerFeed):
    """Drive x64dbg via the MCP tools registered in this environment.

    The MCP tool functions are imported lazily so this module is safe
    to ``import`` even when x64dbg isn't connected. The first
    ``read_memory`` / ``modules`` call will fail with a clear error
    if the bridge is unavailable.
    """

    def __init__(self) -> None:
        self._tools: dict[str, object] = {}

    def _tool(self, name: str) -> object:
        """Look up an MCP tool by name, caching the result.

        We rely on the host environment (Claude Desktop / opencode)
        binding the MCP tools to the global namespace — the caller
        passes them in explicitly via :meth:`bind_tools` if not.
        """
        if name in self._tools:
            return self._tools[name]
        raise RuntimeError(
            f"x64dbg MCP tool {name!r} not bound. Call "
            f"feed.bind_tools(...) with the MCP tool functions first."
        )

    def bind_tools(self, **tools: object) -> None:
        """Inject MCP tool callables by name.

        Example::

            feed = X64DbgMcpFeed()
            feed.bind_tools(
                MemoryRead=x64dbg_MemoryRead,
                GetModuleList=x64dbg_GetModuleList,
            )
        """
        self._tools.update(tools)

    def read_memory(self, address: int, size: int) -> bytes:
        read = self._tool("MemoryRead")
        result = read(addr=hex(address), size=str(size))
        # The MCP returns a hex string; decode it.
        if isinstance(result, dict) and "hex" in result:
            return bytes.fromhex(result["hex"])
        if isinstance(result, str):
            return bytes.fromhex(result)
        raise RuntimeError(f"unexpected MemoryRead return: {result!r}")

    def modules(self) -> list[ModuleInfo]:
        listing = self._tool("GetModuleList")
        result = listing()
        out: list[ModuleInfo] = []
        rows = result if isinstance(result, list) else result.get("modules", [])
        for row in rows:
            out.append(ModuleInfo(
                base=int(row.get("base", row.get("Base", 0)), 16)
                      if isinstance(row.get("base", row.get("Base", 0)), str)
                      else int(row.get("base", row.get("Base", 0))),
                size=int(row.get("size", row.get("Size", 0)), 16)
                     if isinstance(row.get("size", row.get("Size", 0)), str)
                     else int(row.get("size", row.get("Size", 0))),
                name=row.get("name", row.get("Name", "")),
                path=row.get("path", row.get("Path", "")),
            ))
        return out

    def image_base(self) -> int:
        mods = self.modules()
        # The first module listed by x64dbg is typically the debuggee EXE.
        return mods[0].base if mods else 0

    def image_size(self) -> int:
        mods = self.modules()
        return mods[0].size if mods else 0
