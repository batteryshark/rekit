# Server storage contract

Third-party MCP servers may be grouped beneath `mcp-servers/` for organization:

```text
mcp-servers/[<group>/.../]<id>/
```

Grouping directories are storage-only. Rekit's `mcp` command exports registered
skills as tools; it does not discover, configure, or host these third-party servers.
Any future server registry should therefore use flat server ids plus an optional
forward-slash `path`, matching the skill convention, rather than deriving identity
from the grouping hierarchy.

## Deployment boundary

Rekit owns the packaged server artifacts and their catalog metadata. A consuming
harness or manager owns deployment: selecting servers, putting them into its runtime
layout, satisfying prerequisites, injecting configuration and secrets, choosing the
transport and endpoint, starting and stopping processes, supervising health, and
removing them when no longer needed.

Servers remain inert while stored in Rekit. Rekit must not automatically install,
configure, or launch them merely because they are present under `mcp-servers/`.

Any server manifest consumed by that harness or manager would retain a flat public
identity:

```json
{
  "x64dbg-mcp": {
    "path": "debuggers/x64dbg-mcp"
  }
}
```

`path` would affect filesystem storage only. The registry, configuration surface,
and catalog would continue to identify the server as `x64dbg-mcp`.
