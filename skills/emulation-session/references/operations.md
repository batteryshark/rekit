# Operations

The first two positional arguments are always `session` and `action`:

```bash
rekit run emulation-session <session-dir> <action> [options]
```

## Lifecycle

| Action | Required options | Purpose |
|---|---|---|
| `create` | `--engine`, `--input`; Qiling also needs `--rootfs` | Initialize durable state. |
| `info` | none | Report engine, target, current PC, regions, hooks, snapshots, and trace size. |
| `close` | none | Mark the session closed without deleting evidence. |
| `reopen` | none | Allow operations on a closed session. |

`create` refuses a directory that already contains a session manifest. Relative target
and rootfs paths are resolved at creation time so later calls do not depend on their
working directory.

## Execution and inspection

| Action | Main options |
|---|---|
| `run` | `--address`, `--end`, `--count`, `--timeout` |
| `step` | `--count` |
| `read-memory` | `--address`, `--size` |
| `write-memory` | `--address`, `--data` (hex bytes) |
| `map-memory` | `--address`, `--size`, `--perms` (`rwx`, `rw`, `rx`, or numeric mask) |
| `search-memory` | `--data` (hex bytes) |
| `read-registers` | optional comma-separated `--name` list |
| `write-register` | `--name`, `--value` |
| `set-trace` | `--enabled true|false` |
| `get-trace` | optional `--count` tail length |
| `clear-trace` | none |

Unprefixed integers are decimal; use `0x` for hexadecimal. `--data` is always
hexadecimal and may contain spaces.

## Hooks and snapshots

Use `add-hook` with `--hook-type address|syscall|api`. Address hooks require
`--address`; syscall and API hooks require `--name`. `--stop` turns an address hook
into a breakpoint. Unicorn supports address hooks. Qiling supports all three types.

Use `list-hooks` and `remove-hook --name <hook-id>` to manage hooks.

Use `save-snapshot --label <label>`, `list-snapshots`, and
`restore-snapshot --snapshot <id-or-label>` to branch an investigation. Snapshots live
inside the session directory and are never loaded from another session implicitly.

## Persistence

Unicorn sessions store mapped-region bytes and registers explicitly. Qiling sessions
reconstruct the target and rootfs, then restore Qiling's native machine snapshot. A
portable JSON manifest stores the operation history, hooks, trace, and snapshot index.
Writes use atomic replacement where the platform permits it, and a cross-process lock
serializes calls targeting the same directory.

Qiling snapshot files use framework serialization intended for locally generated
state. Do not deserialize an untrusted session directory.

On macOS ARM64, `scripts/build.sh` compiles the pinned Keystone 0.9.2 core because
its Python package does not include an Apple Silicon dynamic library. That build path
requires `git`, `cmake`, and a C/C++ toolchain. Other platforms use packaged wheels.
