# Platform requirements & `setup`

rekit distinguishes **its own** requirements from **per-skill** prerequisites:

- **Per-skill prerequisites** — external tools a *skill* needs (node, yara, jadx, …). Live
  in the central `registry.json` (each skill's `prerequisites`), checked by
  `rekit doctor` / `rekit run`.
- **rekit's own requirements** — what rekit needs to *run at all*, to *vendor runtimes*,
  and to be a *nice analysis workstation*. Live in [`../requirements.json`](../requirements.json),
  reported by `rekit doctor` and printed by `rekit setup`.

Base tools are deliberately **not** modeled as a skill (no input/output contract, no
`entry.command`). The manifest reuses the same `check` / `min_version` schema as a skill
prerequisite, so the dispatcher's `check_prereq()` handles both unchanged.

## The three tiers

| tier | tools | what it's for | severity |
|---|---|---|---|
| **base** | python3 ≥ 3.8, bash | rekit cannot run without these (dispatcher = pure stdlib; shim + `build.sh` = bash) | if python3 is missing rekit can't run at all |
| **build** | npm, uv | needed by `rekit install` to vendor skill runtimes. npm → `js-deobfuscate`; uv → the 4 binary analyzers + `pyc-decompile` + `emulate-code` + `qiling-emulate` | advisory — missing just means those skills can't be *built* |
| **recommended** | rg, git, curl, jq, file | agent/workstation niceties; no skill strictly requires them | advisory |

`base`/`build`/`recommended` are **advisory** in `rekit doctor` — they never change the
exit code (the exit code still reflects per-skill readiness, as before).

## Platform support

| platform | status |
|---|---|
| **macOS** (arm64 / x64) | primary |
| **Linux** (x64 / arm64, glibc or musl) | primary |
| **Windows** | via **WSL2** only. Most dynamic skills need Unix tracers (`strace`/`dtruss`, `tcpdump`, `frida-trace`) anyway. Native-Windows-only targets are a non-goal. `rekit setup --platform windows` prints a "run inside WSL2" banner and emits the linux (apt) commands. |

`native-lift` is the one container-backed catalog entry. It supports Docker's
`linux/amd64` and `linux/arm64` platforms, including Docker Desktop on Intel and Apple
Silicon macOS. Docker is a per-skill prerequisite, not a Rekit base requirement.
`rekit install native-lift` explicitly pulls its immutable image; subsequent analysis
runs require the image to be present and run with networking disabled. An unavailable
Docker daemon, unsupported host platform, absent digest, missing image, or failed image
health check leaves only that skill unavailable.

Within Linux the install commands default to **apt** (Debian/Ubuntu). On Fedora/RHEL use
`dnf`, on Arch use `pacman` — same package names in most cases. `uv`'s installer
(`curl -LsSf https://astral.sh/uv/install.sh | sh`) is distro-agnostic.

## Why `setup` prints instead of installing

`rekit setup` **never runs a package manager.** It prints the platform-appropriate install
commands for whatever's missing, so it's both copy-pasteable and pipeable:

```bash
rekit setup                    # missing BASE tools (default tier)
rekit setup --tier all         # base + build + recommended
rekit setup --platform linux   # override auto-detection
rekit setup --tier all | bash  # you opt in to actually running them
```

Why not auto-install: package managers need `sudo`, differ wildly across OSes/distros, and
can clobber a system. rekit is tooling for **hostile inputs**, where *surprise* is exactly
what to avoid. Printing a vetted command for the human to run (or pipe, deliberately) is the
honest, non-surprising move — and it's trivially scriptable when someone does want it.

## Adding / changing a requirement

Edit [`../requirements.json`](../requirements.json). Each entry is:

```json
{
  "tool": "uv",
  "min_version": null,
  "check": ["uv", "--version"],
  "why": "vendoring pure-python deps via `uv pip --target`",
  "builds": ["elf-analyze", "pe-analyze"],
  "install": {
    "macos": "brew install uv",
    "linux": "curl -LsSf https://astral.sh/uv/install.sh | sh",
    "windows": "# inside WSL2: curl -LsSf https://astral.sh/uv/install.sh | sh"
  }
}
```

`min_version` is optional (omit / null = presence-only). `check` is run verbatim; the first
`\d+(\.\d+)*` in its combined stdout+stderr is parsed as the version. Re-run
`rekit doctor` to confirm detection.
