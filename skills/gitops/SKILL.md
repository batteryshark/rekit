---
name: gitops
description: "Drive git through plain verbs — clone, status, commit, branch, switch, stash, push, pull, remote-add, merge, cherry-pick, tag, worktree-add/list/remove, undo, discard, reset-hard — for harnesses or smaller models that can't or shouldn't hand-write git commands, refspecs, or worktree plumbing. Every op runs git non-interactively and returns ONE structured JSON result (branch, ahead/behind, staged files, new commit hash, ...), so the caller reasons about repo state without parsing git output. Data-loss ops (discard, reset-hard, worktree-remove, force push) refuse unless an explicit --force is passed. Use when an agent needs to commit/branch/stash/push or set up a worktree but you don't want it improvising raw git. Operates on your own trusted repo; never executes analysed samples."
---

# Git Operations

A safe, structured wrapper over `git` for harnesses (or smaller models) that need to
**use** version control without knowing git's syntax, refspecs, or worktree plumbing.
You call plain verbs; the skill runs git non-interactively and hands back one JSON
object describing what happened.

## When to use

Reach for this when an agent needs to commit, branch, stash, push, or set up a
worktree, but you don't want it improvising raw `git` — e.g. a model that knows it
should "save my work on a new branch" but would fumble `git switch -c`, `git add`,
`git commit`, upstream tracking, or `git worktree add`. It removes whole classes of
footguns: no interactive prompts, no accidental `--force`, structured errors instead
of raw git stderr.

It operates on **your own trusted repo** — it does not analyse or execute samples.

## How it works

`gitops <op> [args]`. Every op prints exactly one line of JSON to stdout:

```json
{"ok": true,  "op": "commit", "commit": "a1b2c3d", "branch": "feature-x", ...}
{"ok": false, "op": "commit", "error": "nothing to commit (no staged changes)", "hint": "..."}
```

So a caller never parses git's human output — it reads `ok`, then the fields it needs.
Add `-C <dir>` to any op to target a repo other than the current directory.

## Operations

| op | what it does |
|---|---|
| `status` | branch, upstream, ahead/behind, and staged / unstaged / untracked file lists |
| `log [-n N]` | recent commits (hash, subject, author, when) |
| `diff [--staged] [paths]` | a diff as text, plus a `--stat` summary |
| `branches` | local branches + which is current |
| `add [paths]` | stage paths (default: everything) |
| `commit "<msg>" [--path ...] [--author ...]` | stage (all by default) then commit; returns the new hash |
| `branch <name> [start]` | create a new branch **and switch to it** |
| `switch <name>` | switch to an existing branch |
| `stash [-m msg] [-u]` | stash uncommitted changes (`-u` includes untracked) |
| `stash-pop` / `stash-list` | restore the latest stash / list stashes |
| `push [--remote origin] [--force]` | push the current branch; sets upstream automatically on first push |
| `pull [--rebase]` / `fetch [--remote]` | sync with the remote |
| `clone <url> [dir] [--branch B] [--depth N]` | clone a remote repo into a new directory |
| `remote-add <url> [--name origin]` | add a remote to the current repo (default name `origin`) |
| `remotes` | list configured remotes (name → url) |
| `merge <branch> [--no-ff] [-m msg]` / `merge --abort` | merge a branch into the current one; conflicts come back as `{conflicts:[...]}` |
| `cherry-pick <commit>` / `cherry-pick --abort` | apply one commit onto the current branch |
| `tag <name> [-m msg] [--ref] [--delete] [--push]` | create (annotated if `-m`), delete, or push a tag |
| `tags` | list tags (newest first) |
| `worktree-add <path> (--branch B \| --new-branch B [--start])` | check a branch out into another directory |
| `worktree-list` / `worktree-remove <path> --force` | list / remove worktrees |
| `undo` | undo the **last commit but keep its changes** (soft reset — safe) |
| `discard [paths] --force` | **destructive**: drop uncommitted changes |
| `reset-hard [ref] --force` | **destructive**: move HEAD + working tree to `ref` |
| `init [path] [--initial-branch main]` | start a new repo |

## Safety rails

- **Data-loss ops refuse without `--force`.** `discard`, `reset-hard`, and
  `worktree-remove` won't run unless you pass `--force`; the refusal JSON explains the
  safer alternative (usually `stash`). A small model can't nuke work by accident.
- **`push --force` uses `--force-with-lease`**, so it won't clobber commits it hasn't seen.
- **Non-interactive.** Credential, editor, and pager prompts are disabled — git fails
  fast with a clear error rather than hanging a headless harness.
- **`commit` stages everything by default** (or just `--path` targets) and returns a
  clean `"nothing to commit"` instead of a cryptic git error when there's nothing to do.

## Examples

```bash
rekit run gitops clone https://github.com/you/repo    # into ./repo
rekit run gitops status
rekit run gitops branch feature-x            # new branch, switched
rekit run gitops commit "add parser"         # stage all + commit
rekit run gitops remote-add git@github.com:you/repo.git   # wire up origin
rekit run gitops push                         # sets upstream on first push
rekit run gitops stash -u                     # shelve everything, incl. untracked
rekit run gitops worktree-add ../wt --new-branch experiment
rekit run gitops discard --force              # throw away uncommitted changes
```

## Prerequisites

`git` on `PATH` (>= 2.5, for `worktree`). Pure-Python stdlib runner; nothing to vendor.
