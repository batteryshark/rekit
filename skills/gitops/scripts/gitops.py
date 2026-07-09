#!/usr/bin/env python3
"""gitops — a safe, structured git wrapper for agent harnesses.

Exposes git as a set of plain verbs (status, commit, branch, push, stash,
worktree-add, ...) so a harness that doesn't "know" git can drive a repo without
touching raw git syntax, refspecs, or worktree plumbing. Every op runs git
NON-INTERACTIVELY and prints exactly ONE JSON object to stdout:

    {"ok": true,  "op": "...", ...fields}
    {"ok": false, "op": "...", "error": "...", "hint": "..."}

Data-loss ops (discard, reset-hard, worktree-remove, force push) refuse unless
`--force` is given. Pure stdlib; the only prerequisite is `git` on PATH.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

# Non-interactive: never prompt for creds (fail fast instead of hanging), never
# open a pager or editor.
GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat",
           "GIT_EDITOR": "true", "GIT_OPTIONAL_LOCKS": "0"}


def git(*args: str, cwd: str | None = None) -> tuple[int, str, str]:
    """Run a git command; return (returncode, stdout, stderr) with both trimmed."""
    proc = subprocess.run(["git", *args], cwd=cwd, env=GIT_ENV,
                          capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def emit(obj: dict) -> "NoReturn":  # type: ignore[name-defined]
    print(json.dumps(obj))
    sys.exit(0 if obj.get("ok") else 1)


def ok(op: str, **fields) -> "NoReturn":  # type: ignore[name-defined]
    emit({"ok": True, "op": op, **fields})


def fail(op: str, error: str, **extra) -> "NoReturn":  # type: ignore[name-defined]
    emit({"ok": False, "op": op, "error": error, **extra})


# --- shared helpers ---------------------------------------------------------

def ensure_repo(op: str, cwd: str | None):
    rc, out, _ = git("rev-parse", "--is-inside-work-tree", cwd=cwd)
    if rc != 0 or out != "true":
        fail(op, "not a git repository here",
             hint="run `gitops init` to start one, or pass -C <path-to-repo>")


def current_branch(cwd):
    rc, out, _ = git("rev-parse", "--abbrev-ref", "HEAD", cwd=cwd)
    if rc == 0 and out and out != "HEAD":
        return out
    # unborn branch (fresh repo, no commits yet): read the symbolic ref so a caller
    # still learns it's on e.g. "main" rather than getting a bare null.
    rc, out, _ = git("symbolic-ref", "--short", "HEAD", cwd=cwd)
    return out if rc == 0 and out else None


def upstream(cwd):
    rc, out, _ = git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}", cwd=cwd)
    return out if rc == 0 and out else None


def default_branch(cwd):
    rc, out, _ = git("symbolic-ref", "--short", "refs/remotes/origin/HEAD", cwd=cwd)
    return out.split("/", 1)[-1] if rc == 0 and out else None


def _lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln.strip()]


def _clone_dirname(url: str) -> str:
    """The directory git clone would create from a URL (last path segment, sans .git).
    Handles both https://host/a/b.git and git@host:a/b.git forms."""
    tail = url.rstrip("/").replace(":", "/").rsplit("/", 1)[-1]
    return tail[:-4] if tail.endswith(".git") else tail


# --- ops --------------------------------------------------------------------

def op_status(a):
    ensure_repo("status", a.cwd)
    branch = current_branch(a.cwd)
    up = upstream(a.cwd)
    ahead = behind = 0
    if up:
        rc, out, _ = git("rev-list", "--left-right", "--count", f"{up}...HEAD", cwd=a.cwd)
        if rc == 0 and "\t" in out:
            behind, ahead = (int(x) for x in out.split("\t"))
    staged = _lines(git("diff", "--cached", "--name-only", cwd=a.cwd)[1])
    unstaged = _lines(git("diff", "--name-only", cwd=a.cwd)[1])
    untracked = _lines(git("ls-files", "--others", "--exclude-standard", cwd=a.cwd)[1])
    clean = not (staged or unstaged or untracked)
    ok("status", branch=branch, upstream=up, ahead=ahead, behind=behind,
       clean=clean, defaultBranch=default_branch(a.cwd),
       staged=staged, unstaged=unstaged, untracked=untracked)


def op_log(a):
    ensure_repo("log", a.cwd)
    rc, out, err = git("log", f"-n{a.count}", "--pretty=format:%h%x1f%s%x1f%an%x1f%ar",
                       cwd=a.cwd)
    if rc != 0:
        fail("log", err or "git log failed")
    commits = [dict(zip(("hash", "subject", "author", "when"), ln.split("\x1f")))
               for ln in _lines(out)]
    ok("log", count=len(commits), commits=commits)


def op_diff(a):
    ensure_repo("diff", a.cwd)
    args = ["diff"] + (["--cached"] if a.staged else []) + (["--"] + a.path if a.path else [])
    rc, out, err = git(*args, cwd=a.cwd)
    if rc != 0:
        fail("diff", err or "git diff failed")
    _, stat, _ = git(*(args[:1] + ["--stat"] + args[1:]), cwd=a.cwd)
    ok("diff", staged=a.staged, empty=(out == ""), stat=stat, diff=out)


def op_branches(a):
    ensure_repo("branches", a.cwd)
    rc, out, _ = git("branch", "--format=%(refname:short)", cwd=a.cwd)
    ok("branches", current=current_branch(a.cwd), branches=_lines(out))


def op_add(a):
    ensure_repo("add", a.cwd)
    paths = a.path or ["-A"]
    rc, _, err = git("add", *paths, cwd=a.cwd)
    if rc != 0:
        fail("add", err or "git add failed")
    staged = _lines(git("diff", "--cached", "--name-only", cwd=a.cwd)[1])
    ok("add", staged=staged, count=len(staged))


def op_commit(a):
    ensure_repo("commit", a.cwd)
    # stage first: named paths, else everything (a small model usually means "all").
    rc, _, err = git("add", *(a.path or ["-A"]), cwd=a.cwd)
    if rc != 0:
        fail("commit", f"staging failed: {err}")
    if git("diff", "--cached", "--quiet", cwd=a.cwd)[0] == 0:
        fail("commit", "nothing to commit (no staged changes)",
             hint="edit files first, or check `gitops status`")
    cargs = ["commit", "-m", a.message]
    if a.author:
        cargs += [f"--author={a.author}"]
    rc, out, err = git(*cargs, cwd=a.cwd)
    if rc != 0:
        fail("commit", err or out or "git commit failed")
    _, sha, _ = git("rev-parse", "--short", "HEAD", cwd=a.cwd)
    _, full, _ = git("rev-parse", "HEAD", cwd=a.cwd)
    ok("commit", commit=sha, sha=full, branch=current_branch(a.cwd), summary=out.splitlines()[0] if out else "")


def op_branch(a):
    ensure_repo("branch", a.cwd)
    start = [a.start] if a.start else []
    rc, out, err = git("checkout", "-b", a.name, *start, cwd=a.cwd)
    if rc != 0:
        msg = err or out
        hint = "branch may already exist — use `gitops switch <name>`" if "already exists" in msg else None
        fail("branch", msg or "could not create branch", **({"hint": hint} if hint else {}))
    ok("branch", branch=a.name, created=True, switched=True,
       **({"from": a.start} if a.start else {}))


def op_switch(a):
    ensure_repo("switch", a.cwd)
    rc, out, err = git("checkout", a.name, cwd=a.cwd)
    if rc != 0:
        fail("switch", err or out or "could not switch",
             hint="create it with `gitops branch <name>` if it doesn't exist")
    ok("switch", branch=current_branch(a.cwd))


def op_stash(a):
    ensure_repo("stash", a.cwd)
    args = ["stash", "push"] + (["-u"] if a.include_untracked else [])
    if a.message:
        args += ["-m", a.message]
    rc, out, err = git(*args, cwd=a.cwd)
    if rc != 0:
        fail("stash", err or out or "git stash failed")
    stashed = "No local changes to save" not in out
    ok("stash", stashed=stashed, message=out or None)


def op_stash_pop(a):
    ensure_repo("stash-pop", a.cwd)
    rc, out, err = git("stash", "pop", cwd=a.cwd)
    if rc != 0:
        fail("stash-pop", err or out or "git stash pop failed",
             hint="the pop may have conflicts, or the stash may be empty")
    ok("stash-pop", output=out)


def op_stash_list(a):
    ensure_repo("stash-list", a.cwd)
    rc, out, _ = git("stash", "list", cwd=a.cwd)
    ok("stash-list", stashes=_lines(out), count=len(_lines(out)))


def op_push(a):
    ensure_repo("push", a.cwd)
    branch = current_branch(a.cwd)
    if not branch or branch == "HEAD":
        fail("push", "detached HEAD — checkout a branch first")
    up = upstream(a.cwd)
    args = ["push"]
    set_upstream = up is None
    if set_upstream:
        args += ["-u", a.remote, branch]
    if a.force:
        args += ["--force-with-lease"]  # safer than --force; refuses to clobber others' work
    rc, out, err = git(*args, cwd=a.cwd)
    if rc != 0:
        fail("push", err or out or "git push failed",
             hint="check the remote/credentials; for a diverged branch pass --force")
    ok("push", branch=branch, remote=a.remote, setUpstream=set_upstream,
       forced=a.force, output=(out or err))


def op_pull(a):
    ensure_repo("pull", a.cwd)
    args = ["pull"] + (["--rebase"] if a.rebase else [])
    rc, out, err = git(*args, cwd=a.cwd)
    if rc != 0:
        fail("pull", err or out or "git pull failed",
             hint="resolve conflicts, or `gitops stash` local changes first")
    ok("pull", branch=current_branch(a.cwd), output=out)


def op_fetch(a):
    ensure_repo("fetch", a.cwd)
    rc, out, err = git("fetch", a.remote, cwd=a.cwd)
    if rc != 0:
        fail("fetch", err or "git fetch failed")
    ok("fetch", remote=a.remote, output=(out or err or "up to date"))


def op_clone(a):
    """Clone a remote repo. Runs OUTSIDE a repo — creates one."""
    args = ["clone"]
    if a.branch:
        args += ["-b", a.branch]
    if a.depth:
        args += ["--depth", str(a.depth)]
    args += [a.url] + ([a.path] if a.path else [])
    rc, out, err = git(*args, cwd=a.cwd)
    if rc != 0:
        fail("clone", err or out or "git clone failed",
             hint="check the URL and that you have access (credentials/SSH)")
    rel = a.path or _clone_dirname(a.url)
    ok("clone", url=a.url, path=os.path.abspath(os.path.join(a.cwd or ".", rel)),
       branch=a.branch)


def op_remote_add(a):
    ensure_repo("remote-add", a.cwd)
    rc, existing, _ = git("remote", "get-url", a.name, cwd=a.cwd)
    if rc == 0:  # remote already exists
        if existing == a.url:
            ok("remote-add", name=a.name, url=a.url, note="remote already set to this url")
        fail("remote-add", f"remote '{a.name}' already exists (points at {existing})",
             hint="pass --name for a different remote (or remove the existing one first)")
    rc, out, err = git("remote", "add", a.name, a.url, cwd=a.cwd)
    if rc != 0:
        fail("remote-add", err or out or "git remote add failed")
    ok("remote-add", name=a.name, url=a.url, added=True)


def op_remotes(a):
    ensure_repo("remotes", a.cwd)
    rc, out, _ = git("remote", "-v", cwd=a.cwd)
    remotes = {}
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) >= 2:
            remotes[parts[0]] = parts[1]  # name -> url (fetch and push usually match)
    ok("remotes", remotes=remotes, count=len(remotes))


def op_worktree_add(a):
    ensure_repo("worktree-add", a.cwd)
    if a.new_branch:
        args = ["worktree", "add", "-b", a.new_branch, a.path] + ([a.start] if a.start else [])
        branch = a.new_branch
    elif a.branch:
        args = ["worktree", "add", a.path, a.branch]
        branch = a.branch
    else:
        fail("worktree-add", "specify --branch <existing> or --new-branch <name>")
    rc, out, err = git(*args, cwd=a.cwd)
    if rc != 0:
        fail("worktree-add", err or out or "git worktree add failed")
    ok("worktree-add", path=os.path.abspath(a.path), branch=branch,
       created=bool(a.new_branch))


def op_worktree_list(a):
    ensure_repo("worktree-list", a.cwd)
    rc, out, _ = git("worktree", "list", "--porcelain", cwd=a.cwd)
    trees, cur = [], {}
    for ln in out.splitlines():
        if not ln.strip():
            if cur:
                trees.append(cur); cur = {}
        elif ln.startswith("worktree "):
            cur["path"] = ln[len("worktree "):]
        elif ln.startswith("branch "):
            cur["branch"] = ln[len("branch "):].replace("refs/heads/", "")
        elif ln.startswith("HEAD "):
            cur["head"] = ln[len("HEAD "):]
    if cur:
        trees.append(cur)
    ok("worktree-list", worktrees=trees, count=len(trees))


def op_worktree_remove(a):
    ensure_repo("worktree-remove", a.cwd)
    if not a.force:
        fail("worktree-remove", "refused without --force (removing a worktree is destructive)",
             hint="pass --force once you've confirmed the worktree at that path is disposable")
    rc, out, err = git("worktree", "remove", "--force", a.path, cwd=a.cwd)
    if rc != 0:
        fail("worktree-remove", err or out or "git worktree remove failed")
    ok("worktree-remove", path=a.path, removed=True)


def op_undo(a):
    """Undo the LAST commit but KEEP its changes (soft reset). Safe, no data loss."""
    ensure_repo("undo", a.cwd)
    _, head, _ = git("rev-parse", "--short", "HEAD", cwd=a.cwd)
    rc, out, err = git("reset", "--soft", "HEAD~1", cwd=a.cwd)
    if rc != 0:
        fail("undo", err or out or "nothing to undo",
             hint="there may be only one commit, or none")
    ok("undo", undidCommit=head, note="commit undone; its changes are kept and staged")


def op_discard(a):
    """DESTRUCTIVE: throw away uncommitted changes to tracked files."""
    ensure_repo("discard", a.cwd)
    if not a.force:
        fail("discard", "refused without --force (this permanently drops uncommitted changes)",
             hint="`gitops stash` keeps them; pass --force only to truly discard")
    targets = a.path or ["."]
    rc, out, err = git("checkout", "--", *targets, cwd=a.cwd)
    if rc != 0:
        fail("discard", err or out or "git checkout failed")
    ok("discard", discarded=targets)


def op_reset_hard(a):
    """DESTRUCTIVE: move HEAD and the working tree to <ref>, dropping changes."""
    ensure_repo("reset-hard", a.cwd)
    if not a.force:
        fail("reset-hard", "refused without --force (this drops commits and changes)",
             hint=f"pass --force to hard-reset to {a.ref}")
    rc, out, err = git("reset", "--hard", a.ref, cwd=a.cwd)
    if rc != 0:
        fail("reset-hard", err or out or "git reset failed")
    ok("reset-hard", ref=a.ref, output=out)


def op_init(a):
    args = ["init"] + (["-b", a.initial_branch] if a.initial_branch else []) + [a.path]
    rc, out, err = git(*args)
    if rc != 0:
        fail("init", err or out or "git init failed")
    ok("init", path=os.path.abspath(a.path), output=out)


# --- argument wiring --------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    # -C works BEFORE the op (parsed by the top parser) OR AFTER it (parsed by the
    # per-op parent). SUPPRESS on the parent means an absent after-op -C doesn't clobber
    # a before-op value; the top parser's default=None guarantees args.cwd always exists.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-C", "--cwd", default=argparse.SUPPRESS, metavar="DIR",
                        help="run inside this repo dir (default: current dir)")

    p = argparse.ArgumentParser(prog="gitops", description=__doc__)
    p.add_argument("-C", "--cwd", default=None, metavar="DIR",
                   help="run inside this repo dir (default: current dir)")
    sub = p.add_subparsers(dest="op", required=True)

    def add(name, func, help, parents=(common,)):
        sp = sub.add_parser(name, parents=list(parents), help=help)
        sp.set_defaults(func=func)
        return sp

    add("status", op_status, "branch, upstream ahead/behind, staged/unstaged/untracked")
    lg = add("log", op_log, "recent commits"); lg.add_argument("-n", "--count", type=int, default=15)
    df = add("diff", op_diff, "show a diff (text)")
    df.add_argument("--staged", action="store_true", help="diff the index, not the working tree")
    df.add_argument("path", nargs="*", help="limit to these paths")
    add("branches", op_branches, "list local branches + which is current")

    ad = add("add", op_add, "stage paths (default: everything)")
    ad.add_argument("path", nargs="*", help="paths to stage (default: -A)")

    cm = add("commit", op_commit, "stage + commit (stages all by default)")
    cm.add_argument("message", help="commit message")
    cm.add_argument("--path", nargs="*", help="only stage+commit these paths")
    cm.add_argument("--author", help='override author, e.g. "Name <email>"')

    br = add("branch", op_branch, "create a new branch and switch to it")
    br.add_argument("name", help="new branch name")
    br.add_argument("start", nargs="?", help="start point (default: current HEAD)")
    sw = add("switch", op_switch, "switch to an existing branch")
    sw.add_argument("name", help="branch to switch to")

    st = add("stash", op_stash, "stash uncommitted changes")
    st.add_argument("-m", "--message", help="stash label")
    st.add_argument("-u", "--include-untracked", action="store_true", help="also stash untracked files")
    add("stash-pop", op_stash_pop, "restore the most recent stash")
    add("stash-list", op_stash_list, "list stashes")

    ph = add("push", op_push, "push the current branch (sets upstream on first push)")
    ph.add_argument("--remote", default="origin")
    ph.add_argument("--force", action="store_true", help="allow a non-fast-forward push (uses --force-with-lease)")
    pl = add("pull", op_pull, "pull the current branch")
    pl.add_argument("--rebase", action="store_true")
    fe = add("fetch", op_fetch, "fetch from a remote"); fe.add_argument("--remote", default="origin")

    cl = add("clone", op_clone, "clone a remote repo into a new dir")
    cl.add_argument("url", help="repo URL (https or ssh)")
    cl.add_argument("path", nargs="?", help="target dir (default: repo name from the URL)")
    cl.add_argument("--branch", help="clone this branch instead of the remote's default")
    cl.add_argument("--depth", type=int, help="shallow clone to this many commits")
    ra = add("remote-add", op_remote_add, "add a remote (default name: origin)")
    ra.add_argument("url", help="remote URL")
    ra.add_argument("--name", default="origin", help="remote name (default: origin)")
    add("remotes", op_remotes, "list configured remotes (name -> url)")

    wa = add("worktree-add", op_worktree_add, "add a linked worktree (checkout a branch in another dir)")
    wa.add_argument("path", help="directory for the new worktree")
    wa.add_argument("--branch", help="existing branch to check out there")
    wa.add_argument("--new-branch", help="create this new branch in the worktree")
    wa.add_argument("--start", help="start point for --new-branch (default: HEAD)")
    add("worktree-list", op_worktree_list, "list worktrees")
    wr = add("worktree-remove", op_worktree_remove, "remove a worktree (needs --force)")
    wr.add_argument("path", help="worktree dir to remove")
    wr.add_argument("--force", action="store_true")

    add("undo", op_undo, "undo the last commit but KEEP its changes (safe)")
    dc = add("discard", op_discard, "DESTRUCTIVE: drop uncommitted changes (needs --force)")
    dc.add_argument("path", nargs="*", help="paths to discard (default: all tracked)")
    dc.add_argument("--force", action="store_true")
    rh = add("reset-hard", op_reset_hard, "DESTRUCTIVE: reset HEAD + tree to <ref> (needs --force)")
    rh.add_argument("ref", nargs="?", default="HEAD")
    rh.add_argument("--force", action="store_true")

    it = add("init", op_init, "initialise a new git repo")
    it.add_argument("path", nargs="?", default=".")
    it.add_argument("--initial-branch", default="main")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except SystemExit:
        raise
    except Exception as exc:  # never leak a traceback — emit a JSON error
        fail(getattr(args, "op", "?"), f"unexpected error: {exc}")
    return 0


if __name__ == "__main__":
    main()
