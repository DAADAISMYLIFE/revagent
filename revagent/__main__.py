import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .agent import Agent
from .llm import LLM, Secure, load_secure
from .sandbox import (build_sandbox_cmd, check_docker, container_desc_arg, is_interactive_tty,
                      run_sandbox)


def _read_desc(problem_dir: Path, desc_arg: str | None) -> str:
    if desc_arg:
        return Path(desc_arg).read_text(encoding="utf-8")
    default = problem_dir / "desc.txt"
    return default.read_text(encoding="utf-8") if default.is_file() else ""


def _add_limits(p: argparse.ArgumentParser) -> None:
    p.add_argument("--max-steps", type=int, default=300)
    p.add_argument("--max-minutes", type=int, default=120)
    p.add_argument("--secure", help="path to .secure (default: search order in llm.load_secure)")
    p.add_argument("--show-thinking", action="store_true")
    p.add_argument("--sandbox", action="store_true", help="run inside the revagent-sandbox Docker image")
    p.add_argument("--sandbox-dev", action="store_true",
                   help="like --sandbox, but mount this repo at /app so code edits apply without a rebuild")
    p.add_argument("--sandbox-ca",
                   help="trust this CA cert (.crt) at runtime inside the sandbox, for TLS-inspecting "
                        "proxies (default: env REVAGENT_SANDBOX_CA)")


def _sandbox_passthrough(args, desc_in_container: str | None, no_ask: bool) -> list[str]:
    out = ["--max-steps", str(args.max_steps), "--max-minutes", str(args.max_minutes)]
    if no_ask:
        out.append("--no-ask")
    if args.show_thinking:
        out.append("--show-thinking")
    if desc_in_container:
        out += ["--desc", desc_in_container]
    return out


class _Usage(Exception):
    """A preflight failure: main prints `error: <message>` on stderr and exits 2."""


@dataclass
class _Runtime:
    """What a run needs once preflight has passed: an LLM on the host, or the docker inputs in the sandbox."""
    sandbox: bool
    llm: LLM | None = None
    secure: Secure | None = None
    extra_ca: Path | None = None
    dev_repo: Path | None = None


def _preflight(args, sandbox: bool, problem_dir: Path | None = None, desc_arg: str | None = None) -> _Runtime:
    """Checks and loads that happen once per invocation, before any challenge runs. Order matters for
    which error a user sees first: docker, --desc placement, --sandbox-ca file, then .secure."""
    if not sandbox:
        return _Runtime(sandbox=False, llm=LLM(_load_secure(args)))
    msg = check_docker()
    if msg:
        raise _Usage(msg)
    try:
        container_desc_arg(problem_dir, desc_arg)   # validated here; _run_one maps it again per dir
    except ValueError as e:
        raise _Usage(e) from e
    ca_arg = args.sandbox_ca or os.environ.get("REVAGENT_SANDBOX_CA")
    extra_ca = Path(ca_arg) if ca_arg else None
    if extra_ca is not None and not extra_ca.is_file():
        raise _Usage(f"--sandbox-ca file not found: {extra_ca}")
    dev_repo = Path(__file__).resolve().parents[1] if args.sandbox_dev else None
    return _Runtime(sandbox=True, secure=_load_secure(args), extra_ca=extra_ca, dev_repo=dev_repo)


def _load_secure(args) -> Secure:
    try:
        return load_secure(Path(args.secure) if args.secure else None)
    except (FileNotFoundError, ValueError) as e:
        raise _Usage(e) from e


def _run_one(d: Path, args, desc_arg: str | None, no_ask: bool, rt: _Runtime) -> tuple[dict, int]:
    """Run one challenge directory and return (result dict, exit code). On the host the code is
    0 solved / 3 runbook / 1 anything else; in the sandbox it is the container's own exit code."""
    if not rt.sandbox:
        r = Agent(d, _read_desc(d, desc_arg), rt.llm, max_steps=args.max_steps, max_minutes=args.max_minutes,
                  interactive=not no_ask, show_thinking=args.show_thinking).run()
        return r, {"solved": 0, "runbook": 3}.get(r["status"], 1)
    interactive = (not no_ask) and is_interactive_tty()
    cmd = build_sandbox_cmd(d, _sandbox_passthrough(args, container_desc_arg(d, desc_arg), no_ask), rt.secure,
                            interactive, rt.dev_repo, rt.extra_ca)
    env_extra = {"QWEN": rt.secure.key, "URL": rt.secure.url, "MODEL": rt.secure.model}
    p = d / ".revagent" / "result.json"
    before = p.stat().st_mtime_ns if p.exists() else None
    rc = run_sandbox(cmd, env_extra=env_extra)
    if rc != 0 and (not p.exists() or p.stat().st_mtime_ns == before):
        # the container failed before the agent wrote a result: never report a stale result.json as this run
        return {"status": "error", "reason": f"container exited {rc}", "flag": None, "steps": 0, "minutes": 0}, rc
    return _read_result(d), rc


def _read_result(d: Path) -> dict:
    p = d / ".revagent" / "result.json"
    if not p.is_file():
        return {"status": "error", "reason": "no result.json", "flag": None, "steps": 0, "minutes": 0}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return {"status": "error", "reason": f"bad result.json: {e}", "flag": None, "steps": 0, "minutes": 0}


def check_answer(problem_dir: Path, status: str, flag: str | None) -> tuple[str, str | None]:
    """Cross-check a bench result against bench/<suite>/ANSWERS.md, a markdown table
    `| <challenge dir name> | <expected flag> |`. If the row exists and the run was
    reported `solved` with a flag that does not match, downgrade it to `wrong` and
    explain why. Anything else (no ANSWERS.md, no matching row, non-solved status,
    a matching flag) passes through unchanged: (status, None)."""
    answers = problem_dir.parent / "ANSWERS.md"
    if not answers.is_file():
        return status, None
    expected = None
    for line in answers.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) >= 2 and cells[0] == problem_dir.name:
            expected = cells[1]
            break
    if expected is None or status != "solved" or flag == expected:
        return status, None
    return "wrong", f"got {flag}, expected {expected}"


def _mark_wrong_if_answer_mismatch(problem_dir: Path) -> str | None:
    """After a `solve` run: if `<parent>/ANSWERS.md` says the reported flag is wrong, rewrite result.json
    with status "wrong" plus a note, print it, and return "wrong"; otherwise return None. bench already
    does this in its table; without it a `solve` run leaves a wrong flag on disk as "solved"
    (captain-hook run 9)."""
    r = _read_result(problem_dir)
    status, note = check_answer(problem_dir, r.get("status", "error"), r.get("flag"))
    if status != "wrong":
        return None
    r["status"], r["note"] = "wrong", note
    p = problem_dir / ".revagent" / "result.json"
    p.write_text(json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n\033[1mWRONG\033[0m: {note} (see ANSWERS.md); result.json updated")
    return status


def _row(d: Path, r: dict) -> tuple:
    """One bench table row from a result dict, with the ANSWERS.md cross-check applied."""
    status, note = check_answer(d, r.get("status", "error"), r.get("flag"))
    return (d.name, status, note or (r.get("flag") or r.get("runbook") or r.get("reason", "")),
            r.get("steps", 0), r.get("minutes", 0))


def _print_bench_table(rows) -> int:
    print("\n| challenge | status | flag/reason | steps | min |\n|---|---|---|---|---|")
    for row in rows:
        print("| " + " | ".join(str(x) for x in row) + " |")
    return 0 if all(r[1] == "solved" for r in rows) else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="revagent", description="Autonomous reversing agent on Qwen3.8/vLLM")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("solve", help="solve one challenge directory")
    s.add_argument("dir")
    s.add_argument("--desc", help="description file (default <dir>/desc.txt)")
    s.add_argument("--no-ask", action="store_true", help="never block on ask_user")
    _add_limits(s)
    b = sub.add_parser("bench", help="solve several directories non-interactively")
    b.add_argument("dirs", nargs="+")
    _add_limits(b)
    args = ap.parse_args(argv)
    sandbox = args.sandbox or args.sandbox_dev

    if args.sandbox_ca and not sandbox:
        print("error: --sandbox-ca requires --sandbox", file=sys.stderr)
        return 2

    solve = args.cmd == "solve"
    d = Path(args.dir) if solve else None
    if solve and not d.is_dir():
        print(f"error: {d} is not a directory", file=sys.stderr)
        return 2
    try:
        rt = _preflight(args, sandbox, d, getattr(args, "desc", None))
    except _Usage as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if solve:
        r, rc = _run_one(d, args, args.desc, args.no_ask, rt)
        if rc == 0 and _mark_wrong_if_answer_mismatch(d):
            return 1
        return rc

    rows = []
    for d in map(Path, args.dirs):
        try:
            r, _ = _run_one(d, args, None, True, rt)
            rows.append(_row(d, r))
        except Exception as e:
            print(f"error: {d}: {e}", file=sys.stderr)
            rows.append((d.name, "error", str(e)[:80], 0, 0))
    return _print_bench_table(rows)


if __name__ == "__main__":
    sys.exit(main())
