import argparse
import json
import os
import sys
from pathlib import Path

from .agent import Agent
from .llm import LLM, load_secure
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


def _run_in_sandbox(d: Path, args, desc_arg: str | None, no_ask: bool) -> int:
    msg = check_docker()
    if msg:
        print(f"error: {msg}", file=sys.stderr)
        return 2
    try:
        desc_in = container_desc_arg(d, desc_arg)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    ca_arg = args.sandbox_ca or os.environ.get("REVAGENT_SANDBOX_CA") or None
    extra_ca = Path(ca_arg) if ca_arg else None
    if extra_ca is not None and not extra_ca.is_file():
        print(f"error: --sandbox-ca file not found: {extra_ca}", file=sys.stderr)
        return 2
    secure = load_secure(Path(args.secure) if args.secure else None)
    dev_repo = Path(__file__).resolve().parents[1] if args.sandbox_dev else None
    interactive = (not no_ask) and is_interactive_tty()
    cmd = build_sandbox_cmd(d, _sandbox_passthrough(args, desc_in, no_ask), secure, interactive, dev_repo,
                            extra_ca)
    env_extra = {"QWEN": secure.key, "URL": secure.url, "MODEL": secure.model}
    return run_sandbox(cmd, env_extra=env_extra)


def _read_result(d: Path) -> dict:
    p = d / ".revagent" / "result.json"
    if not p.is_file():
        return {"status": "error", "reason": "no result.json", "flag": None, "steps": 0, "minutes": 0}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return {"status": "error", "reason": f"bad result.json: {e}", "flag": None, "steps": 0, "minutes": 0}


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

    if args.cmd == "solve":
        d = Path(args.dir)
        if not d.is_dir():
            print(f"error: {d} is not a directory", file=sys.stderr)
            return 2
        if sandbox:
            return _run_in_sandbox(d, args, args.desc, args.no_ask)
        llm = LLM(load_secure(Path(args.secure) if args.secure else None))
        r = Agent(d, _read_desc(d, args.desc), llm, max_steps=args.max_steps, max_minutes=args.max_minutes,
                  interactive=not args.no_ask, show_thinking=args.show_thinking).run()
        return 0 if r["status"] == "solved" else 1

    if sandbox:
        rows = []
        for d in map(Path, args.dirs):
            try:
                p = d / ".revagent" / "result.json"
                before = p.stat().st_mtime_ns if p.exists() else None
                rc = _run_in_sandbox(d, args, None, no_ask=True)
                if rc != 0 and (not p.exists() or p.stat().st_mtime_ns == before):
                    rows.append((d.name, "error", f"container exited {rc}", 0, 0))
                    continue
                r = _read_result(d)
                rows.append((d.name, r.get("status", "error"), r.get("flag") or r.get("reason", ""),
                              r.get("steps", 0), r.get("minutes", 0)))
            except Exception as e:
                print(f"error: {d}: {e}", file=sys.stderr)
                rows.append((d.name, "error", str(e)[:80], 0, 0))
        return _print_bench_table(rows)

    llm = LLM(load_secure(Path(args.secure) if args.secure else None))
    rows = []
    for d in map(Path, args.dirs):
        try:
            r = Agent(d, _read_desc(d, None), llm, max_steps=args.max_steps, max_minutes=args.max_minutes,
                      interactive=False, show_thinking=args.show_thinking).run()
            rows.append((d.name, r["status"], r.get("flag") or r["reason"], r["steps"], r["minutes"]))
        except Exception as e:
            print(f"error: {d}: {e}", file=sys.stderr)
            rows.append((d.name, "error", str(e)[:80], 0, 0))
    return _print_bench_table(rows)


if __name__ == "__main__":
    sys.exit(main())
