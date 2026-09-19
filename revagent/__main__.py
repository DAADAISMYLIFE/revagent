import argparse
import sys
from pathlib import Path

from .agent import Agent
from .llm import LLM, load_secure


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

    if args.cmd == "solve":
        d = Path(args.dir)
        if not d.is_dir():
            print(f"error: {d} is not a directory", file=sys.stderr)
            return 2
        llm = LLM(load_secure(Path(args.secure) if args.secure else None))
        r = Agent(d, _read_desc(d, args.desc), llm, max_steps=args.max_steps, max_minutes=args.max_minutes,
                  interactive=not args.no_ask, show_thinking=args.show_thinking).run()
        return 0 if r["status"] == "solved" else 1

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
    print("\n| challenge | status | flag/reason | steps | min |\n|---|---|---|---|---|")
    for row in rows:
        print("| " + " | ".join(str(x) for x in row) + " |")
    return 0 if all(r[1] == "solved" for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
