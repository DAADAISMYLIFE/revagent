"""trace_run and emulate as bash commands. The model lives in bash (75-95% of its calls in failed runs) and
rarely picks a dedicated tool, so the same code is reachable from there. Run from the challenge directory:

    revagent-trace BINARY [--stdin TEXT | --stdin-file PATH] [--range START..END] [--top N] [-- ARG ...]
    revagent-emulate BINARY FUNCTION [ARG ...] [--out-lens N,N] [--max-insns N]

Both print exactly what the tool prints, write the same `[obs]` ledger line to .revagent/case.md and
count themselves in .revagent/cli_calls.json (read into result.json signals)."""
import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

from .casefile import CaseFile
from .tools.base import ToolContext

CALLS_FILE = "cli_calls.json"


def _ctx() -> ToolContext:
    problem = Path.cwd().resolve()
    work = problem / ".revagent"
    case = work / "case.md"
    if not case.exists():                               # outside a run: keep the ledger line out of the tree
        case = Path(tempfile.mkdtemp()) / "case.md"
    ctx = ToolContext(problem_dir=problem, work_dir=work, casefile=CaseFile(case, problem.name, ""),
                      llm=None, interactive=False)
    ctx.step = -1                                       # a bash-side call; not the harness's start probe
    out = work / "out"
    ids = [int(m.group(1)) for f in out.glob("trace-*.txt") if (m := re.match(r"trace-(\d+)\.txt$", f.name))] \
        if out.is_dir() else []
    ctx.out_counter = max(ids, default=0) + 100         # never overwrite the agent's own trace-N files
    return ctx


def _count(ctx: ToolContext, name: str) -> None:
    try:
        p = ctx.work_dir / CALLS_FILE
        d = json.loads(p.read_text()) if p.exists() else {}
        d[name] = d.get(name, 0) + 1
        ctx.work_dir.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(d))
    except Exception:
        pass


def main_trace(argv: list[str] | None = None) -> int:
    from .tools import trace_run
    argv = list(sys.argv[1:] if argv is None else argv)
    extra = []
    if "--" in argv:
        i = argv.index("--")
        argv, extra = argv[:i], argv[i + 1:]
    ap = argparse.ArgumentParser(prog="revagent-trace", description="trace_run from bash")
    ap.add_argument("binary")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--stdin", default="")
    g.add_argument("--stdin-file")
    ap.add_argument("--range")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--timeout", type=int, default=60)
    a = ap.parse_args(argv)
    stdin = Path(a.stdin_file).read_text(errors="surrogateescape") if a.stdin_file else a.stdin
    ctx = _ctx()
    print(trace_run.run(ctx, a.binary, stdin=stdin, args=extra or None, range=a.range, top=a.top, timeout=a.timeout))
    _count(ctx, "revagent-trace")
    return 0


def main_emulate(argv: list[str] | None = None) -> int:
    from .tools import emulate
    ap = argparse.ArgumentParser(prog="revagent-emulate", description="emulate from bash")
    ap.add_argument("binary")
    ap.add_argument("function")
    ap.add_argument("args", nargs="*", help="hex:<bytes> | int:<n> | addr:0x<address>")
    ap.add_argument("--out-lens", default="")
    ap.add_argument("--max-insns", type=int, default=emulate.MAX_INSNS)
    a = ap.parse_args(sys.argv[1:] if argv is None else argv)
    out_lens = [int(x, 0) for x in a.out_lens.split(",") if x.strip()] or None
    ctx = _ctx()
    print(emulate.run(ctx, a.binary, a.function, a.args, out_lens=out_lens, max_insns=a.max_insns))
    _count(ctx, "revagent-emulate")
    return 0
