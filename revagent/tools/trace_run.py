"""trace_run: one execution of the binary under qemu-user with `-d exec,nochain,page`, aggregated into
regions, hotspots and the folded sequence of executed block addresses (Ghidra addresses for the image).
The observation the model lacked for interpreters, VMs and self-modifying code: what ran, in what order,
how many times — without reading every handler."""
import os
import re
from pathlib import Path
import tempfile
import shutil
import signal
import struct
import subprocess
import time

from ..trace import (TraceError, analyze, compress, from_ghidra, full_listing, is_ghidra_image_addr, locate_image,
                     ops_lines, parse_elf_header, parse_ops_log, parse_qemu_log, render, suggest_next,
)
from .base import PathError, resolve_inside
from .bash import MAX_TIMEOUT, scrubbed_env

DEFAULT_TIMEOUT = 60
MAX_LOG_BYTES = 200 * 1024 * 1024
EMPTY_STDIN_NOTE = ("[note] stdin was empty: the program read no input, so this trace shows only the input-independent "
                    "path (an early failure, not the check). Run again with stdin of the length the program reads "
                    "before concluding anything about the check")
POLL_SECONDS = 0.5
OUTPUT_CHARS = 400
OPS_HEAD, OPS_TAIL = 40, 30  # ops lines in the tool output; the whole listing is in trace-N.ops.txt. The tail
                             # matters: a run that failed decided at its end
OPS_FLAGS = "in_asm,exec,nochain,page,cpu"
OPS_HEADER = "ops (the real run"
QEMU_NAMES = ("qemu-x86_64-static", "qemu-x86_64")
ELF_HEADER_BYTES = 0x10000     # header + program headers comfortably
ELF64_PHENTSIZE = 56

SCHEMA = {
    "type": "function",
    "function": {
        "name": "trace_run",
        "description": (
            "Run the binary ONCE under qemu-user with an execution trace and return (1) the mapped regions with "
            "how many translation blocks executed in each ([image], [anon rwx]/[anon] = mmap'd after start, "
            "[lib?] = present at start), (2) the hottest addresses with counts, (3) the SEQUENCE of executed "
            "block addresses with consecutive repeats folded as (a b c)×n. Use it for an interpreter, VM, "
            "dispatch loop or self-modifying code: the sequence IS the listing of the interpreted program; "
            "map each distinct handler address to its operation once, then read the listing. Addresses inside "
            "the image are Ghidra's (PIE at 0x100000, same as decompile); addresses outside (an mmap'd region, "
            "a library) are the raw guest addresses. First call without range to see which region the loop runs "
            "in (libraries are then left out of the sequence), then call again with range=start..end over that "
            "region to get the handler sequence alone. Granularity is one translation block (a straight-line "
            "run of instructions up to the next branch), so single instructions inside a block are not listed. "
            "The full folded sequence is saved under .revagent/out/ and the raw qemu log in a local temp dir (both paths "
            "in the output) "
            "and can be grepped or diffed with bash; run twice with different stdin and diff the two .txt files "
            "to see input-dependent branches. x86-64 ELF only; a PE or a script returns [cannot trace] "
            "(use run_binary/run_gui for those). The log is capped at 200 MB ([trace truncated])."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "binary": {"type": "string", "description": "path relative to the challenge directory"},
                "stdin": {"type": "string", "description": "text fed to stdin (default empty)"},
                "args": {"type": "array", "items": {"type": "string"}, "description": "argv (default [])"},
                "range": {"type": "string",
                          "description": "only addresses in [start, end): '0x101000..0x102000' (Ghidra addresses "
                                         "for the image, raw guest addresses outside it, as printed in a previous "
                                         "trace_run output)"},
                "top": {"type": "integer", "description": "hottest addresses to list (default 40)"},
                "timeout": {"type": "integer", "description": "seconds (default 60, max 900)"},
            },
            "required": ["binary"],
        },
    },
}

_RANGE = re.compile(r"^\s*(0x[0-9a-fA-F]+|\d+)\s*(?:\.\.|-)\s*(0x[0-9a-fA-F]+|\d+)\s*$")


def parse_range(text: str) -> tuple[int, int]:
    m = _RANGE.match(str(text))
    if not m:
        raise ValueError(f"range must look like 0x101000..0x102000 (got {text!r})")
    lo, hi = int(m.group(1), 0), int(m.group(2), 0)
    if hi <= lo:
        raise ValueError(f"range end must be above its start (got {text!r})")
    return lo, hi


def find_qemu() -> str | None:
    for name in QEMU_NAMES:
        p = shutil.which(name)
        if p:
            return p
    return None


def _cut(text: str, limit: int = OUTPUT_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + f"...[{len(text) - limit} more chars]"


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def run_qemu(cmd: list[str], cwd, stdin_text: str, log_path, timeout: int) -> dict:
    """Run qemu with the log at log_path; stop it when the log passes MAX_LOG_BYTES or the timeout
    passes. Returns {returncode, stdout, stderr, truncated, timed_out}."""
    proc = subprocess.Popen(cmd, cwd=str(cwd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True, env=scrubbed_env())
    deadline = time.monotonic() + timeout
    truncated = timed_out = False
    payload: bytes | None = stdin_text.encode()
    while True:
        try:
            out, err = proc.communicate(input=payload, timeout=POLL_SECONDS)
            break
        except subprocess.TimeoutExpired:
            payload = None
            try:
                size = log_path.stat().st_size
            except OSError:
                size = 0
            if size > MAX_LOG_BYTES:
                truncated = True
            elif time.monotonic() >= deadline:
                timed_out = True
            else:
                continue
            _kill(proc)
            out, err = proc.communicate()
            break
    return {"returncode": proc.returncode, "stdout": (out or b"").decode("utf-8", "replace"),
            "stderr": (err or b"").decode("utf-8", "replace"), "truncated": truncated, "timed_out": timed_out}


def _read_elf_head(p) -> bytes:
    """The bytes parse_elf_header needs: the first ELF_HEADER_BYTES, extended to the end of the program
    header table when e_phoff + e_phnum * 56 lies past them (never past the end of the file)."""
    with p.open("rb") as f:
        head = f.read(ELF_HEADER_BYTES)
        if head[:4] == b"\x7fELF" and len(head) >= 64 and head[4] == 2:
            e_phoff = struct.unpack_from("<Q", head, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from("<HH", head, 54)
            need = e_phoff + e_phnum * max(e_phentsize, ELF64_PHENTSIZE)
            need = min(need, os.fstat(f.fileno()).st_size)
            if need > len(head):
                head += f.read(need - len(head))
    return head


def _rel(ctx, path) -> str:
    try:
        return str(path.relative_to(ctx.problem_dir))
    except ValueError:
        return str(path)


def run(ctx, binary: str, stdin: str = "", args: list[str] | None = None, range: str | None = None,
        top: int = 40, timeout: int = DEFAULT_TIMEOUT) -> str:
    try:
        return _run(ctx, binary, stdin, args, range, top, timeout)
    except Exception as e:   # nothing escapes into the agent loop
        return f"[tool error] trace_run failed: {type(e).__name__}: {e}"


def _run(ctx, binary: str, stdin: str, args: list[str] | None, range_text: str | None, top: int, timeout: int) -> str:
    try:
        p = resolve_inside(ctx, binary)
    except PathError as e:
        return str(e)
    if args is None:
        args = []
    if not isinstance(args, (list, tuple)) or not all(isinstance(a, str) for a in args):
        return "[tool error] args must be a list of strings"
    stdin = "" if stdin is None else str(stdin)
    range_ = None
    if range_text not in (None, ""):
        try:
            range_ = parse_range(range_text)
        except ValueError as e:
            return f"[tool error] {e}"
    try:
        top = int(top)
    except (TypeError, ValueError):
        return "[tool error] top must be a positive integer"
    if top <= 0:
        return "[tool error] top must be a positive integer"
    try:
        timeout = int(timeout)
    except (TypeError, ValueError):
        return "[tool error] timeout must be an integer number of seconds"
    timeout = ctx.clamp_timeout(max(1, min(timeout, MAX_TIMEOUT)))

    head = _read_elf_head(p)
    try:
        elf = parse_elf_header(head)
    except TraceError as e:
        ctx.observe(f"trace_run {binary}: [cannot trace] {e}")
        return f"[cannot trace] {e}"
    qemu = find_qemu()
    if qemu is None:
        return "[tool error] qemu-x86_64-static not found (it is in the sandbox image; on the host install qemu-user-static)"
    if not os.access(p, os.X_OK):
        p.chmod(p.stat().st_mode | 0o111)

    n = ctx.next_out_id()
    ctx.out_dir.mkdir(parents=True, exist_ok=True)
    # the raw log goes to a local temp dir, not the challenge dir: the challenge dir is often a bind mount of a
    # Windows drive (DrvFs), where writing a 2 MB qemu log took >10 s per call and stalled the start probe
    log_dir = Path(tempfile.gettempdir()) / f"revagent-trace-{os.getpid()}"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"trace-{n}.log"
    txt_path = ctx.out_dir / f"trace-{n}.txt"
    st = p.stat()
    cache_key = (str(p), st.st_mtime_ns, st.st_size)   # a rebuilt binary at the same path gets no stale base
    known_base = ctx.trace_bases.get(cache_key)
    cmd = [qemu, "-d", "exec,nochain,page", "-D", str(log_path)]
    if range_ is not None:
        # -dfilter needs guest addresses; a Ghidra address inside a PIE image can be converted only once
        # a previous trace of this binary told us the base — otherwise qemu logs everything and the range is
        # applied here (correct, just a bigger log). A PIE is never filtered before its base is known, even
        # for a guest-address range: with -dfilter the entry TB is not logged and the base would be a guess.
        lo, hi = range_
        lo_in_image = is_ghidra_image_addr(lo, elf.size, elf.is_pie)
        hi_in_image = is_ghidra_image_addr(hi - 1, elf.size, elf.is_pie)
        # a range straddling the image end has bounds in two address spaces: no single guest -dfilter
        # expresses it, so qemu logs everything and only the Python filter applies
        same_space = lo_in_image == hi_in_image
        if same_space and (not elf.is_pie or known_base is not None):
            base = known_base if known_base is not None else 0
            glo = from_ghidra(lo, base + elf.vaddr_lo, elf.size, elf.is_pie)
            ghi = from_ghidra(hi - 1, base + elf.vaddr_lo, elf.size, elf.is_pie) + 1
            cmd += ["-dfilter", f"{glo:#x}+{ghi - glo:#x}"]
    cmd += [str(p), *args]
    filtered = "-dfilter" in cmd
    if filtered:
        # only a filtered call logs instructions and registers: ~1.2 KB per block instead of ~60 bytes, affordable
        # inside the range; unfiltered, the libraries alone would take most of the log cap
        cmd[2] = OPS_FLAGS

    r = run_qemu(cmd, p.parent, stdin, log_path, timeout)
    try:   # the cap is polled while qemu runs; a fast exit past it is only visible in the final size
        r["truncated"] = r["truncated"] or log_path.stat().st_size > MAX_LOG_BYTES
    except OSError:
        pass
    try:
        with log_path.open("rb") as f:
            log_text = f.read(MAX_LOG_BYTES).decode("utf-8", "replace")
    except OSError:
        log_text = ""
    trace = parse_qemu_log(log_text)

    stdin_note = f"stdin {len(stdin.encode())} bytes" if stdin else "no stdin"
    header = f"trace_run {binary} ({stdin_note}): exit {r['returncode']}, stdout {_cut(r['stdout'].strip())!r}"
    if r["stderr"].strip():
        header += f", stderr {_cut(r['stderr'].strip())!r}"
    if not trace.pcs:
        ctx.observe(f"trace_run {binary}: [no trace] exit {r['returncode']}")
        return (f"[no trace] program did not execute (exit {r['returncode']})\n{header}\n"
                f"raw qemu log: {_rel(ctx, log_path)}")

    image = locate_image(elf, trace, known_base=known_base)
    if elf.is_pie and not image.guessed:
        ctx.trace_bases[cache_key] = image.lo - elf.vaddr_lo
    # a -dfilter log lacks the entry TB, so region tags (library vs later mmap) come from the unfiltered
    # trace of this same file; an unfiltered trace with a firm base refreshes them
    tags = ctx.trace_regions.get(cache_key) if filtered else None
    a = analyze(trace, image, range_, top, filtered=filtered, tags=tags)
    if not filtered and not image.guessed:
        ctx.trace_regions[cache_key] = {(r.start, r.end): r.kind for r in a.regions if r.kind != "image"}
    items = compress(a.seq)
    txt_path.write_text(full_listing(items))
    lines = [header]
    if not stdin and not args:      # an argv-driven program read its input; the note is about programs that read nothing
        lines.append(EMPTY_STDIN_NOTE)
    lines.append(render(a, items, image, top=top))
    lines.append(f"  [full sequence: {_rel(ctx, txt_path)}, raw qemu log: {_rel(ctx, log_path)}]")
    if filtered:
        ops = parse_ops_log(log_text)
        if ops.states:
            ops_text = ops_lines(ops, image)
            ops_path = ctx.out_dir / f"trace-{n}.ops.txt"
            ops_path.write_text("\n".join(ops_text) + "\n")
            cut = len(ops_text) > OPS_HEAD + OPS_TAIL
            shown = f"first {OPS_HEAD} and last {OPS_TAIL}" if cut else "all"
            lines.append(f"{OPS_HEADER}, {len(ops_text)} lines, {shown}; full listing {_rel(ctx, ops_path)}): each "
                         f"executed block's instructions, then the register values after it ran (registers it "
                         f"names, plus any other it changed; rsp only when named). Memory writes are not shown. "
                         f"Repeats fold as (line)×n")
            if cut:
                ops_text = ops_text[:OPS_HEAD] + [f"... [{len(ops_text) - OPS_HEAD - OPS_TAIL} lines]"] + ops_text[-OPS_TAIL:]
            lines.extend("  " + l for l in ops_text)
    nxt = suggest_next(a, image)
    if nxt:
        lines.append(nxt)
    if ctx.step > 0:                                   # step 0 = the harness's own start probe
        ctx.trace_next_shown += bool(nxt)
        ctx.trace_range_calls += range_ is not None
    if r["truncated"]:
        lines.append(f"[trace truncated at {MAX_LOG_BYTES // (1024 * 1024)} MB] the program ran past the log cap; "
                     "the summary covers the log written until then — narrow it with range= or a shorter input")
    if r["timed_out"]:
        lines.append(f"[trace stopped: timeout after {timeout} s] summary covers the log written until then")

    ledger = f"trace_run {binary}"
    if range_ is not None:
        ledger += f" range {range_[0]:#x}..{range_[1]:#x}"
    ledger += f": {a.total} TBs, listing {_rel(ctx, txt_path)}"
    if range_ is not None:
        ledger += f", {len(a.seq)} in range"
    non_image = [(addr, c) for addr, c in a.hot if not (image.ghidra_lo <= addr < image.ghidra_hi)]
    in_image = [(addr, c) for addr, c in a.hot if image.ghidra_lo <= addr < image.ghidra_hi]
    if non_image:
        addr, c = non_image[0]
        reg = next((rg for rg in a.regions if rg.contains(addr)), None)
        ledger += f", hot [{reg.kind if reg else 'other'}] {addr:#x} ×{c}"
    if in_image:
        ledger += f", image top {in_image[0][0]:#x} ×{in_image[0][1]}"
    if r["truncated"]:
        ledger += " [truncated]"
    if r["timed_out"]:
        ledger += " [timeout]"
    ctx.observe(ledger)
    return "\n".join(lines)


PROBE_LENGTHS = (8, 16, 24, 32, 48, 64)   # input lengths tried at start; the deepest trace hints at the length the check wants
MAX_START_TARGETS = 2
START_OUTPUT_CHARS = 3000
START_OPS_CHARS = 5000      # the ops listing's own budget: it comes last in the ranged output and a shared cut dropped it
START_RANGE_TOP = 60
_NEXT_RANGE = re.compile(r'range="(0x[0-9a-f]+)\.\.(0x[0-9a-f]+)"')
_DEPTH = re.compile(r"sequence \((?:image \+ anon|range [^,]*), (\d+) TBs")


def _is_x86_64_elf_exec(path) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(20)
    except OSError:
        return False
    if len(head) < 20 or head[:4] != b"\x7fELF" or head[4] != 2:
        return False
    e_type, e_machine = struct.unpack_from("<HH", head, 16)
    return e_machine == 62 and e_type in (2, 3) and ".so" not in path.name


def start_observation(ctx) -> str | None:
    """Run by the harness once, before step 1: trace every x86-64 ELF executable at the top of the challenge
    directory with probe inputs of several lengths and hand the deepest trace to the model as its first
    observation. Live runs showed the model never calling trace_run on its own from a blank start (ROVM run 7:
    bash 35 of 40 calls); showing the observation does not depend on the model choosing the tool.
    Returns None when there is nothing to trace or qemu is absent. Never raises."""
    try:
        targets = sorted(p for p in ctx.problem_dir.iterdir()
                         if p.is_file() and not p.name.startswith(".") and _is_x86_64_elf_exec(p))[:MAX_START_TARGETS]
        blocks = []
        for p in targets:
            depths, best = [], None
            for n in PROBE_LENGTHS:
                out = run(ctx, p.name, stdin="A" * n + "\n", timeout=20)
                if not out.startswith("trace_run "):
                    break                                   # qemu absent, [cannot trace], [no trace]
                m = _DEPTH.search(out)
                d = int(m.group(1)) if m else 0
                depths.append(f"{n}:{d}")
                if best is None or d > best[0]:
                    best = (d, n, out)
            if best is None:
                continue
            body = best[2]
            probe = "A" * best[1] + "\n"
            nxt = next((l for l in body.splitlines() if l.startswith("next: ")), None)
            m = _NEXT_RANGE.search(nxt or "")
            head = (f"probe input lengths -> TBs outside libraries: {', '.join(depths)} "
                    f"(showing the deepest, {best[1]} x 'A' + newline)")
            if m:
                # an interpreter-shaped trace: make the range call for the model instead of proposing it
                # (ROVM runs 7-8 read the proposal and went back to objdump)
                ranged = run(ctx, p.name, stdin=probe, range=f"{m.group(1)}..{m.group(2)}", top=START_RANGE_TOP)
                if ranged.startswith("trace_run "):
                    ctx.start_range_auto = True
                    if len(body) > START_OUTPUT_CHARS // 2:
                        body = body[:START_OUTPUT_CHARS // 2] + "\n  [cut; the full sequence file is named above]"
                    ranged, sep, ops = ranged.partition(OPS_HEADER)
                    budget = START_OUTPUT_CHARS // 2 if sep else START_OUTPUT_CHARS   # the ops listing covers the sequence
                    if len(ranged) > budget:
                        ranged = ranged[:budget] + "\n  [cut; the full sequence file is named above]"
                    if sep:
                        ops = sep + ops
                        if len(ops) > START_OPS_CHARS:
                            ops = ops[:START_OPS_CHARS] + "\n  [cut; the full ops listing file is named above]"
                        nxt_text = (f"NEXT: read the ops listing as the program: each line is one block the real run "
                                    f"executed, its instructions and the register values it produced, so no handler "
                                    f"needs disassembling and no machine state needs rebuilding in an emulator. Find "
                                    f"where input bytes are loaded and what they are compared with; grep the ops "
                                    f"file for later iterations.")
                    else:
                        nxt_text = (f"NEXT: map each distinct address to its operation ONCE (disassemble the bytes at "
                                    f"that address, or decompile/emulate), then read the sequence as a program.")
                    blocks.append(
                        f"{head}\n{body}\n\n"
                        f"The harness already made the range call over {m.group(1)}..{m.group(2)}, the region mapped "
                        f"after start where the loop runs. Its `hot` line lists every distinct block address there "
                        f"with its count, and its sequence is the order they ran in, repeats folded: for an "
                        f"interpreter, that is the interpreted program. {nxt_text}\n{ranged.rstrip()}"
                        + (f"\n{ops}" if sep else ""))
                    continue
            if len(body) > START_OUTPUT_CHARS:
                body = body[:START_OUTPUT_CHARS] + "\n  [cut; the full sequence file is named above]"
            if nxt:
                head += "\n" + nxt                        # kept above the cut: it is the call to make next
            blocks.append(f"{head}\n{body}")
        if not blocks:
            return None
        return ("[start observation] Before your first step the harness ran trace_run on each x86-64 ELF here with "
                "probe inputs of several lengths. This is an observation of a real execution (evidence ladder: Observation). Compare the "
                "counts: where they stop growing, the program stops consuming input; if they keep growing, every "
                "input byte is processed.\n\n" + "\n\n".join(blocks))
    except Exception:
        return None
