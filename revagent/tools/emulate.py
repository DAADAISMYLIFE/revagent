"""emulate: run ONE function of the challenge binary and see what it does to its arguments.
The oracle the model lacked: after re-implementing a transform in Python, it can compare its function
with the real one on a few inputs before inverting anything."""
import re

from ..emulate import EmulateError, emulate_call, load_image
from .base import PathError, resolve_inside

DEFAULT_TIMEOUT = 30
MAX_INSNS = 5_000_000

SCHEMA = {
    "type": "function",
    "function": {
        "name": "emulate",
        "description": (
            "Run ONE function of the binary under an emulator and return rax and the bytes of every buffer "
            "argument after the call. Use it as the oracle for your Python re-implementation: emulate the "
            "transform on a few inputs, compare with your model, fix the model until they agree, then "
            "invert with solve_check. Addresses are Ghidra's (FUN_..., 0x...); PIE ELF is loaded at 0x100000 "
            "and PE at its ImageBase, exactly as in decompile. Arguments: 'hex:<bytes>' allocates a buffer "
            "with those bytes and passes its address (returned after the call), 'int:<n>' passes a number, "
            "'addr:0x...' passes an address inside the image (a data table). A hex: buffer is zero-filled for at "
            "least one page past your bytes, so it can also serve as an output buffer; out_lens reads back that "
            "many bytes (capped at the mapping). Calling convention follows the "
            "file format (SysV for ELF, Win64 for PE). Only pure code runs: if the function calls an import "
            "(strlen, memcmp, GdipDrawLineI...) emulation stops there and reports the callee and the argument "
            "registers — target the inner function instead, or use that report as the observation you wanted."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "binary": {"type": "string", "description": "path relative to the challenge dir"},
                "function": {"type": "string", "description": "FUN_1400010a0 / thunk_FUN_... / 0x1400010a0"},
                "args": {"type": "array", "items": {"type": "string"},
                         "description": "in order: 'hex:<hex bytes>' | 'int:<number>' | 'addr:0x<address> (DAT_00106020 / 00106020 also accepted)'"},
                "out_lens": {"type": "array", "items": {"type": "integer"},
                             "description": "bytes to read back per hex arg after the call (default: input length)"},
                "max_insns": {"type": "integer", "description": "instruction limit (default 5000000)"},
            },
            "required": ["binary", "function", "args"],
        },
    },
}


def parse_function(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    m = re.search(r"FUN_([0-9a-fA-F]+)$", t)
    if m:
        return int(m.group(1), 16)
    raise ValueError(f"function must be FUN_<hex>, thunk_FUN_<hex> or 0x<hex> (got {text!r})")


_ADDR_PREFIX = re.compile(r"^(?:(?:DAT|PTR|LAB)_)+", re.IGNORECASE)


def parse_addr(val: str) -> int:
    """What a model copies from the decompiler: DAT_00106020, 00106020, 0x106020. A bare run of hex digits
    of 5+ chars is hex (decimal is meaningless for an address); shorter tokens go through int(val, 0)."""
    v = _ADDR_PREFIX.sub("", val.strip())
    if v.lower().startswith("0x"):
        return int(v, 16)
    if len(v) >= 5 and all(c in "0123456789abcdefABCDEF" for c in v):
        return int(v, 16)
    return int(v, 0)


def parse_args(items: list[str]) -> list[tuple[str, object]]:
    out = []
    for s in items:
        s = str(s)   # the model sends JSON; an int or a number-like token still gets a named error below
        if ":" not in s:
            raise ValueError(f"argument {s!r} must be hex:<bytes>, int:<n> or addr:0x<address>")
        kind, _, val = s.partition(":")
        kind = kind.strip().lower()
        val = val.strip()
        if kind not in ("hex", "int", "addr"):
            raise ValueError(f"argument {s!r} must be hex:<bytes>, int:<n> or addr:0x<address>")
        try:
            if kind == "hex":
                v = val[2:] if val.lower().startswith("0x") else val
                out.append(("hex", bytes.fromhex(v.replace(" ", ""))))
            elif kind == "addr":
                out.append(("addr", parse_addr(val)))
            else:
                out.append(("int", int(val, 0)))
        except ValueError as e:
            # bytes.fromhex / int raise their own ValueError without naming the argument; name it
            raise ValueError(f"argument {s!r}: {e}") from None
    return out


def _printable(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def run(ctx, binary: str, function: str, args: list[str], out_lens: list[int] | None = None,
        max_insns: int = MAX_INSNS) -> str:
    try:
        p = resolve_inside(ctx, binary)
    except PathError as e:
        return str(e)
    try:
        func = parse_function(function)
    except ValueError as e:
        return f"[tool error] function: {e}"
    if args is None:
        args = []
    if not isinstance(args, (list, tuple)):
        # a bare string would be iterated per character
        return "[tool error] args must be a list of 'hex:'/'int:'/'addr:' strings"
    try:
        parsed = parse_args(list(args))
    except ValueError as e:
        return f"[tool error] args: {e}"
    if out_lens is not None and not (isinstance(out_lens, list)
                                     and all(isinstance(n, int) and not isinstance(n, bool) for n in out_lens)):
        return "[tool error] out_lens must be a list of integers"
    try:
        max_insns = int(max_insns)
    except (TypeError, ValueError):
        return "[tool error] max_insns must be a positive integer"
    if max_insns <= 0:
        return "[tool error] max_insns must be a positive integer"
    try:
        st = p.stat()
    except OSError as e:
        return f"[tool error] cannot stat {binary}: {e}"
    key = (str(p), st.st_mtime_ns, st.st_size)   # the playbook has the model patch binaries in place
    image = ctx.emulate_images.get(key)
    if image is None:
        try:
            image = load_image(p)
        except EmulateError as e:
            return f"[cannot emulate] {e}"
        except Exception as e:
            return f"[cannot emulate] {type(e).__name__}: {e}"
        ctx.emulate_images[key] = image
    timeout_s = ctx.clamp_timeout(DEFAULT_TIMEOUT)
    try:
        r = emulate_call(image, func, parsed, out_lens=out_lens, max_insns=max_insns, timeout_s=timeout_s)
    except EmulateError as e:
        return f"[tool error] {e}"
    except Exception as e:
        # unicorn's own failures (UcError: e.g. the image overlaps the emulator's fixed regions) must
        # come back as a tool error, not kill the agent loop
        return f"[tool error] emulation failed: {type(e).__name__}: {e}"
    hex_idx = [i for i, (k, _) in enumerate(parsed) if k == "hex"]   # buffers come back in hex-arg order
    lines = [f"rax=0x{r.rax:x}"]
    for i, b in enumerate(r.buffers):
        lines.append(f"arg{hex_idx[i]} ({len(b)} bytes): {b.hex()}  |{_printable(b)}|")
    if r.stopped:
        regs = ("rcx", "rdx", "r8", "r9") if image.is_pe else ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
        regtxt = ", ".join(f"{n}=0x{v:x}" for n, v in zip(regs, r.stopped["arg_regs"]))
        if r.stopped["reason"] == "import":
            lines.append(f"[emulation stopped] called {r.stopped['symbol']} at 0x{r.stopped['rip']:x}; arg registers: {regtxt}")
            lines.append("Imports are not emulated: target the inner function that does the arithmetic (the FUN_ the "
                         "decompiler shows around this call), or treat this call and its registers as the observation.")
        elif r.stopped["reason"] == "limit":
            lines.append(f"[emulation stopped] {r.stopped['detail']}; raise max_insns only if the function really loops "
                         f"that much; arg registers: {regtxt}")
        elif r.stopped["reason"] == "invalid":
            lines.append(f"[emulation stopped] {r.stopped['detail']}; arg registers: {regtxt}")
            lines.append("The function executed an instruction the emulator cannot run (syscall, int, privileged, unusual "
                         "SIMD): target the function below that point, or observe through run_binary instead.")
        else:
            lines.append(f"[emulation stopped] {r.stopped['detail']}; arg registers: {regtxt}")
            lines.append("The function touched memory this oracle did not set up (a global, heap, or a second buffer): "
                         "pass it as an addr:/hex: argument or target a smaller function.")
    first = f"arg{hex_idx[0]}={r.buffers[0].hex()[:32]}" if r.buffers else "arg0=-"
    ctx.observe(f"emulate {function}: rax=0x{r.rax:x}, {first}" + (f", stopped={r.stopped['reason']}" if r.stopped else ""))
    return "\n".join(lines)
