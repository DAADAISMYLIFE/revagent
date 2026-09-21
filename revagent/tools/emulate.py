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
            "'addr:0x...' passes an address inside the image (a data table). Calling convention follows the "
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
                         "description": "in order: 'hex:<hex bytes>' | 'int:<number>' | 'addr:0x<address>'"},
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


def parse_args(items: list[str]) -> list[tuple[str, object]]:
    out = []
    for s in items:
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
            else:
                out.append((kind, int(val, 0)))
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
    try:
        parsed = parse_args(list(args or []))
    except ValueError as e:
        return f"[tool error] args: {e}"
    if int(max_insns) <= 0:
        return "[tool error] max_insns must be positive"
    key = str(p)
    image = ctx.emulate_images.get(key)
    if image is None:
        try:
            image = load_image(p)
        except EmulateError as e:
            return f"[cannot emulate] {e}"
        ctx.emulate_images[key] = image
    timeout_s = ctx.clamp_timeout(DEFAULT_TIMEOUT)
    try:
        r = emulate_call(image, func, parsed, out_lens=out_lens, max_insns=int(max_insns), timeout_s=timeout_s)
    except EmulateError as e:
        return f"[tool error] {e}"
    except Exception as e:
        # unicorn's own failures (UcError: e.g. the image overlaps the emulator's fixed regions) must
        # come back as a tool error, not kill the agent loop
        return f"[tool error] emulation failed: {type(e).__name__}: {e}"
    lines = [f"rax=0x{r.rax:x}"]
    for i, b in enumerate(r.buffers):
        lines.append(f"arg{i} ({len(b)} bytes): {b.hex()}  |{_printable(b)}|")
    if r.stopped:
        regs = ("rcx", "rdx", "r8", "r9") if image.is_pe else ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
        regtxt = ", ".join(f"{n}=0x{v:x}" for n, v in zip(regs, r.stopped["arg_regs"]))
        if r.stopped["reason"] == "import":
            lines.append(f"[emulation stopped] called {r.stopped['symbol']} at 0x{r.stopped['rip']:x}; arg registers: {regtxt}")
            lines.append("Imports are not emulated: target the inner function that does the arithmetic (the FUN_ the "
                         "decompiler shows around this call), or treat this call and its registers as the observation.")
        elif r.stopped["reason"] == "limit":
            lines.append(f"[emulation stopped] {r.stopped['detail']}; raise max_insns only if the function really loops that much")
        else:
            lines.append(f"[emulation stopped] {r.stopped['detail']}; arg registers: {regtxt}")
            lines.append("The function touched memory this oracle did not set up (a global, heap, or a second buffer): "
                         "pass it as an addr:/hex: argument or target a smaller function.")
    first = r.buffers[0].hex()[:32] if r.buffers else "-"
    ctx.observe(f"emulate {function}: rax=0x{r.rax:x}, arg0={first}" + (f", stopped={r.stopped['reason']}" if r.stopped else ""))
    return "\n".join(lines)
