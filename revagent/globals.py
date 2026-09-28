"""Values of the DAT_ globals a decompiled function reads, at the element width the decompiler shows.

bronze chall2 took 20-35 steps in three runs instead of ~8: its check compares the input with a table of
4-byte ints (`*(uint *)(&DAT_140003000 + i * 4)`), and the model read that table from a hexdump by eye,
misread it, then spent the run on encoding and file-offset theories. The harness reads the table instead,
with the width taken from the cast in the C, so there is no hexdump to misread.

Addresses are Ghidra's: the image is loaded with cle at Ghidra's base (PE ImageBase, PIE ELF 0x100000).
Pure module: nothing here knows any challenge."""
import re
from pathlib import Path

GHIDRA_PIE_BASE = 0x100000
MAX_GLOBALS = 6
MAX_ELEMS = 64
LOOKUP_ELEMS = 256        # a table indexed by a data byte (an S-box) is read whole
BLOCK_CHARS = 3_000

_DAT = re.compile(r"\bDAT_([0-9a-fA-F]{4,16})\b")
_WIDTHS = {1: ("char", "uchar", "byte", "undefined", "undefined1", "bool", "int8_t", "uint8_t"),
           2: ("short", "ushort", "word", "undefined2", "wchar_t", "wchar16", "int16_t", "uint16_t"),
           4: ("int", "uint", "dword", "undefined4", "float", "int32_t", "uint32_t", "wchar32"),
           8: ("long", "ulong", "longlong", "ulonglong", "qword", "undefined8", "double", "int64_t", "uint64_t")}
_WIDTH_OF = {name: w for w, names in _WIDTHS.items() for name in names}

_loaders: dict = {}   # (path, mtime_ns, size) -> cle.Loader


def _indexed(c_text: str, addr: int) -> list[str]:
    """The expressions that index DAT_x as a table: `(&DAT_x)[i]`, `DAT_x[i]` or `&DAT_x + i * w`. A scalar global
    (`DAT_x = 1`, CRT bookkeeping) has none, and gets no [globals] line."""
    name = f"DAT_0*{addr:x}"
    rx = re.compile(r"(?:\(\s*&" + name + r"\s*\)|\b" + name + r")\s*\[([^\]]{1,80})\]"
                    r"|&" + name + r"\s*\+\s*((?:\([^()]{0,40}\)|[^()]){1,80})", re.I)   # one level of casts: (long)i * 4
    return [m.group(1) or m.group(2) for m in rx.finditer(c_text or "")]


def referenced(c_text: str) -> list[int]:
    """Distinct DAT_ addresses the C uses as tables, in order of first use."""
    out: list[int] = []
    for m in _DAT.finditer(c_text or ""):
        a = int(m.group(1), 16)
        if a not in out and _indexed(c_text, a):
            out.append(a)
    return out[:MAX_GLOBALS]


def is_lookup(c_text: str, addr: int) -> bool:
    """DAT_x is indexed by data (a loaded byte, an xor), not by the loop counter: `(&DAT_x)[*(byte *)(p + i)]`.
    Then the loop bound says nothing about its size."""
    return any("*(" in e or "[" in e or "^" in e for e in _indexed(c_text, addr))


def loop_count(c_text: str, addr: int) -> int | None:
    """How many elements the loop over DAT_x visits, from a bound on its index variable: `0x17 < i` or `i <= 0x17`
    gives 0x18, `i < 0x18` or `0x18 > i` gives 0x18. None when no bound is found."""
    names = {v for e in _indexed(c_text, addr) for v in re.findall(r"\b([a-zA-Z_]\w*)\b", e)
             if not re.fullmatch(r"(?:u?int|u?long(?:long)?|char|byte|u?short|size_t)", v)}
    num = r"(0x[0-9a-fA-F]+|\d+)"
    for v in names:
        var = r"(?:\([^()]*\))?" + re.escape(v) + r"\b"
        for pat, extra in ((num + r"\s*<\s*" + var, 1), (var + r"\s*<=\s*" + num, 1),
                           (var + r"\s*<\s*" + num, 0), (num + r"\s*>\s*" + var, 0)):
            m = re.search(pat, c_text)
            if m:
                n = int(m.group(1), 0) + extra
                if 0 < n <= MAX_ELEMS:
                    return n
    return None


def element_width(c_text: str, addr: int) -> int:
    """Width of one element as the C reads it: the pointer cast in front of `&DAT_x` (`*(uint *)(&DAT_x + ...)`,
    `(uint *)&DAT_x`), else 1 (Ghidra types an untyped global as undefined, i.e. bytes)."""
    name = f"DAT_0*{addr:x}"                      # Ghidra zero-pads (DAT_00104010)
    for m in re.finditer(r"\(\s*((?:unsigned\s+)?\w+)\s*\*\s*\)\s*\(?\s*&" + name + r"\b", c_text or "", re.I):
        t = m.group(1).lower().replace("unsigned ", "u")
        if t in _WIDTH_OF:
            return _WIDTH_OF[t]
    return 1


def _loader(path: Path):
    import cle
    st = path.stat()
    key = (str(path), st.st_mtime_ns, st.st_size)
    ld = _loaders.get(key)
    if ld is None:
        ld = cle.Loader(str(path), auto_load_libs=False)
        mo = ld.main_object
        if type(mo).__name__.startswith("ELF") and getattr(mo, "pic", False) and mo.mapped_base != GHIDRA_PIE_BASE:
            ld = cle.Loader(str(path), auto_load_libs=False, main_opts={"base_addr": GHIDRA_PIE_BASE})
        _loaders[key] = ld
    return ld


def read(path: Path, addr: int, n: int) -> bytes | None:
    """Up to n bytes of the loaded image at a Ghidra address; None when the address is not in the image."""
    ld = _loader(Path(path))
    try:
        return bytes(ld.memory.load(addr, n))
    except Exception:
        out = b""
        for i in range(n):               # a table can end at a segment boundary: take what is mapped
            try:
                out += bytes(ld.memory.load(addr + i, 1))
            except Exception:
                break
        return out or None


def _as_text(vals: list[int]) -> str | None:
    """The elements as characters, up to the first 0, when there are at least 4 and every one is printable."""
    chars = []
    for v in vals:
        if v == 0:
            break
        if not 0x20 <= v < 0x7f:
            return None
        chars.append(chr(v))
    return "".join(chars) if len(chars) >= 4 else None


def describe(path: Path, c_text: str) -> str:
    """The `[globals]` block for one decompiled function, or "" (nothing referenced, or nothing readable).
    Never raises."""
    lines = []
    try:
        for addr in referenced(c_text):
            w = element_width(c_text, addr)
            lookup = is_lookup(c_text, addr)
            raw = read(path, addr, w * (LOOKUP_ELEMS if lookup else MAX_ELEMS))
            if not raw or len(raw) < w:
                continue
            vals = [int.from_bytes(raw[i:i + w], "little") for i in range(0, len(raw) - w + 1, w)]
            count = None if lookup else loop_count(c_text, addr)
            if count:
                vals = vals[:count]
            if not any(vals):
                lines.append(f"DAT_{addr:x}: all zero in the file (filled at run time; observe it instead)")
                continue
            text = None if lookup else _as_text(vals)
            if count or lookup:
                shown = vals                                     # exactly what the loop reads
            elif text is not None:
                shown = vals[:len(text) + 1]                     # up to the terminator; what follows is other data
            else:
                last = max(i for i, v in enumerate(vals) if v)   # trailing zeros are padding, not data
                shown = vals[:min(len(vals), last + 2)]
            hexes = " ".join(f"{v:02x}" if w == 1 else f"{v:#0{2 + 2 * w}x}" for v in shown)
            src = ("a lookup table indexed by data, read whole" if lookup else
                   f"the loop bound in the C reads {count}" if count else "no loop bound found; cut at padding")
            line = f"DAT_{addr:x} as {len(shown)} x {w}-byte values ({src}): {hexes}"
            if text is not None:
                line += f"\n  as characters (one per {w}-byte element, up to the first 0): {text!r} ({len(text)} chars)"
            lines.append(line)
    except Exception:
        pass
    if not lines:
        return ""
    block = ("[globals] read from the binary at the width the C above uses (not a hexdump; use these values, "
             "do not re-read them by eye):\n" + "\n".join(lines))
    return block[:BLOCK_CHARS] + "\n"
