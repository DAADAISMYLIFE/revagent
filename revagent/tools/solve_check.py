"""Invert a byte-wise transform with z3. The model writes the FORWARD transform as ordinary Python
(what it can do); the solver finds the input (what it repeatedly could not do by hand).

The user script defines transform(x) over a list of 8-bit values using integer arithmetic
(+ - * ^ & | << >> % and constant-table lookups). We run it with x = symbolic values wrapped in Sym,
which keeps Python-int semantics (logical >>, wrap-around only when the script masks) on top of
64-bit z3 bit-vectors, then ask z3 for x such that transform(x) == target."""
import re
import traceback

from .base import PathError, resolve_inside

WIDTH = 64
DEFAULT_TIMEOUT = 60

SCHEMA = {
    "type": "function",
    "function": {
        "name": "solve_check",
        "description": (
            "Invert a byte-wise check with z3 instead of by hand. Write the FORWARD transform as plain Python in a "
            "file: `def transform(x): ...` takes a list of `length` byte values (ints 0-255) and returns the list "
            "the program compares against its target, using only + - * ^ & | << >> % and indexing into constant "
            "tables (wrap tables as Table([...]) — Table is provided). The tool runs transform on symbolic bytes and "
            "returns an input whose transform equals `target`. Works for byte-wise / sequential / stateful checks "
            "(XOR, add, S-box, rotations, per-block rounds); useless for hashes and standard ciphers. Data-dependent "
            "branches, int() casts and loops whose bounds depend on x are not symbolic: the tool names the line."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "python file (relative to the challenge dir) defining transform(x)"},
                "target": {"type": "string", "description": "expected output as hex, e.g. '7e7d9a8b...'"},
                "length": {"type": "integer", "description": "number of input bytes (len(x))"},
                "charset": {"type": "string", "description": "optional regex character class each input byte must match, e.g. '[ -~]' for printable"},
                "timeout": {"type": "integer", "description": "solver seconds (default 60)"},
            },
            "required": ["file", "target", "length"],
        },
    },
}


class NotSymbolic(Exception):
    pass


_TABLES: list = []   # every Table built since the current symbolic_solve started (import time or inside transform)


class Sym:
    """A z3 bit-vector with Python-int semantics for the operators a byte-wise check uses."""
    __slots__ = ("v",)

    def __init__(self, v):
        self.v = v

    @staticmethod
    def _raw(o):
        return o.v if isinstance(o, Sym) else o

    def _bin(self, other, f):
        import z3
        a, b = self.v, Sym._raw(other)
        if isinstance(b, bool):
            b = int(b)
        if not isinstance(b, (int, z3.BitVecRef)):
            raise NotSymbolic(f"unsupported operand {type(other).__name__}")
        return Sym(f(a, b))

    def __add__(self, o): return self._bin(o, lambda a, b: a + b)
    def __radd__(self, o): return self._bin(o, lambda a, b: b + a)
    def __sub__(self, o): return self._bin(o, lambda a, b: a - b)
    def __rsub__(self, o): return self._bin(o, lambda a, b: b - a)
    def __mul__(self, o): return self._bin(o, lambda a, b: a * b)
    def __rmul__(self, o): return self._bin(o, lambda a, b: b * a)
    def __xor__(self, o): return self._bin(o, lambda a, b: a ^ b)
    def __rxor__(self, o): return self._bin(o, lambda a, b: b ^ a)
    def __and__(self, o): return self._bin(o, lambda a, b: a & b)
    def __rand__(self, o): return self._bin(o, lambda a, b: b & a)
    def __or__(self, o): return self._bin(o, lambda a, b: a | b)
    def __ror__(self, o): return self._bin(o, lambda a, b: b | a)
    def __lshift__(self, o): return self._bin(o, lambda a, b: a << b)
    def __rshift__(self, o):
        import z3
        return self._bin(o, lambda a, b: z3.LShR(a, b))       # Python >> on non-negative ints is logical
    def __mod__(self, o):
        import z3
        return self._bin(o, lambda a, b: z3.URem(a, b))
    def __neg__(self): return Sym(-self.v)
    def __invert__(self): return Sym(~self.v)
    def __eq__(self, o): return Sym(self.v == Sym._raw(o))
    def __ne__(self, o): return Sym(self.v != Sym._raw(o))
    def __hash__(self): return id(self)
    def __int__(self): raise NotSymbolic("int() on a symbolic value")
    def __index__(self): raise NotSymbolic("a symbolic value used as an index/range bound (wrap the table in Table)")
    def __bool__(self): raise NotSymbolic("a symbolic value used in a branch (if/while/and/or)")
    def __lt__(self, o): raise NotSymbolic("comparison used as a value; only == against constants is supported")
    __le__ = __gt__ = __ge__ = __lt__


class Table:
    """A constant lookup table. Indexed by a plain int it is a list; indexed by a Sym it becomes a z3
    Array select (the index is reduced mod the table size), so S-boxes and key schedules work symbolically."""

    def __init__(self, values):
        self.values = [int(v) & 0xff for v in values]
        self._arr = None
        _TABLES.append(self)

    def __len__(self):
        return len(self.values)

    def __iter__(self):
        return iter(self.values)

    def __getitem__(self, idx):
        if isinstance(idx, Sym):
            import z3
            if self._arr is None:
                self._arr = z3.Array(f"table_{id(self)}", z3.BitVecSort(WIDTH), z3.BitVecSort(WIDTH))
                self._cons = [self._arr[z3.BitVecVal(i, WIDTH)] == z3.BitVecVal(v, WIDTH) for i, v in enumerate(self.values)]
            n = len(self.values)
            return Sym(self._arr[z3.URem(idx.v, n)])
        return self.values[idx]

    def constraints(self):
        return list(getattr(self, "_cons", []) or [])


def _allowed_bytes(charset: str) -> list[int] | None:
    if not charset:
        return None
    rx = re.compile(f"^{charset}$")
    return [c for c in range(256) if rx.match(chr(c))]


def symbolic_solve(source: str, target: bytes, length: int, charset: str, timeout_s: int):
    """Returns ("sat", bytes) | ("unsat", None) | ("timeout", None) | ("error: <text>", None)."""
    import z3
    ns = {"Table": Table, "__name__": "transform_module"}
    _TABLES.clear()
    try:
        exec(compile(source, "transform.py", "exec"), ns)
    except Exception as e:
        return f"error: the file failed to import: {type(e).__name__}: {e}", None
    fn = ns.get("transform")
    if not callable(fn):
        return "error: the file must define transform(x)", None
    xs = [z3.BitVec(f"x{i}", WIDTH) for i in range(length)]
    try:
        out = fn([Sym(v) for v in xs])
        out = list(out)
    except NotSymbolic as e:
        tb = traceback.extract_tb(e.__traceback__)
        user = [f for f in tb if f.filename == "transform.py"]
        where = f"line {user[-1].lineno}: `{user[-1].line}`" if user else "unknown line"
        return f"error: not symbolic at {where} — {e}. Rewrite that line with arithmetic (masks, Table lookups) only.", None
    except Exception as e:
        tb = traceback.extract_tb(e.__traceback__)
        user = [f for f in tb if f.filename == "transform.py"]
        where = f"line {user[-1].lineno}: `{user[-1].line}`" if user else "unknown line"
        return f"error: transform raised {type(e).__name__}: {e} at {where}", None
    if len(out) != len(target):
        return f"error: transform returned {len(out)} values but target has {len(target)} bytes", None
    s = z3.Solver()
    s.set("timeout", int(timeout_s * 1000))
    for x in xs:
        s.add(z3.ULE(x, 255))
    allowed = _allowed_bytes(charset)
    if allowed is not None:
        for x in xs:
            s.add(z3.Or([x == c for c in allowed]))
    # Tables built inside transform() are not in ns; an unconstrained Array would let z3 invent table
    # contents and answer [sat] for an impossible target, so every Table registers itself instead.
    for t in _TABLES:
        for c in t.constraints():
            s.add(c)
    for o, tb_ in zip(out, target):
        ov = Sym._raw(o)
        if isinstance(ov, int):
            if (ov & 0xff) != tb_:
                return "unsat", None
            continue
        s.add((ov & 0xff) == tb_)
    r = s.check()
    if r == z3.sat:
        m = s.model()
        return "sat", bytes(m.eval(x, model_completion=True).as_long() & 0xff for x in xs)
    if r == z3.unsat:
        return "unsat", None
    return "timeout", None


def run(ctx, file: str, target: str, length: int, charset: str = "", timeout: int = DEFAULT_TIMEOUT) -> str:
    try:
        p = resolve_inside(ctx, file)
    except PathError as e:
        return str(e)
    try:
        tgt = bytes.fromhex(target.replace(" ", ""))
    except ValueError:
        return f"[tool error] target must be hex (got {target[:40]!r})"
    if not (1 <= int(length) <= 4096):
        return f"[tool error] length must be 1..4096 (got {length})"
    if len(tgt) != int(length):
        return f"[tool error] length {length} does not match target ({len(tgt)} bytes); pass the input length and make transform return exactly len(target) values"
    try:
        _allowed_bytes(charset)
    except re.error as e:
        return f"[tool error] charset is not a valid character class: {e}"
    timeout_s = ctx.clamp_timeout(max(1, min(int(timeout), 900)))
    source = p.read_text(encoding="utf-8", errors="replace")
    status, sol = symbolic_solve(source, tgt, int(length), charset, timeout_s)
    if status == "sat":
        printable = "".join(chr(c) if 32 <= c < 127 else "." for c in sol)
        return (f"[sat] input ({len(sol)} bytes)\nhex: {sol.hex()}\ntext: {printable}\ntarget: {tgt.hex()}\n"
                f"Verify it on the real program before submit_flag (run_binary / run_gui).")
    if status == "unsat":
        return ("[unsat] no input of that length maps to the target under this transform. Either the transform is "
                "not faithful (compare it against the real program on a known input) or the length/charset is wrong.")
    if status == "timeout":
        return f"[timeout] z3 gave up after {timeout_s}s; simplify the transform or split the input into independent blocks."
    return f"[error] {status[len('error: '):]}"
