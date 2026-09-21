"""Invert a byte-wise transform with z3. The model writes the FORWARD transform as ordinary Python
(what it can do); the solver finds the input (what it repeatedly could not do by hand).

The user script defines transform(x) over a list of 8-bit values using integer arithmetic
(+ - * // ^ & | << >> % and constant-table lookups). We run it with x = symbolic values wrapped in Sym
on top of 64-bit z3 bit-vectors, then ask z3 for x such that transform(x) == target.

Semantics: intermediate values are treated as non-negative 64-bit integers — mask as the program does
(`& 0xff`, `& 0xffffffff`) and keep intermediates in range; a shift of a negative intermediate or an
unmasked overflow diverges from Python (`>>` and `//` are unsigned, `%` follows Python's floor-mod, `<<`
past bit 63 drops bits). Every sat answer is re-run concretely, so a divergence shows up as `[sat?]`,
never as a wrong `[sat]`."""
import contextlib
import re
import signal
import threading
import traceback

from .base import PathError, resolve_inside

WIDTH = 64
DEFAULT_TIMEOUT = 60
SEMANTICS = ("intermediate values are treated as non-negative 64-bit integers — mask as the program does "
             "(`& 0xff`, `& 0xffffffff`) and keep intermediates in range; a shift of a negative intermediate or an "
             "unmasked overflow diverges from Python.")

SCHEMA = {
    "type": "function",
    "function": {
        "name": "solve_check",
        "description": (
            "Invert a byte-wise check with z3 instead of by hand. Write the FORWARD transform as plain Python in a "
            "file: `def transform(x): ...` takes a list of `length` byte values (ints 0-255) and returns the list "
            "the program compares against its target, using only + - * // ^ & | << >> % and indexing into constant "
            "tables (wrap tables as Table([...]) — Table is provided). The tool runs transform on symbolic bytes and "
            "returns an input whose transform equals `target`. Works for byte-wise / sequential / stateful checks "
            "(XOR, add, S-box, rotations, per-block rounds); useless for hashes and standard ciphers. Intermediate "
            "values are treated as non-negative 64-bit integers — mask as the program does (`& 0xff`, `& 0xffffffff`) "
            "and keep intermediates in range; a shift of a negative intermediate or an unmasked overflow diverges "
            "from Python. Data-dependent branches, int() casts and loops whose bounds depend on x are not symbolic: "
            "the tool names the line."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "python file (relative to the challenge dir) defining transform(x)"},
                "target": {"type": "string", "description": "expected output as hex, e.g. '7e7d9a8b...'"},
                "length": {"type": "integer", "description": "number of input bytes (len(x))"},
                "charset": {"type": "string", "description": "optional regex character class each input byte must match, e.g. '[ -~]' for printable"},
                "timeout": {"type": "integer", "description": "solver and transform seconds (default 60)"},
            },
            "required": ["file", "target", "length"],
        },
    },
}


class NotSymbolic(Exception):
    pass


class SolverTimeout(BaseException):
    """The user's Python (import, transform on symbols, or the concrete re-check) ran past the time bound.
    A BaseException so an `except Exception: pass` inside the user's transform cannot swallow it."""


@contextlib.contextmanager
def _time_limit(seconds: float):
    """Raise SolverTimeout inside the block after `seconds` of wall time. exec/transform run in-process, so
    without this a `while True` in the user's file would hang the whole agent. Armed only around the Python
    phases, never around s.check(): z3 has its own timeout, and an alarm pending across the C call would
    surface after it returned and discard a genuine answer. SIGALRM handlers can only be installed from the
    main thread; elsewhere the block runs unbounded."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def on_alarm(signum, frame):
        raise SolverTimeout()

    prev_handler = signal.signal(signal.SIGALRM, on_alarm)
    prev_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *prev_timer)
        signal.signal(signal.SIGALRM, prev_handler)


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
    def __rrshift__(self, o):
        import z3
        return self._bin(o, lambda a, b: z3.LShR(b, a))
    def __rlshift__(self, o): return self._bin(o, lambda a, b: b << a)
    def __floordiv__(self, o):
        import z3
        return self._bin(o, lambda a, b: z3.UDiv(a, b))      # unsigned: equals Python // while both sides are in range
    def __mod__(self, o): return self._bin(o, lambda a, b: a % b)   # z3 BitVec % is bvsmod: sign of the divisor, like Python
    def __rmod__(self, o): return self._bin(o, lambda a, b: b % a)
    def __neg__(self): return Sym(-self.v)
    def __invert__(self): return Sym(~self.v)
    def __eq__(self, o): return Sym(self.v == Sym._raw(o))
    def __ne__(self, o): return Sym(self.v != Sym._raw(o))
    def __hash__(self): return id(self)
    def __int__(self): raise NotSymbolic("int() on a symbolic value")
    def __index__(self): raise NotSymbolic("a symbolic value was used where a plain int is required (bytes(), range(), list index); index a Table with it instead")
    def __bool__(self): raise NotSymbolic("a symbolic value used in a branch (if/while/and/or)")
    def __lt__(self, o): raise NotSymbolic("comparison used as a value; only == against constants is supported")
    __le__ = __gt__ = __ge__ = __lt__


class Table:
    """A constant lookup table. Indexed by a plain int it is a list; indexed by a Sym it becomes a z3
    Array select with the index constrained to 0..len-1, so S-boxes and key schedules work symbolically.
    Values keep their full width (a 32-bit round-constant table is not truncated)."""

    def __init__(self, values):
        values = list(values)
        if any(isinstance(v, Sym) for v in values):
            raise NotSymbolic("Table entries must be constants; pass the input through indexing, not into the table")
        self.values = [int(v) for v in values]
        self._arr = None
        self._cons = []
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
            self._cons.append(z3.ULT(idx.v, len(self.values)))   # no wrap-around: an index past the end is no solution
            return Sym(self._arr[idx.v])
        return self.values[idx]

    def constraints(self):
        return list(self._cons)


def _allowed_bytes(charset: str) -> list[int] | None:
    if not charset:
        return None
    rx = re.compile(f"^{charset}$")
    return [c for c in range(256) if rx.match(chr(c))]


def _where(source: str, exc: BaseException) -> str:
    """'line N: `text`' for the innermost frame of exc inside the user's file. The text comes from the
    source we compiled: linecache knows no "transform.py" (and must not read a stray real one)."""
    user = [f for f in traceback.extract_tb(exc.__traceback__) if f.filename == "transform.py"]
    if not user:
        return "unknown line"
    lines = source.splitlines()
    n = user[-1].lineno
    text = lines[n - 1] if 1 <= n <= len(lines) else ""
    return f"line {n}: `{text}`"


def _concrete_matches(fn, sol: bytes, target: bytes) -> bool:
    """Re-run the user's transform on plain ints: z3 answered about our symbolic semantics (64-bit wrap,
    floor-mod, table width), and only the real Python run says whether the input actually works."""
    try:
        out = list(fn(list(sol)))
    except SolverTimeout:
        raise
    except Exception:
        return False
    return len(out) == len(target) and all((int(v) & 0xff) == t for v, t in zip(out, target))


def symbolic_solve(source: str, target: bytes, length: int, charset: str, timeout_s: int):
    """Returns ("sat", bytes) | ("unverified", bytes) | ("unsat", None) | ("timeout", None)
    | ("timeout: transform", None) | ("error: <text>", None)."""
    try:
        return _symbolic_solve(source, target, length, charset, timeout_s)
    except SolverTimeout:
        return "timeout: transform", None


def _symbolic_solve(source: str, target: bytes, length: int, charset: str, timeout_s: int):
    import z3
    ns = {"Table": Table, "__name__": "transform_module"}
    _TABLES.clear()
    xs = [z3.BitVec(f"x{i}", WIDTH) for i in range(length)]
    with _time_limit(timeout_s):                    # phase 1: the user's Python (import + symbolic run)
        try:
            exec(compile(source, "transform.py", "exec"), ns)
        except SolverTimeout:
            raise
        except Exception as e:
            return f"error: the file failed to import: {type(e).__name__}: {e}", None
        fn = ns.get("transform")
        if not callable(fn):
            return "error: the file must define transform(x)", None
        try:
            out = fn([Sym(v) for v in xs])
            out = list(out)
        except SolverTimeout:
            raise
        except NotSymbolic as e:
            return f"error: not symbolic at {_where(source, e)} — {e}. Rewrite that line with arithmetic (masks, Table lookups) only.", None
        except Exception as e:
            return f"error: transform raised {type(e).__name__}: {e} at {_where(source, e)}", None
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
    for i, (o, tb_) in enumerate(zip(out, target)):
        ov = Sym._raw(o)
        if isinstance(ov, bool):
            ov = int(ov)
        if isinstance(ov, int):
            if (ov & 0xff) != tb_:
                return "unsat", None
            continue
        if not isinstance(ov, z3.BitVecRef):
            return f"error: transform must return ints, got {type(ov).__name__} at position {i}", None
        s.add((ov & 0xff) == tb_)
    r = s.check()                                   # z3's own timeout; no alarm armed here
    if r == z3.sat:
        m = s.model()
        sol = bytes(m.eval(x, model_completion=True).as_long() & 0xff for x in xs)
        with _time_limit(timeout_s):                # phase 2: the user's Python again (concrete re-check)
            ok = _concrete_matches(fn, sol, target)
        return ("sat" if ok else "unverified"), sol
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
    if status in ("sat", "unverified"):
        printable = "".join(chr(c) if 32 <= c < 127 else "." for c in sol)
        body = f"hex: {sol.hex()}\ntext: {printable}\ntarget: {tgt.hex()}\n"
        if status == "sat":
            return (f"[sat] input ({len(sol)} bytes)\n{body}verified: transform(input) == target\n"
                    f"Verify it on the real program before submit_flag (run_binary / run_gui).")
        return (f"[sat?] z3 found an input but transform(input) != target when run concretely — the symbolic "
                f"semantics diverged; do not trust it. {SEMANTICS} Other causes: `//` on a negative intermediate, "
                f"table width, index range.\n{body}")
    if status == "unsat":
        return ("[unsat] no input of that length maps to the target under this transform. Either the transform is "
                "not faithful (compare it against the real program on a known input), the length/charset is wrong, "
                f"or the symbolic semantics diverged from Python: {SEMANTICS}")
    if status == "timeout: transform":
        return (f"[timeout] the transform itself took longer than {timeout_s}s (importing the file, running it on "
                f"symbolic bytes, or re-checking the answer concretely) — not z3. Remove loops whose bounds are not "
                f"constants and keep transform to arithmetic and Table lookups.")
    if status == "timeout":
        return f"[timeout] z3 gave up after {timeout_s}s; simplify the transform or split the input into independent blocks."
    return f"[error] {status[len('error: '):]}"
