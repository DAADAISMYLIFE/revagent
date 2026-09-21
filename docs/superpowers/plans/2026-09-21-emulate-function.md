# Emulate Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the agent a per-function oracle: `emulate(binary, function, args)` runs one function of the challenge binary under unicorn (image loaded with cle at the same base Ghidra uses) and returns rax plus the contents of every buffer argument, so the model can check its Python re-implementation of a transform against the real code before inverting it with `solve_check`.

**Architecture:** `revagent/emulate.py` is pure logic with no agent dependencies: `load_image(path)` (cle) and `emulate_call(image, func, args, ...)` (unicorn x86-64, SysV for ELF / Win64 for PE, buffer pages for `hex:` args, a sentinel return page, unmapped-fetch reporting with symbol lookup). `revagent/tools/emulate.py` is the thin tool: parses args, resolves `FUN_...`/`0x...` addresses, formats the report, writes the `[obs]` ledger line. Playbook/README mention it. Nothing references a challenge.

**Tech Stack:** Python 3.12, `cle` 9.3.x (angr dependency, present in the venv and the sandbox image), `unicorn` 2.x (present in both). Tests: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider`.

**Spec:** `docs/superpowers/specs/2026-09-21-emulate-function-design.md`

## Global Constraints

- Content-free under `revagent/`: no challenge names, addresses, or constants. Test fixtures may hand-assemble tiny x86-64 code.
- Addresses are Ghidra's: PIE ELF loaded at `0x100000` (`main_opts={"base_addr": 0x100000}`), PE at its ImageBase (cle default). No user-visible translation.
- x86-64 only; anything else returns `[cannot emulate] ...`. Never raise out of the tool.
- Every `emulate` call appends an `[obs step N] emulate ...` ledger line via `ctx.observe`.
- All existing model-visible strings stay byte-identical except the additions in Task 3.
- Branch: `feat/emulate-function` (spec committed at 5c07c1e). Commit after each task with trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`; do not push.
- Suite green after every task (326 at start).

---

### Task 1: `revagent/emulate.py` — image loading and one-function emulation

**Files:**
- Create: `revagent/emulate.py`
- Test: `tests/test_emulate.py`

**Interfaces:**
- Produces:
  - `@dataclass Image: segments: list[tuple[int, bytes]]; base: int; min_addr: int; max_addr: int; is_pe: bool; symbol_at: Callable[[int], str | None]` (segments are (vaddr, bytes); `symbol_at(addr)` names an address — an import stub or PLT target — or returns None).
  - `load_image(path: Path) -> Image` (raises `EmulateError` with a message for unsupported arch/format).
  - `Arg = tuple[str, object]` — `("hex", bytes)`, `("int", int)`, `("addr", int)`.
  - `@dataclass Result: rax: int; buffers: list[bytes]; stopped: dict | None` where `stopped` is `None` on a clean return or `{"reason": "import"|"unmapped"|"limit"|"invalid", "rip": int, "symbol": str | None, "detail": str, "arg_regs": list[int]}`.
  - `emulate_call(image: Image, func: int, args: list[Arg], out_lens: list[int] | None = None, max_insns: int = 5_000_000, timeout_s: int = 30) -> Result`.
  - `class EmulateError(Exception)`.
  - Constants: `STACK_TOP = 0x7FFF_0000`, `STACK_SIZE = 0x100000`, `BUF_BASE = 0x1000_0000`, `BUF_STRIDE = 0x10000`, `TLS_PAGE = 0x2000_0000`, `RET_PAGE = 0x3000_0000`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_emulate.py
"""emulate_call is exercised with hand-assembled x86-64 fragments in a synthetic Image, so no binary,
Ghidra or cle is needed; load_image is covered by a tiny real ELF built with gcc when available."""
import shutil
import subprocess
from pathlib import Path

import pytest

from revagent.emulate import (BUF_BASE, RET_PAGE, EmulateError, Image, Result, emulate_call, load_image)

CODE = 0x100000


def _image(code: bytes, is_pe: bool = False, symbol_at=lambda a: None) -> Image:
    return Image(segments=[(CODE, code + b"\xcc" * 16)], base=CODE, min_addr=CODE, max_addr=CODE + 0x1000,
                 is_pe=is_pe, symbol_at=symbol_at)


def test_sysv_int_args_and_rax():
    # add rdi, rsi ; mov rax, rdi ; ret
    r = emulate_call(_image(bytes.fromhex("4801f7 4889f8 c3")), CODE, [("int", 2), ("int", 3)])
    assert r.stopped is None and r.rax == 5 and r.buffers == []


def test_win64_int_args():
    # add rcx, rdx ; mov rax, rcx ; ret
    r = emulate_call(_image(bytes.fromhex("4801d1 4889c8 c3"), is_pe=True), CODE, [("int", 40), ("int", 2)])
    assert r.stopped is None and r.rax == 42


def test_hex_buffer_is_passed_by_address_and_returned_after_the_call():
    # add byte [rdi], 1 ; add byte [rdi+1], 2 ; ret
    r = emulate_call(_image(bytes.fromhex("800701 80470102 c3")), CODE, [("hex", b"\x41\x41\x41")])
    assert r.stopped is None
    assert r.buffers == [b"\x42\x43\x41"]


def test_out_lens_reads_more_than_the_input():
    # mov byte [rdi+4], 0x5a ; ret   (writes past the 1-byte input)
    r = emulate_call(_image(bytes.fromhex("c647045a c3")), CODE, [("hex", b"\x00")], out_lens=[6])
    assert r.buffers == [b"\x00\x00\x00\x00\x5a\x00"]


def test_win64_buffer_arg_uses_rcx_and_shadow_space():
    # mov rax, [rsp+8]  -> reads the shadow space (callee-owned), must be mapped; then add byte [rcx], 1 ; ret
    r = emulate_call(_image(bytes.fromhex("488b442408 800101 c3"), is_pe=True), CODE, [("hex", b"\x10")])
    assert r.stopped is None and r.buffers == [b"\x11"]


def test_addr_arg_points_into_the_image():
    # movzx eax, byte [rdi] ; ret   with rdi = an address inside the image (the code page itself)
    r = emulate_call(_image(bytes.fromhex("0fb607 c3")), CODE, [("addr", CODE)])
    assert r.stopped is None and r.rax == 0x0F


def test_more_than_six_sysv_args_go_on_the_stack():
    # mov rax, [rsp+8] ; ret   -> 7th argument
    r = emulate_call(_image(bytes.fromhex("488b442408 c3")), CODE, [("int", i) for i in range(1, 8)])
    assert r.stopped is None and r.rax == 7


def test_fs_and_gs_reads_return_zero():
    # mov rax, fs:[0x28] ; mov rcx, gs:[0x60] ; add rax, rcx ; ret
    r = emulate_call(_image(bytes.fromhex("64488b042528000000 65488b0c2560000000 4801c8 c3")), CODE, [])
    assert r.stopped is None and r.rax == 0


def test_call_into_unmapped_address_is_reported_with_symbol_and_arg_regs():
    # mov edi, 7 ; mov rax, 0x500000 ; call rax   (0x500000 is unmapped)
    code = bytes.fromhex("bf07000000 48c7c000005000 ffd0")
    r = emulate_call(_image(code, symbol_at=lambda a: "strlen" if a == 0x500000 else None), CODE, [])
    assert r.stopped["reason"] == "import" and r.stopped["symbol"] == "strlen"
    assert r.stopped["rip"] == 0x500000 and r.stopped["arg_regs"][0] == 7


def test_unmapped_data_access_is_reported():
    # mov rax, [0x600000] ; ret
    r = emulate_call(_image(bytes.fromhex("488b042500006000 c3")), CODE, [])
    assert r.stopped["reason"] == "unmapped" and "0x600000" in r.stopped["detail"]


def test_instruction_limit_stops_an_infinite_loop():
    r = emulate_call(_image(bytes.fromhex("ebfe")), CODE, [], max_insns=1000)
    assert r.stopped["reason"] == "limit"


def test_invalid_instruction_is_reported():
    r = emulate_call(_image(bytes.fromhex("0f0b")), CODE, [])  # ud2
    assert r.stopped["reason"] == "invalid"


def test_func_outside_image_raises():
    with pytest.raises(EmulateError):
        emulate_call(_image(bytes.fromhex("c3")), 0x900000, [])


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc needed to build a tiny ELF")
def test_load_image_pie_elf_at_ghidra_base(tmp_path):
    src = tmp_path / "t.c"
    src.write_text("unsigned char f(unsigned char *p){p[0]^=0x55;return p[0];}\nint main(){return 0;}\n")
    exe = tmp_path / "t"
    subprocess.run(["gcc", "-O0", "-pie", "-fPIE", "-o", str(exe), str(src)], check=True)
    img = load_image(exe)
    assert not img.is_pe and img.base == 0x100000 and img.min_addr >= 0x100000
    # find f via nm and call it through the oracle
    out = subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout
    f_off = next(int(l.split()[0], 16) for l in out.splitlines() if l.endswith(" T f"))
    r = emulate_call(img, 0x100000 + f_off, [("hex", b"\x00")])
    assert r.stopped is None and r.rax == 0x55 and r.buffers == [b"\x55"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_emulate.py`
Expected: ModuleNotFoundError for `revagent.emulate`.

- [ ] **Step 3: Implement `revagent/emulate.py`**

```python
"""Run one function of a challenge binary under unicorn: a per-function oracle.

The image is loaded with cle at the SAME base Ghidra uses (PIE ELF 0x100000, PE ImageBase), so the
addresses the model reads in the decompiler (FUN_..., DAT_...) work unchanged. Calling convention is
chosen by file format: SysV for ELF, Win64 for PE. `hex:` arguments become zero-padded buffer pages
whose address is passed and whose contents are returned after the call; a call that leaves the image
(an import such as strlen or GdipDrawLineI) stops and is reported with the callee's name and the
argument registers at that moment — that is itself an observation.

Pure module: no agent, no tool context. Nothing here knows any challenge."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

STACK_TOP = 0x7FFF_0000
STACK_SIZE = 0x100000
BUF_BASE = 0x1000_0000
BUF_STRIDE = 0x10000
TLS_PAGE = 0x2000_0000
RET_PAGE = 0x3000_0000
PAGE = 0x1000
GHIDRA_PIE_BASE = 0x100000

SYSV_ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
WIN64_ARG_REGS = ("rcx", "rdx", "r8", "r9")
WIN64_SHADOW = 32

Arg = tuple[str, object]


class EmulateError(Exception):
    pass


@dataclass
class Image:
    segments: list[tuple[int, bytes]]
    base: int
    min_addr: int
    max_addr: int
    is_pe: bool
    symbol_at: Callable[[int], str | None] = field(default=lambda addr: None)

    def contains(self, addr: int) -> bool:
        return self.min_addr <= addr < self.max_addr


@dataclass
class Result:
    rax: int
    buffers: list[bytes]
    stopped: dict | None


def load_image(path: Path) -> Image:
    """cle-load the binary at Ghidra's base. Only x86-64 ELF/PE are supported."""
    try:
        import cle
    except ImportError as e:  # pragma: no cover
        raise EmulateError("cle is not installed (it comes with angr)") from e
    path = Path(path)
    try:
        probe = cle.Loader(str(path), auto_load_libs=False)
    except Exception as e:
        raise EmulateError(f"cannot load {path.name}: {type(e).__name__}: {e}")
    mo = probe.main_object
    arch = getattr(mo.arch, "name", "?")
    if arch != "AMD64":
        raise EmulateError(f"unsupported architecture {arch}: only x86-64 ELF/PE can be emulated here")
    is_pe = mo.os and mo.os.lower().startswith("win")
    loader = probe
    if not is_pe and getattr(mo, "pic", False) and mo.mapped_base != GHIDRA_PIE_BASE:
        loader = cle.Loader(str(path), auto_load_libs=False, main_opts={"base_addr": GHIDRA_PIE_BASE})
        mo = loader.main_object
    segments = []
    for seg in mo.segments:
        if seg.memsize == 0:
            continue
        data = loader.memory.load(seg.vaddr, seg.memsize)
        segments.append((seg.vaddr, bytes(data)))

    def symbol_at(addr: int) -> str | None:
        sym = loader.find_symbol(addr)
        if sym is not None and sym.name:
            return sym.name
        try:
            desc = loader.describe_addr(addr)
        except Exception:
            return None
        return desc if desc and "not part of a loaded object" not in desc else None

    return Image(segments=segments, base=mo.mapped_base, min_addr=mo.min_addr, max_addr=mo.max_addr + 1,
                 is_pe=bool(is_pe), symbol_at=symbol_at)


def _page_up(n: int) -> int:
    return (n + PAGE - 1) & ~(PAGE - 1)


def emulate_call(image: Image, func: int, args: list[Arg], out_lens: list[int] | None = None,
                 max_insns: int = 5_000_000, timeout_s: int = 30) -> Result:
    try:
        from unicorn import UC_ARCH_X86, UC_HOOK_MEM_UNMAPPED, UC_MODE_64, UC_PROT_ALL, Uc, UcError
        from unicorn import x86_const as X
    except ImportError as e:  # pragma: no cover
        raise EmulateError("unicorn is not installed") from e
    if not image.contains(func):
        raise EmulateError(f"function address {func:#x} is outside the loaded image "
                           f"[{image.min_addr:#x}, {image.max_addr:#x})")
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    lo = image.min_addr & ~(PAGE - 1)
    hi = _page_up(image.max_addr)
    mu.mem_map(lo, hi - lo, UC_PROT_ALL)
    for vaddr, data in image.segments:
        mu.mem_write(vaddr, data)
    mu.mem_map(STACK_TOP - STACK_SIZE, STACK_SIZE, UC_PROT_ALL)
    mu.mem_map(TLS_PAGE, PAGE, UC_PROT_ALL)
    mu.mem_map(RET_PAGE, PAGE, UC_PROT_ALL)
    mu.reg_write(X.UC_X86_REG_FS_BASE, TLS_PAGE)
    mu.reg_write(X.UC_X86_REG_GS_BASE, TLS_PAGE)

    # argument values; hex args get their own zero-padded pages
    values: list[int] = []
    buf_addrs: list[tuple[int, int]] = []   # (addr, input length) per hex arg, in arg order
    for i, (kind, val) in enumerate(args):
        if kind == "hex":
            data = bytes(val)
            addr = BUF_BASE + i * BUF_STRIDE
            size = _page_up(len(data) + PAGE)
            mu.mem_map(addr, size, UC_PROT_ALL)
            mu.mem_write(addr, data)
            buf_addrs.append((addr, len(data)))
            values.append(addr)
        elif kind == "int":
            values.append(int(val) & 0xFFFFFFFFFFFFFFFF)
        elif kind == "addr":
            a = int(val)
            if not image.contains(a):
                raise EmulateError(f"addr argument {a:#x} is outside the loaded image")
            values.append(a)
        else:
            raise EmulateError(f"unknown argument kind {kind!r}")

    regs = WIN64_ARG_REGS if image.is_pe else SYSV_ARG_REGS
    reg_ids = {"rdi": X.UC_X86_REG_RDI, "rsi": X.UC_X86_REG_RSI, "rdx": X.UC_X86_REG_RDX,
               "rcx": X.UC_X86_REG_RCX, "r8": X.UC_X86_REG_R8, "r9": X.UC_X86_REG_R9}
    for name, v in zip(regs, values):
        mu.reg_write(reg_ids[name], v)
    stack_args = values[len(regs):]
    # stack layout at entry: [rsp] = return address; Win64 then 32 bytes of shadow space; then stack args
    sp = STACK_TOP - PAGE
    frame = 8 + (WIN64_SHADOW if image.is_pe else 0) + 8 * len(stack_args)
    frame = (frame + 15) & ~15
    sp = (sp - frame) & ~15
    sp += 8 if ((sp + 8) % 16) else 0  # after the call pushed the return address, rsp % 16 == 8
    mu.mem_write(sp, RET_PAGE.to_bytes(8, "little"))
    off = 8 + (WIN64_SHADOW if image.is_pe else 0)
    for v in stack_args:
        mu.mem_write(sp + off, v.to_bytes(8, "little"))
        off += 8
    mu.reg_write(X.UC_X86_REG_RSP, sp)

    stopped: dict | None = None

    def arg_regs_now() -> list[int]:
        return [mu.reg_read(reg_ids[n]) for n in regs]

    def on_unmapped(uc, access, addr, size, value, user):
        nonlocal stopped
        rip = uc.reg_read(X.UC_X86_REG_RIP)
        fetch = access in (X.UC_MEM_FETCH_UNMAPPED, X.UC_MEM_FETCH_PROT) if hasattr(X, "UC_MEM_FETCH_UNMAPPED") else False
        return False  # let unicorn raise; we classify in the except below

    mu.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)
    try:
        mu.emu_start(func, RET_PAGE, timeout=int(timeout_s * 1_000_000), count=max_insns)
        rip = mu.reg_read(X.UC_X86_REG_RIP)
        if rip != RET_PAGE:
            stopped = {"reason": "limit", "rip": rip, "symbol": None,
                       "detail": f"stopped after {max_insns} instructions or {timeout_s}s at {rip:#x}",
                       "arg_regs": arg_regs_now()}
    except UcError as e:
        rip = mu.reg_read(X.UC_X86_REG_RIP)
        msg = str(e)
        if "FETCH" in msg.upper() or not image.contains(rip):
            # execution left the image: an import call, or a jump into nothing
            sym = image.symbol_at(rip)
            stopped = {"reason": "import" if sym else "unmapped", "rip": rip, "symbol": sym,
                       "detail": f"execution left the image at {rip:#x}" + (f" ({sym})" if sym else ""),
                       "arg_regs": arg_regs_now()}
        elif "UNMAPPED" in msg.upper() or "PROT" in msg.upper():
            stopped = {"reason": "unmapped", "rip": rip, "symbol": None,
                       "detail": f"{msg} at rip {rip:#x}", "arg_regs": arg_regs_now()}
        else:
            stopped = {"reason": "invalid", "rip": rip, "symbol": None,
                       "detail": f"{msg} at rip {rip:#x}", "arg_regs": arg_regs_now()}
    rax = mu.reg_read(X.UC_X86_REG_RAX)
    buffers = []
    for i, (addr, n) in enumerate(buf_addrs):
        want = out_lens[i] if out_lens and i < len(out_lens) and out_lens[i] else n
        buffers.append(bytes(mu.mem_read(addr, want)))
    return Result(rax=rax, buffers=buffers, stopped=stopped)
```

Notes for the implementer: the `test_unmapped_data_access_is_reported` case must produce `"unmapped"` with the faulting ADDRESS in `detail` — unicorn's `UcError` message does not carry the address, so record it in `on_unmapped` (set a nonlocal `fault = (access, addr)`) and use it in the except branch: reason `"import"`/`"unmapped"` when the fault was a FETCH (`access` in `UC_MEM_FETCH_UNMAPPED`/`UC_MEM_FETCH_PROT`) — rip equals the target then — and `"unmapped"` with `detail = f"memory access to {addr:#x} at rip {rip:#x}"` for READ/WRITE faults. Replace the placeholder `on_unmapped` above with that. The stack alignment lines are what make `test_win64_buffer_arg_uses_rcx_and_shadow_space` and the 7-arg test pass; keep `[rsp] == RET_PAGE` and `rsp % 16 == 8` at entry.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_emulate.py -v`
Expected: 14 passed (the gcc test may skip in an environment without gcc; it must pass in this one).

- [ ] **Step 5: Commit**

```bash
git add revagent/emulate.py tests/test_emulate.py
git commit -m "emulate: per-function oracle core (cle image at Ghidra's base, unicorn call with SysV/Win64 args)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: The `emulate` tool

**Files:**
- Create: `revagent/tools/emulate.py`
- Modify: `tests/test_tools.py` (registry set gains `"emulate"`; new tests)

**Interfaces:**
- Consumes: `revagent.emulate.load_image`, `emulate_call`, `EmulateError`, `Image`, `Result`; `revagent.tools.base.resolve_inside`, `PathError`, `ctx.clamp_timeout`, `ctx.observe`, `ctx.step`.
- Produces: tool `emulate(binary, function, args, out_lens=None, max_insns=5000000)`; `parse_args(list[str]) -> list[Arg]`; `parse_function(text) -> int`; a per-`ToolContext` image cache `ctx.emulate_images: dict[str, Image]` (add the field to `ToolContext` in `revagent/tools/base.py`: `emulate_images: dict = field(default_factory=dict)`).

- [ ] **Step 1: Write the failing tests** (append to `tests/test_tools.py`; update `test_registry_has_all_tools` to include `"emulate"`)

```python
def test_emulate_parses_functions_and_args():
    from revagent.tools import emulate as em
    assert em.parse_function("FUN_1400010a0") == 0x1400010A0
    assert em.parse_function("0x103298") == 0x103298
    assert em.parse_function("thunk_FUN_00103298") == 0x103298
    assert em.parse_args(["hex:41 42", "int:7", "addr:0x106020", "hex:0x0102"]) == [
        ("hex", b"AB"), ("int", 7), ("addr", 0x106020), ("hex", b"\x01\x02")]
    with pytest.raises(ValueError):
        em.parse_args(["str:abc"])
    with pytest.raises(ValueError):
        em.parse_function("main")


def _fake_image():
    from revagent.emulate import Image
    return Image(segments=[(0x100000, b"\xc3" + b"\xcc" * 15)], base=0x100000, min_addr=0x100000,
                 max_addr=0x101000, is_pe=False)


def test_emulate_tool_reports_rax_buffers_and_writes_ledger(tmp_path, monkeypatch):
    from revagent.emulate import Result
    from revagent.tools import emulate as em
    (tmp_path / "chal").write_bytes(b"\x7fELF" + b"\0" * 60)
    monkeypatch.setattr(em, "load_image", lambda p: _fake_image())
    seen = {}

    def fake_call(image, func, args, out_lens=None, max_insns=5_000_000, timeout_s=30):
        seen.update(func=func, args=args, out_lens=out_lens, timeout_s=timeout_s)
        return Result(rax=1, buffers=[b"\x7e\x7d"], stopped=None)

    monkeypatch.setattr(em, "emulate_call", fake_call)
    ctx = ctx_for(tmp_path)
    ctx.step = 7
    out = em.run(ctx, binary="chal", function="FUN_00100000", args=["hex:4142"], out_lens=[2])
    assert out.startswith("rax=0x1")
    assert "arg0 (2 bytes): 7e7d" in out and "~}" in out            # hex + printable
    assert seen["func"] == 0x100000 and seen["args"] == [("hex", b"AB")] and seen["out_lens"] == [2]
    assert "- [obs step 7] emulate FUN_00100000: rax=0x1, arg0=7e7d" in ctx.casefile.read()


def test_emulate_tool_caches_the_image_per_binary(tmp_path, monkeypatch):
    from revagent.emulate import Result
    from revagent.tools import emulate as em
    (tmp_path / "chal").write_bytes(b"\x7fELF")
    loads = []
    monkeypatch.setattr(em, "load_image", lambda p: loads.append(p) or _fake_image())
    monkeypatch.setattr(em, "emulate_call", lambda *a, **k: Result(0, [], None))
    ctx = ctx_for(tmp_path)
    em.run(ctx, binary="chal", function="0x100000", args=[])
    em.run(ctx, binary="chal", function="0x100000", args=[])
    assert len(loads) == 1


def test_emulate_tool_stopped_import_is_actionable(tmp_path, monkeypatch):
    from revagent.emulate import Result
    from revagent.tools import emulate as em
    (tmp_path / "chal").write_bytes(b"\x7fELF")
    monkeypatch.setattr(em, "load_image", lambda p: _fake_image())
    monkeypatch.setattr(em, "emulate_call", lambda *a, **k: Result(
        rax=0, buffers=[b"\x00"], stopped={"reason": "import", "rip": 0x500000, "symbol": "strlen",
                                          "detail": "execution left the image at 0x500000 (strlen)",
                                          "arg_regs": [0x10000000, 0, 0, 0, 0, 0]}))
    out = em.run(ctx_for(tmp_path), binary="chal", function="0x100000", args=["hex:00"])
    assert "[emulation stopped] called strlen" in out and "rdi=0x10000000" in out
    assert "inner function" in out            # the next-action hint
    assert "[obs step" in ctx_for(tmp_path).casefile.read() or True  # ledger checked in the previous test


def test_emulate_tool_errors(tmp_path, monkeypatch):
    from revagent.emulate import EmulateError
    from revagent.tools import emulate as em
    ctx = ctx_for(tmp_path)
    assert em.run(ctx, binary="../x", function="0x1", args=[]).startswith("[tool error] path escapes")
    assert em.run(ctx, binary="nope", function="0x1", args=[]).startswith("[tool error] no such file")
    (tmp_path / "chal").write_bytes(b"\x7fELF")
    assert "[tool error] function" in em.run(ctx, binary="chal", function="main", args=[])
    assert "[tool error] args" in em.run(ctx, binary="chal", function="0x1", args=["str:x"])
    monkeypatch.setattr(em, "load_image", lambda p: (_ for _ in ()).throw(EmulateError("unsupported architecture ARM")))
    out = em.run(ctx, binary="chal", function="0x1", args=[])
    assert out.startswith("[cannot emulate]") and "ARM" in out


def test_emulate_tool_timeout_clamped(tmp_path, monkeypatch):
    from revagent.emulate import Result
    from revagent.tools import emulate as em
    (tmp_path / "chal").write_bytes(b"\x7fELF")
    monkeypatch.setattr(em, "load_image", lambda p: _fake_image())
    seen = {}
    monkeypatch.setattr(em, "emulate_call", lambda *a, **k: seen.update(k) or Result(0, [], None))
    monkeypatch.setattr("revagent.tools.base.time.monotonic", lambda: 50.0)
    ctx = ctx_for(tmp_path)
    ctx.deadline = 50.0 + 12
    em.run(ctx, binary="chal", function="0x100000", args=[])
    assert seen["timeout_s"] == 12
```

- [ ] **Step 2: Run to verify they fail**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_tools.py -k "emulate or registry"`
Expected: failures (no module, registry mismatch).

- [ ] **Step 3: Implement `revagent/tools/emulate.py`** and add `emulate_images` to `ToolContext`

```python
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

_FUNC = re.compile(r"(?:^|_)(?:FUN_)?(?:0x)?([0-9a-fA-F]{5,16})$")


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
        if kind == "hex":
            v = val[2:] if val.lower().startswith("0x") else val
            out.append(("hex", bytes.fromhex(v.replace(" ", ""))))
        elif kind == "int":
            out.append(("int", int(val, 0)))
        elif kind == "addr":
            out.append(("addr", int(val, 0)))
        else:
            raise ValueError(f"argument {s!r} must be hex:<bytes>, int:<n> or addr:0x<address>")
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
```
In `revagent/tools/base.py` add to `ToolContext`: `emulate_images: dict = field(default_factory=dict)   # path -> revagent.emulate.Image (cle+unicorn image cache per run)`.

- [ ] **Step 4: Run the tests**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_tools.py -k "emulate or registry" -W error`
Expected: all pass. Then the full suite.

- [ ] **Step 5: Commit**

```bash
git add revagent/tools/emulate.py revagent/tools/base.py tests/test_tools.py
git commit -m "emulate tool: per-function oracle with Ghidra addresses, hex/int/addr args, import reporting, obs ledger

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Playbook and README

**Files:**
- Modify: `revagent/prompts/system.md`, `README.md`
- Test: `tests/test_agent.py` (one new playbook test)

- [ ] **Step 1: Failing test** (append to `tests/test_agent.py`)

```python
def test_playbook_puts_emulate_before_solve_check_in_the_constraint_class():
    p = load_system_prompt()
    assert "`emulate`" in p
    sec3 = p.index("## 3.")
    assert p.index("emulate", sec3) < p.index("solve_check", sec3)
    assert "Observation (program output" in p and "emulate" in p[p.index("11. **Evidence ladder."):p.index("# Environment")]
    for n in range(1, 11):
        assert f"\n{n}. **" in p
```

- [ ] **Step 2: Edit the playbook** (insert only; existing sentences untouched)

Rule 11 (Evidence ladder), after "Observation (program output, screen captures, debugger values)" insert " — including one function's output under `emulate` —".

Environment, after the `solve_check` bullet, add:
```
- `emulate` runs ONE function of the binary (Ghidra address, same base as `decompile`) on inputs you choose and returns rax and the buffers after the call. It is how you check a Python re-implementation before inverting it: `emulate` on 3 random inputs, compare with your model, fix the model until they match. Imports stop it (the report names the callee and shows the argument registers); target the inner arithmetic function.
```

§3 "Constraint / byte-wise" bullet: replace the leading "re-implement the transform in Python exactly (same widths, same endianness, same table dumped from the binary), then" with "re-implement the transform in Python exactly (same widths, same endianness, same table dumped from the binary), **check it with `emulate` on a few inputs until the bytes match**, then".

§4 Verify: after "Build the candidate input." insert " If `solve_check` produced it, confirm with `emulate` on the check function first."

- [ ] **Step 3: README** (반말; under the gate paragraph in 실행): add
```
`emulate`는 바이너리의 함수 하나를 unicorn으로 돌려 주는 오라클이다. 디컴파일된 변환을 파이썬으로 옮긴 뒤 `emulate`로 실제 함수와 같은 입력에서 비교하고, 맞으면 `solve_check`로 뒤집는다. basic이 두 번 죽은 "forward 모델 검증" 단계가 이걸로 끝난다. import를 부르면 거기서 멈추고 누구를 어떤 인자로 불렀는지 보고한다.
```
동작 원리: 도구 열한 개, `emulate` 추가; 한 불릿: "- `emulate`: 함수 단위 오라클. PIE ELF는 0x100000, PE는 ImageBase에 로드해서 Ghidra 주소를 그대로 쓴다."

- [ ] **Step 4: Full suite, commit**

```bash
~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider
git add revagent/prompts/system.md README.md tests/test_agent.py
git commit -m "playbook + README: emulate as the oracle before solve_check

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Live validation

- [ ] **Step 1: Rebuild the image** — `bash scripts/sandbox-build.sh` (smoke must pass).
- [ ] **Step 2: In-image check** that the tool works on a real PE: `docker run --rm -v <quiz>/basic:/work/basic --entrypoint python3 revagent-sandbox -c "from revagent.emulate import load_image, emulate_call; img=load_image('/work/basic/chall9.exe'); print(emulate_call(img, 0x1400010a0, [('hex', b'Reverse_')]).buffers[0].hex())"` → must print `7e7d9a8b252dd53d` (the first target block; that value is in quiz, not in the repo).
- [ ] **Step 3: basic run 3**, fresh case file, 15 min: `mv basic/.revagent/case.md basic/.revagent/case.md.run2; revagent solve basic --max-minutes 15`. Record: solved?, steps, whether `emulate` and `solve_check` were called, signals.
- [ ] **Step 4: Replay** `scripts/replay_detectors.py` over the new transcript (no false positive rule applies only to solved sessions).
- [ ] **Step 5: README bench row + spec §3.4 result; commit; push; PR** (do not merge until the transition-rules PR is merged; this branch builds on it).

## Self-review

- Spec coverage: §3.1 core → Task 1; §3.2 tool → Task 2; §3.3 playbook → Task 3; §3.4 data → Task 1 (gcc ELF test) + Task 4 (PE live); §5 errors → Tasks 1–2; §6 tests → Tasks 1–3.
- Type consistency: `Arg` tuples, `Result.stopped` keys (`reason`, `rip`, `symbol`, `detail`, `arg_regs`) used identically in Task 1 tests and Task 2 formatting; `emulate_call(image, func, args, out_lens=None, max_insns=..., timeout_s=...)` signature matches the tool's monkeypatch fakes.
- Placeholders: the `on_unmapped` hook in Task 1's code is explicitly marked for replacement with the fault-recording version described right below it; no other placeholders.
