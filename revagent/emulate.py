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
MASK64 = 0xFFFF_FFFF_FFFF_FFFF

SYSV_ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
WIN64_ARG_REGS = ("rcx", "rdx", "r8", "r9")
WIN64_SHADOW = 32

Arg = tuple[str, object]


class EmulateError(Exception):
    pass


@dataclass
class Image:
    segments: list[tuple[int, bytes]]   # (vaddr, bytes) as loaded, relocations applied
    base: int
    min_addr: int
    max_addr: int                       # exclusive
    is_pe: bool
    symbol_at: Callable[[int], "str | None"] = field(default=lambda addr: None)

    def contains(self, addr: int) -> bool:
        return self.min_addr <= addr < self.max_addr


@dataclass
class Result:
    rax: int
    buffers: list[bytes]
    stopped: "dict | None"   # None on a clean return, else {reason, rip, symbol, detail, arg_regs}


def load_image(path: Path) -> Image:
    """cle-load the binary at Ghidra's base. Only x86-64 ELF/PE are supported."""
    try:
        import cle
    except ImportError as e:  # pragma: no cover
        raise EmulateError("cle is not installed (it comes with angr)") from e
    path = Path(path)
    try:
        loader = cle.Loader(str(path), auto_load_libs=False)
    except Exception as e:
        raise EmulateError(f"cannot load {path.name}: {type(e).__name__}: {e}") from e
    mo = loader.main_object
    arch = getattr(mo.arch, "name", "?")
    if arch != "AMD64":
        raise EmulateError(f"unsupported architecture {arch}: only x86-64 ELF/PE can be emulated here")
    os_name = (getattr(mo, "os", None) or "").lower()
    is_pe = os_name.startswith("win") or type(mo).__name__ == "PE"
    if not is_pe and not type(mo).__name__.startswith("ELF"):
        raise EmulateError(f"unsupported format {type(mo).__name__}: only x86-64 ELF/PE can be emulated here")
    if not is_pe and getattr(mo, "pic", False) and mo.mapped_base != GHIDRA_PIE_BASE:
        # cle's default PIE base is 0x400000; Ghidra loads PIE ELFs at 0x100000
        try:
            loader = cle.Loader(str(path), auto_load_libs=False, main_opts={"base_addr": GHIDRA_PIE_BASE})
        except Exception as e:
            raise EmulateError(f"cannot load {path.name} at {GHIDRA_PIE_BASE:#x}: "
                               f"{type(e).__name__}: {e}") from e
        mo = loader.main_object

    segments: list[tuple[int, bytes]] = []
    for seg in mo.segments:
        if seg.memsize == 0:
            continue
        try:
            data = loader.memory.load(seg.vaddr, seg.memsize)
        except Exception:
            # sparse/short backing: read what is there and zero-fill the rest
            data = _load_sparse(loader.memory, seg.vaddr, seg.memsize)
        if len(data) < seg.memsize:
            data = bytes(data) + b"\0" * (seg.memsize - len(data))
        segments.append((seg.vaddr, bytes(data)))

    def symbol_at(addr: int) -> "str | None":
        try:
            sym = loader.find_symbol(addr)
        except Exception:
            sym = None
        if sym is not None and getattr(sym, "name", None):
            return sym.name
        try:
            desc = loader.describe_addr(addr)
        except Exception:
            return None
        return desc if desc and "not part of a loaded object" not in desc else None

    return Image(segments=segments, base=mo.mapped_base, min_addr=mo.min_addr, max_addr=mo.max_addr + 1,
                 is_pe=bool(is_pe), symbol_at=symbol_at)


def _load_sparse(memory, vaddr: int, size: int) -> bytes:
    out = bytearray(size)
    for off in range(0, size, PAGE):
        n = min(PAGE, size - off)
        try:
            chunk = memory.load(vaddr + off, n)
        except Exception:
            continue
        out[off:off + len(chunk)] = chunk
    return bytes(out)


def _page_up(n: int) -> int:
    return (n + PAGE - 1) & ~(PAGE - 1)


def emulate_call(image: Image, func: int, args: list[Arg], out_lens: "list[int] | None" = None,
                 max_insns: int = 5_000_000, timeout_s: int = 30) -> Result:
    """Call `func` once with `args` and return rax, the hex buffers after the call, and why it stopped."""
    try:
        import unicorn
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
        if data:
            mu.mem_write(vaddr, data)
    mu.mem_map(STACK_TOP - STACK_SIZE, STACK_SIZE, UC_PROT_ALL)
    mu.mem_map(TLS_PAGE, PAGE, UC_PROT_ALL)     # fs:/gs: reads (canary, TEB) see zeros
    mu.mem_map(RET_PAGE, PAGE, UC_PROT_ALL)     # the sentinel return address
    mu.reg_write(X.UC_X86_REG_FS_BASE, TLS_PAGE)
    mu.reg_write(X.UC_X86_REG_GS_BASE, TLS_PAGE)

    # argument values; hex args get their own zero-padded pages
    values: list[int] = []
    bufs: list[tuple[int, int, int]] = []   # (addr, input length, mapped size) per hex arg, in arg order
    for i, (kind, val) in enumerate(args):
        if kind == "hex":
            data = bytes(val)
            addr = BUF_BASE + i * BUF_STRIDE
            size = _page_up(len(data) + PAGE)
            if size > BUF_STRIDE:
                raise EmulateError(f"hex argument {i} is too large ({len(data)} bytes; "
                                   f"limit {BUF_STRIDE - PAGE})")
            mu.mem_map(addr, size, UC_PROT_ALL)
            if data:
                mu.mem_write(addr, data)
            bufs.append((addr, len(data), size))
            values.append(addr)
        elif kind == "int":
            values.append(int(val) & MASK64)
        elif kind == "addr":
            a = int(val)
            if not image.contains(a):
                raise EmulateError(f"addr argument {a:#x} is outside the loaded image "
                                   f"[{image.min_addr:#x}, {image.max_addr:#x})")
            values.append(a)
        else:
            raise EmulateError(f"unknown argument kind {kind!r} (expected hex, int or addr)")

    regs = WIN64_ARG_REGS if image.is_pe else SYSV_ARG_REGS
    reg_ids = {"rdi": X.UC_X86_REG_RDI, "rsi": X.UC_X86_REG_RSI, "rdx": X.UC_X86_REG_RDX,
               "rcx": X.UC_X86_REG_RCX, "r8": X.UC_X86_REG_R8, "r9": X.UC_X86_REG_R9}
    for name, v in zip(regs, values):
        mu.reg_write(reg_ids[name], v)
    stack_args = values[len(regs):]

    # Stack at entry, as if the caller had just executed `call`: [rsp] = return address (RET_PAGE) and
    # rsp % 16 == 8. Win64: 32 bytes of callee-owned shadow space at [rsp+8, rsp+40), stack args from
    # [rsp+40]; SysV: stack args from [rsp+8]. Everything above rsp stays below STACK_TOP.
    shadow = WIN64_SHADOW if image.is_pe else 0
    above = 8 + shadow + 8 * len(stack_args)            # bytes from rsp up to the last stack arg
    room = _page_up(above + 8)                          # page-rounded, so sp keeps STACK_TOP's alignment
    if room >= STACK_SIZE // 2:
        raise EmulateError(f"too many stack arguments ({len(stack_args)})")
    sp = STACK_TOP - room - 8                           # STACK_TOP and room are 16-aligned -> sp % 16 == 8
    mu.mem_write(sp, RET_PAGE.to_bytes(8, "little"))
    off = 8 + shadow
    for v in stack_args:
        mu.mem_write(sp + off, v.to_bytes(8, "little"))
        off += 8
    mu.reg_write(X.UC_X86_REG_RSP, sp)

    fetch_kinds = {unicorn.UC_MEM_FETCH_UNMAPPED, unicorn.UC_MEM_FETCH_PROT}
    fault: "tuple[int, int] | None" = None   # (access kind, address) of the first unmapped access

    def arg_regs_now() -> list[int]:
        return [mu.reg_read(reg_ids[n]) for n in regs]

    def on_unmapped(uc, access, addr, size, value, user):
        nonlocal fault
        if fault is None:
            fault = (access, addr)
        return False   # let unicorn raise; classified in the except branch below

    mu.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)
    stopped: "dict | None" = None
    try:
        mu.emu_start(func, RET_PAGE, timeout=int(timeout_s * 1_000_000), count=max_insns)
        rip = mu.reg_read(X.UC_X86_REG_RIP)
        if rip != RET_PAGE:
            stopped = {"reason": "limit", "rip": rip, "symbol": None,
                       "detail": f"stopped after {max_insns} instructions or {timeout_s}s at {rip:#x}",
                       "arg_regs": arg_regs_now()}
    except UcError as e:
        rip = mu.reg_read(X.UC_X86_REG_RIP)
        if fault is not None and fault[0] in fetch_kinds:
            # execution left the image: an import call (IAT/PLT target) or a jump into nothing
            rip = fault[1]
            sym = image.symbol_at(rip)
            stopped = {"reason": "import" if sym else "unmapped", "rip": rip, "symbol": sym,
                       "detail": f"execution left the image at {rip:#x}" + (f" ({sym})" if sym else ""),
                       "arg_regs": arg_regs_now()}
        elif fault is not None:
            stopped = {"reason": "unmapped", "rip": rip, "symbol": None,
                       "detail": f"memory access to {fault[1]:#x} at rip {rip:#x}",
                       "arg_regs": arg_regs_now()}
        else:
            stopped = {"reason": "invalid", "rip": rip, "symbol": None,
                       "detail": f"{e} at rip {rip:#x}", "arg_regs": arg_regs_now()}

    rax = mu.reg_read(X.UC_X86_REG_RAX)
    buffers: list[bytes] = []
    for i, (addr, n, size) in enumerate(bufs):
        want = out_lens[i] if out_lens and i < len(out_lens) and out_lens[i] else n
        want = max(0, min(int(want), size))
        buffers.append(bytes(mu.mem_read(addr, want)) if want else b"")
    return Result(rax=rax, buffers=buffers, stopped=stopped)
