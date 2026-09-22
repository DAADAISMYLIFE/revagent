"""Aggregate a qemu-user execution trace (`-d exec,nochain,page`) into what a reverse engineer wants
to read: which mapped regions executed how many translation blocks, the hottest addresses, and the
sequence of executed block addresses with consecutive repeats folded.

Addresses are reported the way Ghidra shows them: a PIE ELF is rebased from qemu's guest base to
0x100000, a non-PIE ELF keeps its link addresses. Addresses outside the main image (an mmap'd
region, a library) are left as qemu printed them.

Pure module: no agent, no tool context, no subprocess. Nothing here knows any challenge, only the
qemu log format and the ELF header."""
import re
import struct
from dataclasses import dataclass
from typing import NamedTuple

GHIDRA_PIE_BASE = 0x100000
PAGE = 0x1000
EM_X86_64 = 62
ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
DEFAULT_MAX_K = 16

Item = tuple[tuple[int, ...], int]   # (addresses, consecutive repeat count)


class TraceError(Exception):
    """str(e) is the reason text used after `[cannot trace]`."""


class Mapping(NamedTuple):
    start: int
    end: int      # exclusive
    prot: str     # 'r-x', 'rw-', 'rwx', '---', ...


@dataclass
class Trace:
    pcs: list[int]                                   # guest pc of every executed TB, in order
    layouts: list[tuple[int, list[Mapping]]]         # (number of Trace lines seen before the block, mappings)

    @property
    def mappings(self) -> list[Mapping]:
        """The final page layout (the last block printed)."""
        return list(self.layouts[-1][1]) if self.layouts else []

    @property
    def initial_mappings(self) -> list[Mapping]:
        """The layout in force before the first Trace line."""
        return layout_before_trace(self, 0)


def layout_before_trace(trace: Trace, idx: int) -> list[Mapping]:
    """The mappings in force when TB number `idx` executed: the last layout block printed after
    at most `idx` Trace lines."""
    chosen: list[Mapping] = []
    for n_before, maps in trace.layouts:
        if n_before <= idx:
            chosen = maps
        else:
            break
    return list(chosen)


_TRACE_LINE = re.compile(r"^Trace \d+: 0x[0-9a-fA-F]+ \[[0-9a-fA-F]+/([0-9a-fA-F]+)/")
_MAP_LINE = re.compile(r"^([0-9a-f]{8,16})-([0-9a-f]{8,16}) [0-9a-f]{8,16} ([rwx-]{3})\s*$")


def parse_qemu_log(text: str) -> Trace:
    pcs: list[int] = []
    layouts: list[tuple[int, list[Mapping]]] = []
    block: list[Mapping] | None = None
    for line in text.splitlines():
        if line.startswith("page layout changed"):
            block = []
            layouts.append((len(pcs), block))
            continue
        if block is not None:
            m = _MAP_LINE.match(line)
            if m:
                block.append(Mapping(int(m.group(1), 16), int(m.group(2), 16), m.group(3)))
                continue
            if line.startswith("start "):   # the column header of the block
                continue
            block = None
        m = _TRACE_LINE.match(line)
        if m:
            pcs.append(int(m.group(1), 16))
    return Trace(pcs=pcs, layouts=layouts)


@dataclass
class ElfInfo:
    machine: int
    e_type: int
    entry: int
    vaddr_lo: int     # page-floored lowest PT_LOAD vaddr
    vaddr_hi: int     # page-ceiled highest PT_LOAD vaddr + memsz

    @property
    def is_pie(self) -> bool:
        return self.e_type == ET_DYN

    @property
    def size(self) -> int:
        return self.vaddr_hi - self.vaddr_lo


def parse_elf_header(data: bytes) -> ElfInfo:
    """ELF64 header + program headers with struct only. Raises TraceError with the reason for
    anything that is not a 64-bit little-endian x86-64 ELF executable."""
    if data[:2] == b"MZ":
        raise TraceError("PE (Windows) binary: qemu-user cannot trace it (it runs under wine); use run_binary/run_gui")
    if data[:2] == b"#!":
        raise TraceError("script (#!): only ELF executables are traced; run the interpreter binary instead")
    if data[:4] != b"\x7fELF":
        raise TraceError("not an ELF file")
    if len(data) < 64:
        raise TraceError("ELF header truncated")
    if data[4] != 2:
        raise TraceError("32-bit ELF: only x86-64 ELF is traced")
    if data[5] != 1:
        raise TraceError("big-endian ELF: only x86-64 ELF is traced")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    e_entry, e_phoff = struct.unpack_from("<QQ", data, 24)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    if e_machine != EM_X86_64:
        raise TraceError(f"ELF e_machine {e_machine} is not x86-64 (62): only x86-64 ELF is traced here; "
                         f"for another architecture run qemu-<arch>-static -d exec,nochain,page via bash")
    if e_type not in (ET_EXEC, ET_DYN):
        raise TraceError(f"ELF e_type {e_type} is not an executable")
    lo, hi = None, None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 56 > len(data):
            break
        p_type, _flags, _off, p_vaddr, _paddr, _filesz, p_memsz, _align = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type != PT_LOAD:
            continue
        lo = p_vaddr if lo is None else min(lo, p_vaddr)
        hi = p_vaddr + p_memsz if hi is None else max(hi, p_vaddr + p_memsz)
    if lo is None:
        raise TraceError("ELF has no PT_LOAD segment")
    lo &= ~(PAGE - 1)
    hi = (hi + PAGE - 1) & ~(PAGE - 1)
    return ElfInfo(machine=e_machine, e_type=e_type, entry=e_entry, vaddr_lo=lo, vaddr_hi=hi)


def _run_start(mappings: list[Mapping], m: Mapping) -> int:
    """Start of the contiguous run of mappings that `m` belongs to."""
    by_end = {x.end: x for x in mappings}
    cur = m
    while cur.start in by_end:
        cur = by_end[cur.start]
    return cur.start


def find_image_base(mappings: list[Mapping], pcs: set[int], e_entry: int, is_pie: bool) -> tuple[int, bool]:
    """(base, guessed). PIE: the mapping start such that start + e_entry was executed; if the entry
    never ran (immediate crash) the start of the first executable run of mappings, flagged guessed.
    Non-PIE: (0, False) — no rebasing."""
    if not is_pie:
        return 0, False
    for m in sorted(mappings):
        if m.start + e_entry in pcs:
            return m.start, False
    for m in sorted(mappings):
        if "x" in m.prot:
            return _run_start(mappings, m), True
    return 0, True


@dataclass
class ImageInfo:
    lo: int          # guest address of the image start
    hi: int          # exclusive
    is_pie: bool
    guessed: bool
    entry: int       # guest address of the ELF entry point

    @property
    def ghidra_lo(self) -> int:
        return GHIDRA_PIE_BASE if self.is_pie else self.lo

    @property
    def ghidra_hi(self) -> int:
        return self.ghidra_lo + (self.hi - self.lo)


def locate_image(elf: ElfInfo, trace: Trace, known_base: int | None = None) -> ImageInfo:
    if not elf.is_pie:
        return ImageInfo(lo=elf.vaddr_lo, hi=elf.vaddr_hi, is_pie=False, guessed=False, entry=elf.entry)
    if known_base is not None:
        base, guessed = known_base, False
    else:
        base, guessed = find_image_base(trace.mappings, set(trace.pcs), elf.entry, True)
    return ImageInfo(lo=base + elf.vaddr_lo, hi=base + elf.vaddr_hi, is_pie=True, guessed=guessed,
                     entry=base + elf.entry)


def to_ghidra(pc: int, image_base: int, image_end: int, is_pie: bool) -> int | None:
    """Ghidra's address for a guest pc inside the image, None outside it."""
    if not (image_base <= pc < image_end):
        return None
    return pc - image_base + GHIDRA_PIE_BASE if is_pie else pc


def display_addr(pc: int, image: ImageInfo) -> int:
    g = to_ghidra(pc, image.lo, image.hi, image.is_pie)
    return pc if g is None else g


def from_ghidra(addr: int, image_lo: int, image_size: int, is_pie: bool) -> int:
    """Inverse of display_addr for a range bound: a Ghidra address inside the PIE image goes back
    to the guest address; anything else is already a guest address."""
    if is_pie and GHIDRA_PIE_BASE <= addr < GHIDRA_PIE_BASE + image_size:
        return addr - GHIDRA_PIE_BASE + image_lo
    return addr


@dataclass
class Region:
    kind: str        # 'image' | 'lib?' | 'anon rwx' | 'anon'
    start: int
    end: int
    prot: str
    count: int = 0   # executed TBs, filled by count_regions

    def contains(self, pc: int) -> bool:
        return self.start <= pc < self.end


def classify_regions(mappings: list[Mapping], initial_mappings: list[Mapping], image: ImageInfo) -> list[Region]:
    """One region per executable mapping outside the image, plus the image itself. A mapping that
    already existed in `initial_mappings` is a library ('lib?'); one created later is 'anon rwx'
    when writable and executable, else 'anon'."""
    regions = [Region("image", image.lo, image.hi, "")]
    initial = {(m.start, m.end) for m in initial_mappings}
    for m in mappings:
        if "x" not in m.prot:
            continue
        if m.start >= image.lo and m.end <= image.hi:
            continue
        if (m.start, m.end) in initial:
            kind = "lib?"
        elif "w" in m.prot:
            kind = "anon rwx"
        else:
            kind = "anon"
        regions.append(Region(kind, m.start, m.end, m.prot))
    regions.sort(key=lambda r: r.start)
    return regions


def region_of(regions: list[Region], pc: int) -> Region | None:
    for r in regions:
        if r.contains(pc):
            return r
    return None


def count_regions(regions: list[Region], pcs: list[int]) -> int:
    """Fill Region.count from the pcs; returns the number of pcs in no region."""
    for r in regions:
        r.count = 0
    other = 0
    cache: dict[int, Region | None] = {}
    for pc in pcs:
        r = cache.get(pc)
        if r is None and pc not in cache:
            r = region_of(regions, pc)
            cache[pc] = r
        if r is None:
            other += 1
        else:
            r.count += 1
    return other


def initial_layout(trace: Trace, image: ImageInfo) -> list[Mapping]:
    """The mappings present when the image's entry point first ran (libraries the dynamic loader
    mapped before handing over count as present); before the first Trace line if it never ran."""
    try:
        idx = trace.pcs.index(image.entry)
    except ValueError:
        idx = 0
    return layout_before_trace(trace, idx)
