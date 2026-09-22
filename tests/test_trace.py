"""revagent.trace is exercised on a synthetic qemu-user log shaped like the real `-d exec,nochain,page`
output (host mmap_min_addr line, page layout blocks, Trace lines) and on ELF headers built with struct."""
import struct

import pytest

from revagent.trace import (GHIDRA_PIE_BASE, Analysis, ImageInfo, Mapping, Region, TraceError, analyze,
                            classify_regions, compress, count_regions, find_image_base, from_ghidra, full_listing,
                            initial_layout, item_text, layout_before_trace, locate_image, parse_elf_header,
                            parse_qemu_log, render, summarize, to_ghidra)

QEMU_LOG = """host mmap_min_addr=0x10000
Locating guest address space @ 0x0
page layout changed following mmap
start            end              size             prot
0000004000000000-0000004000001000 0000000000001000 r-x
0000004000001000-0000004000200000 00000000001ff000 ---
0000004000200000-0000004000202000 0000000000002000 rw-
0000004000202000-0000004000203000 0000000000001000 rw-
0000004001000000-0000004001040000 0000000000040000 r-x
0000004001040000-0000004001050000 0000000000010000 rw-
ffffffffff600000-ffffffffff601000 0000000000001000 --x
Trace 0: 0x7e43d4000100 [0000000000000000/0000004001000a00/1040c0b3/00000200]
Trace 0: 0x7e43d4000200 [0000000000000000/0000004001000a20/1040c0b3/00000200]
Trace 0: 0x7e43d4000300 [0000000000000000/0000004000000100/1040c0b3/00000200]
Trace 0: 0x7e43d4000400 [0000000000000000/0000004000000140/1040c0b3/00000200]
page layout changed following mmap
start            end              size             prot
0000004000000000-0000004000001000 0000000000001000 r-x
0000004000001000-0000004000200000 00000000001ff000 ---
0000004000200000-0000004000202000 0000000000002000 rw-
0000004000202000-0000004000203000 0000000000001000 rw-
0000004001000000-0000004001040000 0000000000040000 r-x
0000004001040000-0000004001050000 0000000000010000 rw-
0000004001100000-0000004001101000 0000000000001000 rwx
ffffffffff600000-ffffffffff601000 0000000000001000 --x
Trace 0: 0x7e43d4000500 [0000000000000000/0000004000000180/1040c0b3/00000200]
Trace 0: 0x7e43d4000600 [0000000000000000/0000004001100000/1040c0b3/00000200]
Trace 0: 0x7e43d4000700 [0000000000000000/00000040000001a0/1040c0b3/00000200]
Trace 0: 0x7e43d4000600 [0000000000000000/0000004001100000/1040c0b3/00000200]
Trace 0: 0x7e43d4000700 [0000000000000000/00000040000001a0/1040c0b3/00000200]
Trace 0: 0x7e43d4000600 [0000000000000000/0000004001100000/1040c0b3/00000200]
Trace 0: 0x7e43d4000700 [0000000000000000/00000040000001a0/1040c0b3/00000200]
Trace 0: 0x7e43d4000800 [0000000000000000/00000040000001c0/1040c0b3/00000200]
Trace 0: 0x7e43d4000200 [0000000000000000/0000004001000a20/1040c0b3/00000200]
Trace 0: 0x7e43d4000900 [0000000000000000/0000004001000b00/1040c0b3/00000200]
"""

IMAGE = 0x4000000000
LIB = 0x4001000000
ANON = 0x4001100000
E_ENTRY = 0x100


def make_elf64(e_type: int = 3, machine: int = 62, entry: int = E_ENTRY,
               loads=((0, 0x1000), (0x200000, 0x3000)), ei_class: int = 2, phoff: int = 64) -> bytes:
    """A minimal ELF64 header + PT_LOAD program headers (no sections, no code). `phoff` places the
    program headers past the 64-byte header (zero padding in between)."""
    phnum = len(loads)
    ident = b"\x7fELF" + bytes([ei_class, 1, 1, 0]) + b"\0" * 8
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", e_type, machine, 1, entry, phoff, 0, 0, 64, 56, phnum, 64, 0, 0)
    phdrs = b"".join(struct.pack("<IIQQQQQQ", 1, 5, vaddr, vaddr, vaddr, size, size, 0x1000) for vaddr, size in loads)
    return ehdr + b"\0" * (phoff - 64) + phdrs


def _image() -> ImageInfo:
    return ImageInfo(lo=IMAGE, hi=IMAGE + 0x203000, is_pie=True, guessed=False, entry=IMAGE + E_ENTRY)


def test_parser_extracts_guest_pcs_in_order():
    t = parse_qemu_log(QEMU_LOG)
    assert len(t.pcs) == 14
    assert t.pcs[:3] == [LIB + 0xA00, LIB + 0xA20, IMAGE + 0x100]
    assert t.pcs[-1] == LIB + 0xB00


def test_parser_keeps_initial_and_final_layouts():
    t = parse_qemu_log(QEMU_LOG)
    assert [n for n, _ in t.layouts] == [0, 4]
    assert Mapping(ANON, ANON + 0x1000, "rwx") not in t.initial_mappings
    assert Mapping(ANON, ANON + 0x1000, "rwx") in t.mappings
    assert Mapping(IMAGE, IMAGE + 0x1000, "r-x") in t.initial_mappings
    assert t.initial_mappings[-1] == Mapping(0xFFFFFFFFFF600000, 0xFFFFFFFFFF601000, "--x")
    assert layout_before_trace(t, 3) == t.initial_mappings
    assert layout_before_trace(t, 4) == t.mappings


def test_parser_tolerates_noise_and_empty_input():
    assert parse_qemu_log("").pcs == [] and parse_qemu_log("").mappings == []
    t = parse_qemu_log("garbage\nTrace 1: 0x1 [0/00000000deadbeef/0/0]\nqemu: uncaught target signal 11\n")
    assert t.pcs == [0xDEADBEEF]


def test_find_image_base_pie_uses_the_entry_point():
    t = parse_qemu_log(QEMU_LOG)
    assert find_image_base(t.mappings, set(t.pcs), E_ENTRY, True) == (IMAGE, False)


def test_find_image_base_guesses_when_the_entry_never_ran():
    t = parse_qemu_log(QEMU_LOG)
    pcs = {LIB + 0xA00}
    assert find_image_base(t.mappings, pcs, E_ENTRY, True) == (IMAGE, True)
    # modern PIE layout: first segment r--, the entry in the second (r-x) segment; the base is the run start
    maps = [Mapping(0x4000000000, 0x4000001000, "r--"), Mapping(0x4000001000, 0x4000002000, "r-x")]
    assert find_image_base(maps, {0x4000001100}, 0x1100, True) == (0x4000000000, False)
    assert find_image_base(maps, set(), 0x1100, True) == (0x4000000000, True)
    assert find_image_base([], set(), 0x1100, True) == (0, True)


def test_find_image_base_non_pie_is_zero():
    t = parse_qemu_log(QEMU_LOG)
    assert find_image_base(t.mappings, set(t.pcs), 0x401000, False) == (0, False)


def test_to_ghidra_rebases_pie_and_keeps_non_pie():
    assert to_ghidra(IMAGE + 0x1234, IMAGE, IMAGE + 0x203000, True) == GHIDRA_PIE_BASE + 0x1234
    assert to_ghidra(IMAGE + 0x203000, IMAGE, IMAGE + 0x203000, True) is None
    assert to_ghidra(ANON, IMAGE, IMAGE + 0x203000, True) is None
    assert to_ghidra(0x401234, 0x400000, 0x404000, False) == 0x401234
    assert to_ghidra(0x1224000, 0x400000, 0x404000, False) is None


def test_from_ghidra_inverts_only_image_addresses():
    assert from_ghidra(0x100180, IMAGE, 0x203000, True) == IMAGE + 0x180
    assert from_ghidra(ANON, IMAGE, 0x203000, True) == ANON
    assert from_ghidra(0x401000, 0x400000, 0x4000, False) == 0x401000


def test_parse_elf_header_pie_and_non_pie():
    e = parse_elf_header(make_elf64())
    assert e.is_pie and e.entry == E_ENTRY and e.vaddr_lo == 0 and e.vaddr_hi == 0x203000 and e.size == 0x203000
    e2 = parse_elf_header(make_elf64(e_type=2, entry=0x401050, loads=((0x400000, 0x1000), (0x401000, 0x800))))
    assert not e2.is_pie and e2.vaddr_lo == 0x400000 and e2.vaddr_hi == 0x402000


def test_parse_elf_header_rejects_what_qemu_cannot_trace():
    with pytest.raises(TraceError, match="PE"):
        parse_elf_header(b"MZ" + b"\0" * 100)
    with pytest.raises(TraceError, match="script"):
        parse_elf_header(b"#!/bin/sh\n")
    with pytest.raises(TraceError, match="not an ELF"):
        parse_elf_header(b"\x00\x01\x02\x03" + b"\0" * 100)
    with pytest.raises(TraceError, match="not x86-64"):
        parse_elf_header(make_elf64(machine=183))
    with pytest.raises(TraceError, match="32-bit"):
        parse_elf_header(make_elf64(ei_class=1))
    with pytest.raises(TraceError, match="PT_LOAD"):
        parse_elf_header(make_elf64(loads=()))


def test_locate_image_pie_from_trace_and_known_base():
    elf = parse_elf_header(make_elf64())
    t = parse_qemu_log(QEMU_LOG)
    img = locate_image(elf, t)
    assert (img.lo, img.hi, img.is_pie, img.guessed, img.entry) == (IMAGE, IMAGE + 0x203000, True, False, IMAGE + 0x100)
    assert img.ghidra_lo == 0x100000 and img.ghidra_hi == 0x303000
    img2 = locate_image(elf, parse_qemu_log(""), known_base=0x5000000000)
    assert img2.lo == 0x5000000000 and not img2.guessed
    non_pie = parse_elf_header(make_elf64(e_type=2, entry=0x401050, loads=((0x400000, 0x2000),)))
    img3 = locate_image(non_pie, t)
    assert (img3.lo, img3.hi, img3.is_pie, img3.ghidra_lo) == (0x400000, 0x402000, False, 0x400000)


def test_classify_regions_image_lib_anon():
    t = parse_qemu_log(QEMU_LOG)
    regions = classify_regions(t.mappings, t.initial_mappings, _image())
    assert [(r.kind, r.start, r.end) for r in regions] == [
        ("image", IMAGE, IMAGE + 0x203000),
        ("lib?", LIB, LIB + 0x40000),
        ("anon rwx", ANON, ANON + 0x1000),
        ("lib?", 0xFFFFFFFFFF600000, 0xFFFFFFFFFF601000),
    ]
    # an executable, non-writable mapping created after start is plain [anon]
    maps = t.mappings + [Mapping(0x1224000, 0x1225000, "r-x")]
    regions = classify_regions(maps, t.initial_mappings, _image())
    assert ("anon", 0x1224000, 0x1225000) in [(r.kind, r.start, r.end) for r in regions]


def test_count_regions_and_other():
    t = parse_qemu_log(QEMU_LOG)
    regions = classify_regions(t.mappings, t.initial_mappings, _image())
    other = count_regions(regions, t.pcs + [0x12345])
    counts = {r.kind + ("" if r.kind != "lib?" else f"@{r.start:#x}"): r.count for r in regions}
    assert counts["image"] == 7 and counts[f"lib?@{LIB:#x}"] == 4 and counts["anon rwx"] == 3
    assert other == 1


def test_initial_layout_is_the_one_before_the_entry_ran():
    # libraries the dynamic loader maps before jumping to the entry are already present at the entry
    log = ("page layout changed following mmap\nstart end size prot\n"
           "0000004000000000-0000004000001000 0000000000001000 r-x\n"
           "0000004002000000-0000004002001000 0000000000001000 r-x\n"
           "Trace 0: 0x1 [0/0000004002000000/0/0] \n"
           "page layout changed following mmap\nstart end size prot\n"
           "0000004000000000-0000004000001000 0000000000001000 r-x\n"
           "0000004002000000-0000004002001000 0000000000001000 r-x\n"
           "0000004003000000-0000004003001000 0000000000001000 r-x\n"
           "Trace 0: 0x1 [0/0000004003000000/0/0] \n"
           "Trace 0: 0x1 [0/0000004000000100/0/0] \n"
           "page layout changed following mmap\nstart end size prot\n"
           "0000004000000000-0000004000001000 0000000000001000 r-x\n"
           "0000004002000000-0000004002001000 0000000000001000 r-x\n"
           "0000004003000000-0000004003001000 0000000000001000 r-x\n"
           "0000004004000000-0000004004001000 0000000000001000 rwx\n"
           "Trace 0: 0x1 [0/0000004004000000/0/0] \n")
    t = parse_qemu_log(log)
    img = ImageInfo(lo=0x4000000000, hi=0x4000001000, is_pie=True, guessed=False, entry=0x4000000100)
    initial = initial_layout(t, img)
    assert Mapping(0x4003000000, 0x4003001000, "r-x") in initial
    assert Mapping(0x4004000000, 0x4004001000, "rwx") not in initial
    kinds = {r.start: r.kind for r in classify_regions(t.mappings, initial, img)}
    assert kinds[0x4002000000] == "lib?" and kinds[0x4003000000] == "lib?" and kinds[0x4004000000] == "anon rwx"


def test_compress_simple_repeat():
    assert compress([1, 2, 3, 1, 2, 3, 1, 2, 3, 4]) == [((1, 2, 3), 3), ((4,), 1)]


def test_compress_length_one_and_empty():
    assert compress([5, 5, 5, 5]) == [((5,), 4)]
    assert compress([]) == []
    assert compress([9]) == [((9,), 1)]


def test_compress_prefers_the_period_that_covers_most_without_nesting():
    assert compress([1, 1, 2, 1, 1, 2]) == [((1, 1, 2), 2)]
    assert compress([1, 2, 1, 2, 3]) == [((1, 2), 2), ((3,), 1)]


def test_compress_does_not_fold_a_period_longer_than_max_k():
    seq = list(range(17)) * 2
    assert compress(seq) == [((x,), 1) for x in seq]
    assert compress(seq, max_k=17) == [(tuple(range(17)), 2)]


def test_item_text_and_full_listing():
    assert item_text(((0x1224000, 0x1013A4), 512)) == "(0x1224000 0x1013a4)×512"
    assert item_text(((0x101040,), 1)) == "0x101040"
    assert full_listing([((1,), 1), ((2, 3), 2)]) == "0x1\n(0x2 0x3)×2\n"
    assert full_listing([]) == ""


def test_analyze_default_skips_libraries_and_translates():
    t = parse_qemu_log(QEMU_LOG)
    a = analyze(t, _image())
    assert a.total == 14 and a.other == 0 and a.skipped_lib and a.range_ is None
    assert a.seq == [0x100100, 0x100140, 0x100180, ANON, 0x1001A0, ANON, 0x1001A0, ANON, 0x1001A0, 0x1001C0]
    assert a.hot[0] == (ANON, 3) and (0x1001A0, 3) in a.hot
    assert compress(a.seq) == [((0x100100,), 1), ((0x100140,), 1), ((0x100180,), 1),
                               ((ANON, 0x1001A0), 3), ((0x1001C0,), 1)]


def test_analyze_range_filters_on_display_addresses():
    t = parse_qemu_log(QEMU_LOG)
    a = analyze(t, _image(), range_=(0x100180, 0x1001C0))
    assert a.seq == [0x100180, 0x1001A0, 0x1001A0, 0x1001A0] and not a.skipped_lib
    b = analyze(t, _image(), range_=(LIB, LIB + 0x40000))
    assert b.seq == [LIB + 0xA00, LIB + 0xA20, LIB + 0xA20, LIB + 0xB00]


def test_summarize_format():
    t = parse_qemu_log(QEMU_LOG)
    out = summarize(t, _image())
    lines = out.splitlines()
    assert lines[0] == "image: 0x4000000000..0x4000203000 (PIE, Ghidra base 0x100000)"
    assert lines[1] == "regions (executed TBs):"
    assert "[image]      0x100000..0x303000  7" in out
    assert f"[lib?]       {LIB:#x}..{LIB + 0x40000:#x}  4  (skipped in sequence; pass range= to include)" in out
    assert f"[anon rwx]   {ANON:#x}..{ANON + 0x1000:#x}  3  <- mmap'd after start; not a library" in out
    assert "0xffffffffff600000" not in out               # a lib mapping with 0 TBs is not listed
    assert "hot (Ghidra addr × count, top 40):" in out
    assert f"{ANON:#x} ×3" in out and "0x1001a0 ×3" in out
    assert "sequence (image + anon, 10 TBs, repeats folded):" in out
    assert f"0x100100 0x100140 0x100180 ({ANON:#x} 0x1001a0)×3 0x1001c0" in out
    assert "head" not in out                              # short sequences are shown whole


def test_summarize_cuts_long_sequences_and_marks_guessed_base_and_range():
    t = parse_qemu_log(QEMU_LOG)
    img = ImageInfo(lo=IMAGE, hi=IMAGE + 0x203000, is_pie=True, guessed=True, entry=IMAGE + E_ENTRY)
    out = summarize(t, img, range_=(0x100180, 0x1001C0), head=1, tail=1)
    assert "(base guessed: the entry point never executed)" in out
    assert "sequence (range 0x100180..0x1001c0, 4 TBs, repeats folded):" in out
    assert "  0x100180 (0x1001a0)×3" in out and "items shown" not in out   # 2 items <= head + tail: whole
    out2 = summarize(t, img, head=1, tail=1)
    assert "0x100100 ... 0x1001c0" in out2 and "[head 1 / tail 1 of 5 items shown]" in out2


def test_render_non_pie_and_other_bucket():
    img = ImageInfo(lo=0x400000, hi=0x402000, is_pie=False, guessed=False, entry=0x401000)
    a = Analysis(regions=[Region("image", 0x400000, 0x402000, "", 5)], other=2, total=7, seq=[0x401000] * 5,
                 hot=[(0x401000, 5)], range_=None, skipped_lib=True)
    out = render(a, compress(a.seq), img)
    assert out.splitlines()[0] == "image: 0x400000..0x402000 (non-PIE, addresses as in Ghidra)"
    assert "[image]      0x400000..0x402000  5" in out and "[other]      (no mapping)  2" in out
    assert "(0x401000)×5" in out


def test_render_tail_zero_shows_the_head_once():
    # items[-0:] is the whole list: with tail=0 the head must be shown exactly once, followed by the cut marker
    t = parse_qemu_log(QEMU_LOG)
    out = summarize(t, _image(), head=2, tail=0)
    lines = out.splitlines()
    i = next(i for i, l in enumerate(lines) if l.startswith("sequence ("))
    assert lines[i + 1] == "  0x100100 0x100140 ..."
    assert lines[i + 2] == "  ... [head 2 / tail 0 of 5 items shown]"
    assert out.count("0x1001c0") == 1                       # only in the hot list, not in the sequence
