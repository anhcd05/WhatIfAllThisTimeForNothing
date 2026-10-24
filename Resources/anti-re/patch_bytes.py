#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_bytes.py  -  UNIVERSAL BYTE PATCHER cho CTF Reverse Engineering
=====================================================================
Muc dich: vo hieu check / ep nhanh / go anti-debug cho binary PE (Windows)
va ELF (Linux) SAU KHI da reverse ra chinh xac offset/lenh can sua.

Dac diem:
  - Ap patch theo FILE OFFSET (off=...) hoac theo VIRTUAL ADDRESS (va=...).
      * PE : dung pefile neu co; neu khong co -> tu parse section header.
      * ELF: tu parse ELF header + program headers (khong can thu vien ngoai).
  - Ham tien ich: nop_range, force_jmp, ret_now, set_eax_1, invert_jcc,
                  patch_hex, patch_bytes.
  - Doc file -> ap patch -> LUU RA BAN SAO MOI (khong ghi de goc).
  - Hexdump TRUOC/SAU vung sua de xac nhan bang mat.
  - Nhan patch tu CLI hoac tu list PATCHES trong main() (co # TODO).

KHONG ghi de file goc. KHONG tai/chay binary la.

Vi du CLI:
  python patch_bytes.py chall                       # self patch theo list PATCHES
  python patch_bytes.py chall -o chall_patched
  python patch_bytes.py chall --off 0x1234 --hex 90 90
  python patch_bytes.py chall --va  0x401234 --jmp         # ep jcc -> jmp
  python patch_bytes.py chall --va  0x401240 --nop 5       # nop 5 byte
  python patch_bytes.py chall --off 0x1250 --ret           # ghi 0xC3
  python patch_bytes.py chall --off 0x1260 --eax1          # B8 01 00 00 00
  python patch_bytes.py chall --off 0x1270 --invert        # dao dieu kien jcc
  python patch_bytes.py chall --show 0x1234 --len 32       # chi hexdump, khong sua
"""

import sys
import os
import struct
import shutil
import argparse

try:
    import pefile  # tuy chon, chi dung cho VA->offset cua PE
    HAVE_PEFILE = True
except Exception:
    HAVE_PEFILE = False


# ----------------------------------------------------------------------------
# 1) PHAT HIEN DINH DANG & QUY DOI VA <-> FILE OFFSET
# ----------------------------------------------------------------------------

def detect_format(data: bytes) -> str:
    """Tra ve 'PE', 'ELF' hoac 'RAW'."""
    if data[:2] == b"MZ":
        # kiem tra con tro toi 'PE\0\0'
        if len(data) >= 0x40:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if e_lfanew + 4 <= len(data) and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    return "RAW"


# ---- ELF: tu parse (khong can pyelftools) ----------------------------------

def elf_va_to_off(data: bytes, va: int) -> int:
    """
    Quy doi Virtual Address -> file offset cho ELF bang program headers (PT_LOAD).
    Cong thuc: off = va - p_vaddr + p_offset, voi segment chua va.
    """
    if data[:4] != b"\x7fELF":
        raise ValueError("Khong phai ELF")

    ei_class = data[4]      # 1=ELF32, 2=ELF64
    ei_data = data[5]       # 1=little, 2=big
    endian = "<" if ei_data == 1 else ">"

    if ei_class == 1:   # ELF32
        # e_phoff @0x1C (4), e_phentsize @0x2A (2), e_phnum @0x2C (2)
        e_phoff = struct.unpack_from(endian + "I", data, 0x1C)[0]
        e_phentsize = struct.unpack_from(endian + "H", data, 0x2A)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 0x2C)[0]
        PT_LOAD = 1
        for i in range(e_phnum):
            base = e_phoff + i * e_phentsize
            p_type = struct.unpack_from(endian + "I", data, base + 0x00)[0]
            p_offset = struct.unpack_from(endian + "I", data, base + 0x04)[0]
            p_vaddr = struct.unpack_from(endian + "I", data, base + 0x08)[0]
            p_filesz = struct.unpack_from(endian + "I", data, base + 0x10)[0]
            if p_type == PT_LOAD and p_vaddr <= va < p_vaddr + p_filesz:
                return va - p_vaddr + p_offset
    elif ei_class == 2:  # ELF64
        # e_phoff @0x20 (8), e_phentsize @0x36 (2), e_phnum @0x38 (2)
        e_phoff = struct.unpack_from(endian + "Q", data, 0x20)[0]
        e_phentsize = struct.unpack_from(endian + "H", data, 0x36)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 0x38)[0]
        PT_LOAD = 1
        for i in range(e_phnum):
            base = e_phoff + i * e_phentsize
            # Phdr64: p_type(4) p_flags(4) p_offset(8) p_vaddr(8) p_paddr(8) p_filesz(8)
            p_type = struct.unpack_from(endian + "I", data, base + 0x00)[0]
            p_offset = struct.unpack_from(endian + "Q", data, base + 0x08)[0]
            p_vaddr = struct.unpack_from(endian + "Q", data, base + 0x10)[0]
            p_filesz = struct.unpack_from(endian + "Q", data, base + 0x20)[0]
            if p_type == PT_LOAD and p_vaddr <= va < p_vaddr + p_filesz:
                return va - p_vaddr + p_offset
    else:
        raise ValueError("EI_CLASS khong hop le: %d" % ei_class)

    raise ValueError("VA 0x%X khong nam trong segment PT_LOAD nao (co phai .bss?)" % va)


# ---- PE: pefile neu co, neu khong tu parse section header -------------------

def pe_va_to_off_manual(data: bytes, va: int) -> int:
    """
    Quy doi VA -> file offset cho PE bang cach tu parse section headers.
    VA la dia chi tuyet doi (da gom ImageBase). RVA = VA - ImageBase.
    off = RVA - VirtualAddress(section) + PointerToRawData(section).
    """
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    # COFF File Header ngay sau 'PE\0\0'
    coff = e_lfanew + 4
    machine = struct.unpack_from("<H", data, coff + 0)[0]
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    size_opt = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20  # Optional Header bat dau

    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:      # PE32
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
    elif magic == 0x20B:    # PE32+
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    else:
        raise ValueError("Optional header magic la?: 0x%X" % magic)

    rva = va - image_base
    sec_tab = opt + size_opt  # Section table bat dau ngay sau Optional Header
    IMAGE_SIZEOF_SECTION_HEADER = 40
    for i in range(num_sections):
        s = sec_tab + i * IMAGE_SIZEOF_SECTION_HEADER
        virt_size = struct.unpack_from("<I", data, s + 8)[0]
        virt_addr = struct.unpack_from("<I", data, s + 12)[0]
        raw_size = struct.unpack_from("<I", data, s + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, s + 20)[0]
        span = max(virt_size, raw_size)
        if virt_addr <= rva < virt_addr + span:
            return rva - virt_addr + raw_ptr
    raise ValueError("RVA 0x%X khong thuoc section nao (VA 0x%X, ImageBase 0x%X)"
                     % (rva, va, image_base))


def pe_va_to_off(data: bytes, path: str, va: int) -> int:
    if HAVE_PEFILE:
        pe = pefile.PE(path, fast_load=True)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        off = pe.get_offset_from_rva(va - image_base)
        pe.close()
        return off
    return pe_va_to_off_manual(data, va)


def va_to_off(data: bytes, path: str, va: int) -> int:
    """Quy doi VA -> file offset, tu dong theo dinh dang."""
    fmt = detect_format(data)
    if fmt == "PE":
        return pe_va_to_off(data, path, va)
    if fmt == "ELF":
        return elf_va_to_off(data, va)
    raise ValueError("Khong the quy doi VA cho dinh dang RAW; hay dung FILE OFFSET.")


# ----------------------------------------------------------------------------
# 2) HEXDUMP
# ----------------------------------------------------------------------------

def hexdump(data: bytes, start: int, length: int, mark=None) -> str:
    """Hexdump theo khung 16 byte. 'mark' = tap offset se duoc danh dau [].
       Dia chi in ra la FILE OFFSET tuyet doi."""
    mark = mark or set()
    out = []
    base = start - (start % 16)
    end = start + length
    a = base
    while a < end:
        row = data[a:a + 16]
        hexs = []
        asci = []
        for j, b in enumerate(row):
            off = a + j
            cell = "%02X" % b
            if off in mark:
                cell = "[%02X]" % b  # danh dau byte bi sua
            else:
                cell = " %02X " % b
            # chi hien thi trong pham vi [start, end)
            if off < start or off >= end:
                cell = " .. "
            hexs.append(cell)
            ch = chr(b) if 32 <= b < 127 else "."
            if off < start or off >= end:
                ch = " "
            asci.append(ch)
        out.append("%08X  %s |%s|" % (a, "".join(hexs), "".join(asci)))
        a += 16
    return "\n".join(out)


# ----------------------------------------------------------------------------
# 3) CAC HAM PATCH TIEN ICH  (thao tac tren bytearray tai chO)
# ----------------------------------------------------------------------------

def patch_bytes_at(buf: bytearray, off: int, new: bytes):
    """Ghi 'new' vao buf tai file offset 'off'."""
    if off < 0 or off + len(new) > len(buf):
        raise ValueError("Patch vuot pham vi file: off=0x%X len=%d (size=0x%X)"
                         % (off, len(new), len(buf)))
    buf[off:off + len(new)] = new


def patch_hex_at(buf: bytearray, off: int, hexstr: str):
    """Ghi chuoi hex (vd '90 90' hoac '9090') vao offset."""
    clean = hexstr.replace(" ", "").replace(",", "").replace("0x", "")
    patch_bytes_at(buf, off, bytes.fromhex(clean))


def nop_range(buf: bytearray, off: int, length: int):
    """Ghi 'length' byte NOP (0x90) tu offset. Dung bu khi lenh moi ngan hon lenh cu."""
    patch_bytes_at(buf, off, b"\x90" * length)


def ret_now(buf: bytearray, off: int):
    """Ghi RET (0xC3) de tra ve som (vd lam ham check tra ve ngay)."""
    patch_bytes_at(buf, off, b"\xC3")


def set_eax_1(buf: bytearray, off: int):
    """Ghi 'mov eax, 1' = B8 01 00 00 00 (ep gia tri tra ve = 1 / TRUE)."""
    patch_bytes_at(buf, off, b"\xB8\x01\x00\x00\x00")


def set_eax_0(buf: bytearray, off: int):
    """Ghi 'xor eax, eax' = 31 C0 (ep gia tri tra ve = 0 / FALSE), 2 byte."""
    patch_bytes_at(buf, off, b"\x31\xC0")


def force_jmp(buf: bytearray, off: int):
    """
    Ep mot jump co dieu kien thanh jump KHONG dieu kien (luon nhay).
      - jcc ngan 1 byte opcode: 70..7F  -> 0xEB (jmp short), giu nguyen rel8.
      - jcc dai 2 byte: 0F 80..0F 8F    -> chuyen thanh E9 + rel32.
        0F 8x cc rel32 (6 byte) -> E9 rel32 (5 byte) + 1 NOP de bu.
    """
    op = buf[off]
    if 0x70 <= op <= 0x7F:
        buf[off] = 0xEB
        return "jcc short (0x%02X) -> EB (jmp short)" % op
    if op == 0x0F and 0x80 <= buf[off + 1] <= 0x8F:
        op2 = buf[off + 1]
        rel32 = bytes(buf[off + 2:off + 6])
        # near jcc la 6 byte, near jmp E9 la 5 byte -> dich rel32 len 1 va NOP cuoi
        buf[off] = 0xE9
        buf[off + 1:off + 5] = rel32
        buf[off + 5] = 0x90
        return "jcc near (0F %02X) -> E9 rel32 + NOP" % op2
    raise ValueError("Byte tai 0x%X (0x%02X) khong phai jcc da biet" % (off, op))


def invert_jcc(buf: bytearray, off: int):
    """
    Dao DIEU KIEN cua mot jcc (jz<->jnz, je<->jne, jb<->jae, ...).
    Quy tac: lat bit thap nhat cua opcode phan dieu kien.
      - ngan 1 byte: 70..7F -> op XOR 1
      - dai 2 byte : 0F 80..0F 8F -> (0F) (op2 XOR 1)
    """
    op = buf[off]
    if 0x70 <= op <= 0x7F:
        buf[off] = op ^ 1
        return "jcc short 0x%02X -> 0x%02X (dao dieu kien)" % (op, op ^ 1)
    if op == 0x0F and 0x80 <= buf[off + 1] <= 0x8F:
        old = buf[off + 1]
        buf[off + 1] = old ^ 1
        return "jcc near 0F %02X -> 0F %02X (dao dieu kien)" % (old, old ^ 1)
    raise ValueError("Byte tai 0x%X (0x%02X) khong phai jcc da biet" % (off, op))


def nop_call(buf: bytearray, off: int):
    """
    NOP mot lenh CALL rel32 (E8 xx xx xx xx, 5 byte) -> 5 NOP.
    Dung de vo hieu call toi ptrace/IsDebuggerPresent/anti-debug.
    """
    if buf[off] != 0xE8:
        raise ValueError("Byte tai 0x%X khong phai CALL rel32 (E8), ma la 0x%02X" % (off, buf[off]))
    nop_range(buf, off, 5)
    return "CALL rel32 (E8..) -> 5x NOP"


# ----------------------------------------------------------------------------
# 4) AP MOT DANH SACH PATCH
# ----------------------------------------------------------------------------
#
# Moi phan tu la mot dict. Chi dinh vi tri bang 'off' (file offset) HOAC
# 'va' (virtual address, se tu quy doi). Hanh dong bang mot trong cac khoa:
#   hex:     chuoi hex ghi thang,          vd {"off":0x1234, "hex":"90 90"}
#   bytes:   bytes() ghi thang,            vd {"off":0x1234, "bytes": b"\x90\x90"}
#   nop:     so byte NOP,                  vd {"va":0x401234, "nop":5}
#   jmp:     True -> force_jmp,            vd {"va":0x401234, "jmp":True}
#   invert:  True -> invert_jcc,           vd {"off":0x1234, "invert":True}
#   ret:     True -> ret_now (0xC3),       vd {"off":0x1234, "ret":True}
#   eax1:    True -> set_eax_1,            vd {"off":0x1234, "eax1":True}
#   eax0:    True -> set_eax_0,            vd {"off":0x1234, "eax0":True}
#   nopcall: True -> nop_call (E8..),      vd {"va":0x401234, "nopcall":True}
# Them "note":"mo ta" de in giai thich.

def resolve_off(data: bytes, path: str, p: dict) -> int:
    if "off" in p:
        return int(p["off"])
    if "va" in p:
        return va_to_off(data, path, int(p["va"]))
    raise ValueError("Patch thieu 'off' hoac 'va': %r" % p)


def apply_patch(buf: bytearray, off: int, p: dict) -> str:
    if "hex" in p:
        patch_hex_at(buf, off, p["hex"])
        return "hex=%s" % p["hex"]
    if "bytes" in p:
        patch_bytes_at(buf, off, p["bytes"])
        return "bytes=%s" % p["bytes"].hex(" ")
    if p.get("nop") is not None and p.get("nop") is not False:
        n = int(p["nop"])
        nop_range(buf, off, n)
        return "nop x%d" % n
    if p.get("jmp"):
        return force_jmp(buf, off)
    if p.get("invert"):
        return invert_jcc(buf, off)
    if p.get("ret"):
        ret_now(buf, off)
        return "ret (C3)"
    if p.get("eax1"):
        set_eax_1(buf, off)
        return "mov eax,1 (B8 01 00 00 00)"
    if p.get("eax0"):
        set_eax_0(buf, off)
        return "xor eax,eax (31 C0)"
    if p.get("nopcall"):
        return nop_call(buf, off)
    raise ValueError("Patch khong co hanh dong hop le: %r" % p)


def patch_len(buf_before: bytearray, buf_after: bytearray, off: int) -> int:
    """Uoc luong so byte da doi quanh off (de hexdump dung vung)."""
    n = 0
    i = off
    while i < len(buf_before) and i < off + 16:
        if buf_before[i] != buf_after[i]:
            n = i - off + 1
        i += 1
    return max(n, 1)


def run_patches(src_path: str, out_path: str, patches: list, context: int = 16):
    with open(src_path, "rb") as f:
        data = f.read()
    fmt = detect_format(data)
    print("[*] File   : %s (%d byte)" % (src_path, len(data)))
    print("[*] Dinh dang: %s | pefile: %s" % (fmt, "co" if HAVE_PEFILE else "khong"))
    print("[*] So patch : %d" % len(patches))
    print("=" * 72)

    buf = bytearray(data)
    for idx, p in enumerate(patches, 1):
        off = resolve_off(data, src_path, p)
        before_region = bytes(buf[max(0, off - context): off + context])
        note = p.get("note", "")
        desc = apply_patch(buf, off, p)
        changed = patch_len(bytearray(data), buf, off)  # so byte doi so voi goc
        mark = set(range(off, off + max(changed, 1)))
        print("[Patch %d] offset=0x%08X  %s  %s" % (idx, off, desc, ("<- " + note) if note else ""))
        if "va" in p:
            print("          (tu VA 0x%X)" % int(p["va"]))
        print("  --- TRUOC ---")
        print(hexdump(data, off - context if off >= context else 0,
                      context * 2, mark))
        print("  --- SAU ---")
        print(hexdump(bytes(buf), off - context if off >= context else 0,
                      context * 2, mark))
        print("-" * 72)

    # LUU RA BAN SAO MOI (khong ghi de goc)
    with open(out_path, "wb") as f:
        f.write(buf)
    print("[+] Da luu ban va: %s" % out_path)
    print("[i] File goc KHONG bi thay doi: %s" % src_path)


# ----------------------------------------------------------------------------
# 5) CLI
# ----------------------------------------------------------------------------

def build_cli_patch(args) -> dict:
    """Dung mot patch tu doi so CLI (neu co)."""
    p = {}
    if args.off is not None:
        p["off"] = int(args.off, 0)
    elif args.va is not None:
        p["va"] = int(args.va, 0)
    else:
        return None  # khong co patch tu CLI -> dung list PATCHES

    if args.hex is not None:
        p["hex"] = " ".join(args.hex)
    elif args.nop is not None:
        p["nop"] = int(args.nop)
    elif args.jmp:
        p["jmp"] = True
    elif args.invert:
        p["invert"] = True
    elif args.ret:
        p["ret"] = True
    elif args.eax1:
        p["eax1"] = True
    elif args.eax0:
        p["eax0"] = True
    elif args.nopcall:
        p["nopcall"] = True
    else:
        raise SystemExit("Co --off/--va nhung thieu hanh dong "
                         "(--hex/--nop/--jmp/--invert/--ret/--eax1/--eax0/--nopcall)")
    if args.note:
        p["note"] = args.note
    return p


def main():
    ap = argparse.ArgumentParser(
        description="Universal byte patcher cho CTF RE (PE/ELF). "
                    "Luu ra ban sao, khong ghi de goc.")
    ap.add_argument("infile", help="Binary dau vao (KHONG bi ghi de)")
    ap.add_argument("-o", "--out", help="File dau ra (mac dinh: <infile>.patched)")

    # vi tri
    ap.add_argument("--off", help="File offset (vd 0x1234)")
    ap.add_argument("--va", help="Virtual address (tu quy doi -> offset)")

    # hanh dong
    ap.add_argument("--hex", nargs="+", help="Ghi hex, vd: --hex 90 90 EB 0A")
    ap.add_argument("--nop", help="So byte NOP tu vi tri")
    ap.add_argument("--jmp", action="store_true", help="Ep jcc -> jmp (force_jmp)")
    ap.add_argument("--invert", action="store_true", help="Dao dieu kien jcc")
    ap.add_argument("--ret", action="store_true", help="Ghi RET (0xC3)")
    ap.add_argument("--eax1", action="store_true", help="mov eax,1 (B8 01 00 00 00)")
    ap.add_argument("--eax0", action="store_true", help="xor eax,eax (31 C0)")
    ap.add_argument("--nopcall", action="store_true", help="NOP 1 call E8 rel32 (5 byte)")
    ap.add_argument("--note", help="Ghi chu cho patch")

    # chi xem, khong sua
    ap.add_argument("--show", help="Chi hexdump tai offset/VA nay roi thoat")
    ap.add_argument("--len", type=lambda s: int(s, 0), default=32,
                    help="So byte hexdump cho --show (mac dinh 32)")

    args = ap.parse_args()

    out = args.out or (args.infile + ".patched")

    # che do chi xem
    if args.show is not None:
        with open(args.infile, "rb") as f:
            data = f.read()
        val = int(args.show, 0)
        # neu trong vung VA thi thu quy doi; neu loi, coi la offset
        off = val
        try:
            off = va_to_off(data, args.infile, val)
            print("[*] VA 0x%X -> offset 0x%X" % (val, off))
        except Exception:
            print("[*] Coi 0x%X la FILE OFFSET" % val)
        print(hexdump(data, off, args.len))
        return

    cli_patch = build_cli_patch(args)
    if cli_patch is not None:
        patches = [cli_patch]
    else:
        patches = PATCHES  # dung list dinh nghia o duoi

    if not patches:
        raise SystemExit("Khong co patch nao. Dua --off/--va + hanh dong, "
                         "hoac dien vao list PATCHES trong main().")

    run_patches(args.infile, out, patches)


# ----------------------------------------------------------------------------
# DANH SACH PATCH MAC DINH  -  SUA O DAY cho tung de
# ----------------------------------------------------------------------------
# TODO: Dien cac patch cua ban vao day. Vi du (dang comment):
PATCHES = [
    # {"va": 0x0040129A, "jmp": True,  "note": "ep nhanh 'Correct!' luon chay"},
    # {"off": 0x11B0,    "nop": 2,     "note": "nop jz sau strcmp"},
    # {"off": 0x1200,    "ret": True,  "note": "anti_debug() tra ve ngay"},
    # {"va": 0x0040120F, "eax1": True, "note": "check() luon return 1"},
    # {"off": 0x1240,    "invert": True, "note": "dao je -> jne"},
    # {"va": 0x00401055, "nopcall": True, "note": "vo hieu call ptrace"},
    # {"off": 0x1300,    "hex": "90 90 90 90 90", "note": "nop thu cong 5 byte"},
]


if __name__ == "__main__":
    main()
