#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tmpl_fileparse.py - Template ĐỌC/PARSE FILE NHỊ PHÂN (Reverse / Forensics)
Cyber SEA Game 2026

MỤC ĐÍCH
    Bộ công cụ mẫu để phân tích một file nhị phân bất kỳ:
        - Đọc bytes, giải mã số (struct.unpack) theo Little/Big Endian.
        - Hexdump giống `xxd` để quan sát dữ liệu.
        - Tìm "magic bytes" / chữ ký file, carve (cắt) dữ liệu theo offset + độ dài.
        - Parse file PE (Windows .exe/.dll) bằng thư viện `pefile`.
        - Đọc header + sections của file ELF (Linux) bằng struct hoặc pyelftools.
        - Quét/giải XOR, trích các blob base64 / hex nhúng trong file.

AN TOÀN (RẤT QUAN TRỌNG)
    Template này CHỈ ĐỌC và PHÂN TÍCH BYTES. Nó KHÔNG BAO GIỜ chạy/exec binary lạ.
    Tuyệt đối không dùng os.system / subprocess để thực thi file mẫu.

CÁCH DÙNG NHANH
    python tmpl_fileparse.py <đường_dẫn_file>
    -> In thông tin tổng quát + hexdump đầu file. Sau đó mở code và sửa phần `main()`
       hoặc gọi trực tiếp các hàm bên dưới cho đúng bài của bạn (xem các dấu # TODO).

PHỤ THUỘC (tùy chọn, chỉ cần khi parse PE/ELF):
    pip install pefile pyelftools
"""

import sys
import os
import re
import struct
import base64
import binascii
import string

# ---------------------------------------------------------------------------
# PHẦN 0: ĐỌC FILE + TIỆN ÍCH CƠ BẢN
# ---------------------------------------------------------------------------

def read_file(path):
    """Đọc toàn bộ file dưới dạng bytes (đọc nhị phân 'rb').

    Trả về: đối tượng `bytes`.
    Lưu ý: với file RẤT lớn (vài trăm MB) nên dùng mmap thay vì nạp hết vào RAM,
    nhưng trong CTF thường file nhỏ nên đọc hết cho tiện.
    """
    with open(path, "rb") as f:
        return f.read()


def hexdump(data, length=256, base_off=0, width=16):
    """In hexdump giống lệnh `xxd`:  OFFSET: HEX ...  |ASCII|

    data     : bytes cần in.
    length   : số byte in ra (mặc định 256). Dùng None để in hết.
    base_off : offset bắt đầu ghi ở cột địa chỉ (hữu ích khi dump 1 đoạn giữa file).
    width    : số byte mỗi dòng (mặc định 16).
    """
    if length is not None:
        data = data[:length]
    out_lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        # Cột hex: mỗi byte 2 ký tự, cách nhau 1 space
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Căn lề cho dòng cuối (thiếu byte) để cột ASCII thẳng hàng
        hex_part = hex_part.ljust(width * 3 - 1)
        # Cột ASCII: ký tự in được giữ nguyên, còn lại thay bằng '.'
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out_lines.append(f"{base_off + i:08x}: {hex_part}  |{ascii_part}|")
    result = "\n".join(out_lines)
    print(result)
    return result


def carve(data, offset, length):
    """Cắt (carve) `length` byte bắt đầu từ `offset`. Trả về bytes.

    Dùng khi đã biết dữ liệu cần nằm ở đâu (ví dụ sau khi tìm magic bytes).
    """
    return data[offset:offset + length]


def carve_to_file(data, offset, length, out_path):
    """Cắt dữ liệu rồi ghi ra file (ví dụ tách 1 file nhúng bên trong)."""
    blob = carve(data, offset, length)
    with open(out_path, "wb") as f:
        f.write(blob)
    print(f"[+] Da ghi {len(blob)} byte ra: {out_path}")
    return blob


# ---------------------------------------------------------------------------
# PHẦN 1: GIẢI MÃ SỐ BẰNG struct (Little Endian / Big Endian)
# ---------------------------------------------------------------------------
# Bảng ký tự định dạng struct hay dùng:
#   <  Little Endian     >  Big Endian     =  native (theo máy)
#   B  uint8  (1 byte)    b  int8
#   H  uint16 (2 byte)    h  int16
#   I  uint32 (4 byte)    i  int32
#   Q  uint64 (8 byte)    q  int64
#   f  float (4)          d  double (8)
#   s  chuỗi bytes (ví dụ '4s' = 4 byte)
# ---------------------------------------------------------------------------

def unpack_int(data, offset, fmt):
    """Đọc 1 số nguyên từ `data` tại `offset` theo định dạng struct `fmt`.

    Ví dụ:
        unpack_int(data, 0, "<I")  -> uint32 little-endian tại offset 0
        unpack_int(data, 4, ">H")  -> uint16 big-endian  tại offset 4
    """
    size = struct.calcsize(fmt)
    (value,) = struct.unpack_from(fmt, data, offset)
    return value, size


def unpack_many(data, offset, fmt):
    """Đọc NHIỀU trường cùng lúc bằng 1 chuỗi định dạng.

    Ví dụ đọc 1 "record" gồm: magic(4s) + version(uint16 LE) + size(uint32 LE):
        fields = unpack_many(data, 0, "<4sHI")
        magic, version, size = fields
    Trả về tuple các giá trị.
    """
    return struct.unpack_from(fmt, data, offset)


def demo_struct():
    """Ví dụ minh họa LE vs BE để thấy sự khác biệt endian."""
    raw = bytes([0x01, 0x02, 0x03, 0x04])
    (le,) = struct.unpack("<I", raw)   # 0x04030201
    (be,) = struct.unpack(">I", raw)   # 0x01020304
    print(f"[demo] bytes 01 02 03 04 -> LE=0x{le:08x}  BE=0x{be:08x}")


# ---------------------------------------------------------------------------
# PHẦN 2: TÌM MAGIC BYTES / CHỮ KÝ FILE
# ---------------------------------------------------------------------------
# Một số magic phổ biến (xem thêm "file signatures" / "magic numbers"):
MAGIC_SIGNATURES = {
    b"MZ":                    "PE/DOS executable (Windows .exe/.dll)",
    b"\x7fELF":               "ELF executable (Linux)",
    b"\x89PNG\r\n\x1a\n":     "PNG image",
    b"\xff\xd8\xff":          "JPEG image",
    b"GIF8":                  "GIF image",
    b"PK\x03\x04":            "ZIP / JAR / APK / DOCX / XLSX ...",
    b"Rar!\x1a\x07":          "RAR archive",
    b"\x1f\x8b":              "GZIP",
    b"BZh":                   "BZIP2",
    b"\xfd7zXZ\x00":          "XZ",
    b"7z\xbc\xaf\x27\x1c":    "7-Zip",
    b"%PDF":                  "PDF",
    b"\x25\x21PS":            "PostScript",
    b"OggS":                  "OGG",
    b"ID3":                   "MP3 (ID3)",
    b"\x00\x00\x01\x00":      "ICO icon",
    b"SQLite format 3\x00":   "SQLite database",
}


def identify_magic(data):
    """Nhận diện loại file dựa trên magic bytes ở ĐẦU file.

    Trả về mô tả (str) hoặc None nếu không khớp cái nào đã biết.
    """
    for sig, desc in MAGIC_SIGNATURES.items():
        if data.startswith(sig):
            return desc
    return None


def find_all(data, needle):
    """Tìm TẤT CẢ vị trí xuất hiện của chuỗi bytes `needle` trong `data`.

    Hữu ích để: tìm file nhúng (ví dụ tìm tất cả 'PK\\x03\\x04' = các zip bên trong),
    tìm chữ ký, tìm marker,...
    Trả về list các offset.
    """
    offsets = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1     # +1 để tìm cả các vị trí chồng lấn
    return offsets


def scan_known_magics(data):
    """Quét toàn file tìm mọi magic đã biết (không chỉ ở đầu file).

    Rất hữu ích để phát hiện file nhúng / dữ liệu bị nối thêm (appended data).
    """
    print("[*] Quet magic trong toan file:")
    for sig, desc in MAGIC_SIGNATURES.items():
        locs = find_all(data, sig)
        if locs:
            shown = ", ".join(hex(o) for o in locs[:10])
            more = " ..." if len(locs) > 10 else ""
            print(f"    {desc:40s} tai offset: {shown}{more}")


# ---------------------------------------------------------------------------
# PHẦN 3: PARSE PE (Windows) BẰNG pefile
# ---------------------------------------------------------------------------

def parse_pe(path, verbose=True):
    """Parse 1 file PE (.exe/.dll) bằng thư viện `pefile`.

    In ra: thông tin header, danh sách sections (tên, VA, kích thước, entropy),
    imports (DLL + hàm), và có resource hay không.
    Trả về đối tượng pefile.PE (để bạn khai thác tiếp).

    Yêu cầu: pip install pefile
    """
    try:
        import pefile
    except ImportError:
        print("[!] Chua cai pefile. Chay: pip install pefile")
        return None

    pe = pefile.PE(path, fast_load=False)

    if verbose:
        print("=" * 60)
        print("[PE] Thong tin co ban")
        print("=" * 60)
        # ImageBase: địa chỉ nạp mặc định; EntryPoint: RVA điểm vào
        print(f"  Machine        : 0x{pe.FILE_HEADER.Machine:04x}")
        print(f"  TimeDateStamp  : 0x{pe.FILE_HEADER.TimeDateStamp:08x}")
        print(f"  ImageBase      : 0x{pe.OPTIONAL_HEADER.ImageBase:x}")
        print(f"  EntryPoint RVA : 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        print(f"  La DLL         : {is_dll}")

        print("\n[PE] Sections:")
        print(f"    {'Name':8s} {'VA':>10s} {'VSize':>10s} {'RawOff':>10s} {'RawSize':>10s} {'Entropy':>8s}")
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
            print(f"    {name:8s} 0x{s.VirtualAddress:08x} 0x{s.Misc_VirtualSize:08x} "
                  f"0x{s.PointerToRawData:08x} 0x{s.SizeOfRawData:08x} {s.get_entropy():8.3f}")
            # Entropy ~ 7.9+ thường là dữ liệu nén/mã hóa -> đáng nghi!

        # Imports: hàm mà binary gọi -> gợi ý chức năng (crypto, network, file,...)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            print("\n[PE] Imports (rut gon):")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("latin-1", "replace")
                funcs = [imp.name.decode("latin-1", "replace")
                         for imp in entry.imports if imp.name]
                print(f"    {dll}: {', '.join(funcs[:12])}{' ...' if len(funcs) > 12 else ''}")

        # Resources (ảnh, string table, hoặc payload nhúng)
        has_rsrc = hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")
        print(f"\n[PE] Co resource (.rsrc): {has_rsrc}")

    return pe


def pe_rva_to_offset(pe, rva):
    """Chuyển RVA (Relative Virtual Address) -> offset vật lý trong file.

    Cần khi biết 1 địa chỉ ảo (ví dụ từ disassembler) và muốn đọc byte tại đó.
    """
    return pe.get_offset_from_rva(rva)


def pe_get_section_data(pe, section_name):
    """Lấy TOÀN BỘ dữ liệu raw của 1 section theo tên (ví dụ '.data', '.rdata').

    Thường dùng để trích vùng chứa chuỗi/khóa/cấu hình nhúng.
    Trả về bytes, hoặc None nếu không tìm thấy.
    """
    want = section_name.encode() if isinstance(section_name, str) else section_name
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") == want.rstrip(b"\x00"):
            return s.get_data()
    return None


def pe_dump_resources(pe, out_dir="pe_resources"):
    """Trích toàn bộ resource ra file (payload hay bị giấu trong .rsrc).

    Tạo thư mục out_dir rồi ghi mỗi resource leaf thành 1 file .bin.
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        print("[PE] Khong co resource.")
        return
    os.makedirs(out_dir, exist_ok=True)
    count = 0
    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for name_entry in getattr(type_entry, "directory", type_entry).entries:
            for lang_entry in getattr(name_entry, "directory", name_entry).entries:
                data_rva = lang_entry.data.struct.OffsetToData
                size = lang_entry.data.struct.Size
                blob = pe.get_data(data_rva, size)
                fname = os.path.join(out_dir, f"res_{count:03d}.bin")
                with open(fname, "wb") as f:
                    f.write(blob)
                print(f"    [+] {fname} ({size} byte)")
                count += 1
    print(f"[PE] Da trich {count} resource vao '{out_dir}/'")


# ---------------------------------------------------------------------------
# PHẦN 4: ĐỌC ELF (Linux)
# ---------------------------------------------------------------------------

def parse_elf_struct(data):
    """Đọc ELF header + bảng section CHỈ bằng struct (không cần thư viện ngoài).

    Hỗ trợ cả ELF32 và ELF64, cả Little/Big Endian.
    Trả về dict thông tin cơ bản + list sections [(name, type, addr, offset, size)].
    Tham chiếu cấu trúc: /usr/include/elf.h (Elf64_Ehdr / Elf64_Shdr).
    """
    if not data.startswith(b"\x7fELF"):
        print("[!] Khong phai file ELF (thieu magic 7f 45 4c 46).")
        return None

    ei_class = data[4]      # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]       # 1 = little-endian, 2 = big-endian
    is64 = (ei_class == 2)
    endian = "<" if ei_data == 1 else ">"

    info = {"class": "ELF64" if is64 else "ELF32",
            "endian": "LE" if ei_data == 1 else "BE"}

    if is64:
        # Elf64_Ehdr (phần sau e_ident 16 byte): H H I Q Q Q I H H H H H H
        (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
         e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
            struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
    else:
        # Elf32_Ehdr: H H I I I I I H H H H H H
        (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
         e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
            struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)

    info.update(e_type=e_type, e_machine=e_machine, e_entry=e_entry,
                e_shoff=e_shoff, e_shnum=e_shnum, e_shstrndx=e_shstrndx)

    print("=" * 60)
    print(f"[ELF] {info['class']} / {info['endian']} / machine=0x{e_machine:x} "
          f"entry=0x{e_entry:x}")
    print("=" * 60)

    # Đọc bảng section header string (.shstrtab) để lấy TÊN các section
    sections = []
    if e_shoff and e_shnum:
        # Lấy entry của section chứa tên (shstrndx) để biết nơi đặt bảng tên
        def read_shdr(idx):
            off = e_shoff + idx * e_shentsize
            if is64:
                # Elf64_Shdr: name(I) type(I) flags(Q) addr(Q) offset(Q) size(Q) ...
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                    struct.unpack_from(endian + "IIQQQQ", data, off)
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                    struct.unpack_from(endian + "IIIIII", data, off)
            return sh_name, sh_type, sh_addr, sh_offset, sh_size

        str_name, str_type, str_addr, str_off, str_size = read_shdr(e_shstrndx)
        shstrtab = data[str_off:str_off + str_size]

        def get_name(noff):
            end = shstrtab.find(b"\x00", noff)
            return shstrtab[noff:end].decode("latin-1", "replace")

        print(f"    {'Name':20s} {'Type':>6s} {'Addr':>12s} {'Offset':>10s} {'Size':>10s}")
        for i in range(e_shnum):
            sh_name, sh_type, sh_addr, sh_offset, sh_size = read_shdr(i)
            name = get_name(sh_name)
            sections.append((name, sh_type, sh_addr, sh_offset, sh_size))
            print(f"    {name:20s} {sh_type:6d} 0x{sh_addr:010x} "
                  f"0x{sh_offset:08x} 0x{sh_size:08x}")

    info["sections"] = sections
    return info


def parse_elf_pyelftools(path):
    """Phiên bản dùng `pyelftools` (nếu đã cài) - gọn và đầy đủ hơn.

    Yêu cầu: pip install pyelftools
    """
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        print("[!] Chua cai pyelftools. Chay: pip install pyelftools "
              "(hoac dung parse_elf_struct()).")
        return None

    with open(path, "rb") as f:
        elf = ELFFile(f)
        print("=" * 60)
        print(f"[ELF] class={elf.elfclass}  entry=0x{elf.header.e_entry:x}  "
              f"machine={elf['e_machine']}")
        print("=" * 60)
        for sec in elf.iter_sections():
            print(f"    {sec.name:20s} off=0x{sec['sh_offset']:08x} "
                  f"size=0x{sec['sh_size']:08x} addr=0x{sec['sh_addr']:x}")
        # TODO: lấy data 1 section cụ thể:  data = elf.get_section_by_name('.data').data()
    return True


# ---------------------------------------------------------------------------
# PHẦN 5: QUÉT XOR + TRÍCH CHUỖI / BLOB
# ---------------------------------------------------------------------------

def extract_strings(data, min_len=4):
    """Trích các chuỗi ASCII in được (giống lệnh `strings`).

    Trả về list (offset, chuoi). Dùng để nhanh chóng thấy text, URL, flag,...
    """
    results = []
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for m in pattern.finditer(data):
        results.append((m.start(), m.group().decode("latin-1")))
    return results


def extract_base64_blobs(data, min_len=20):
    """Tìm các blob trông giống base64 nhúng trong file và thử decode.

    Trả về list (offset, chuoi_b64, bytes_da_decode). Chỉ giữ blob decode được.
    """
    results = []
    # Mẫu base64: ký tự A-Za-z0-9+/ và '=' đệm ở cuối
    pattern = re.compile(rb"[A-Za-z0-9+/]{%d,}={0,2}" % min_len)
    for m in pattern.finditer(data):
        blob = m.group()
        try:
            decoded = base64.b64decode(blob, validate=True)
            # Lọc bớt nhiễu: chỉ giữ cái decode ra đủ dài
            if len(decoded) >= min_len // 2:
                results.append((m.start(), blob.decode("latin-1"), decoded))
        except (binascii.Error, ValueError):
            continue
    return results


def extract_hex_blobs(data, min_len=16):
    """Tìm các blob hex dài (chuỗi [0-9a-fA-F]) và decode thành bytes.

    min_len tính theo số KÝ TỰ hex (phải chẵn mới decode được).
    Trả về list (offset, chuoi_hex, bytes).
    """
    results = []
    pattern = re.compile(rb"(?:[0-9a-fA-F]{2}){%d,}" % (min_len // 2))
    for m in pattern.finditer(data):
        blob = m.group()
        try:
            decoded = bytes.fromhex(blob.decode("latin-1"))
            results.append((m.start(), blob.decode("latin-1"), decoded))
        except ValueError:
            continue
    return results


def xor_bytes(data, key):
    """XOR `data` với `key` (key lặp lại). key là int (1 byte) hoặc bytes.

    Trả về bytes kết quả.
    """
    if isinstance(key, int):
        return bytes(b ^ key for b in data)
    if len(key) == 0:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _printable_ratio(b):
    """Tỉ lệ ký tự in được trong 1 chuỗi bytes (0..1). Dùng để chấm điểm XOR."""
    if not b:
        return 0.0
    good = sum(1 for x in b if x in b"\t\r\n" or 32 <= x < 127)
    return good / len(b)


def xor_brute_single(data, min_ratio=0.9, sample=512):
    """Brute XOR 1-byte: thử key 0..255, in các key cho ra nhiều ký tự in được.

    data      : dữ liệu (sẽ chỉ lấy `sample` byte đầu để chấm điểm cho nhanh).
    min_ratio : ngưỡng tỉ lệ ký tự in được để coi là "ứng viên".
    Trả về list (key, ratio, preview) sắp theo ratio giảm dần.
    """
    probe = data[:sample]
    candidates = []
    for key in range(256):
        dec = xor_bytes(probe, key)
        ratio = _printable_ratio(dec)
        if ratio >= min_ratio:
            preview = dec[:60].decode("latin-1", "replace")
            candidates.append((key, ratio, preview))
    candidates.sort(key=lambda t: t[1], reverse=True)
    for key, ratio, preview in candidates:
        print(f"    key=0x{key:02x} ratio={ratio:.2f} | {preview!r}")
    return candidates


def xor_find_key_from_known(cipher, known_plain, known_off=0):
    """XOR known-plaintext: suy ra khóa khi biết 1 đoạn plaintext.

    Nguyên lý:  key = cipher XOR plaintext  (tại cùng vị trí).
    cipher      : toàn bộ dữ liệu mã hóa.
    known_plain : đoạn plaintext đã biết (bytes), ví dụ b"flag{" hoặc b"\\x89PNG".
    known_off   : offset của đoạn đó trong cipher (mặc định 0 = đầu file).
    Trả về key (bytes) tìm được. Nếu plaintext là cả chu kỳ key thì giải được hết.
    """
    seg = cipher[known_off:known_off + len(known_plain)]
    key = bytes(c ^ p for c, p in zip(seg, known_plain))
    print(f"    [known-plaintext] key ung vien = {key!r}  (hex: {key.hex()})")
    return key


# ---------------------------------------------------------------------------
# MAIN - CHẠY THỬ NHANH
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\n[demo struct]")
        demo_struct()
        print("\n[!] Cach dung: python tmpl_fileparse.py <file>")
        return

    path = sys.argv[1]
    data = read_file(path)
    print(f"[*] File: {path}  ({len(data)} byte)")

    # 1) Nhận diện loại file qua magic
    kind = identify_magic(data)
    print(f"[*] Magic dau file: {data[:8].hex()}  -> {kind or 'khong ro'}")

    # 2) Hexdump 256 byte đầu
    print("\n[*] Hexdump 256 byte dau:")
    hexdump(data, 256)

    # 3) Quét magic trong toàn file (phát hiện file nhúng)
    print()
    scan_known_magics(data)

    # 4) Nếu là PE -> parse PE; nếu là ELF -> parse ELF
    if data.startswith(b"MZ"):
        print()
        parse_pe(path)
    elif data.startswith(b"\x7fELF"):
        print()
        parse_elf_struct(data)

    # 5) Gợi ý: trích blob base64 (bật nếu cần)
    # TODO: bỏ comment để quét base64 nhúng
    # for off, b64, dec in extract_base64_blobs(data)[:5]:
    #     print(f"[b64] off=0x{off:x} -> {dec[:40]!r}")

    # TODO: Tùy bài, gọi thêm:
    #   - carve_to_file(data, offset, length, "out.bin")  # tách file nhúng
    #   - xor_brute_single(data)                          # dò XOR 1 byte
    #   - key = xor_find_key_from_known(data, b"flag{")   # XOR known-plaintext
    #   - sec = pe_get_section_data(parse_pe(path, False), ".data")  # lấy .data


if __name__ == "__main__":
    main()
