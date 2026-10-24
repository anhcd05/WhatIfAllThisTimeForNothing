#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
realign_helper.py — Công cụ patch byte rác (anti-disassembly) phục vụ PHÂN TÍCH/GIẢI CTF.

Mục đích:
  - Ghi đè một vùng byte bằng NOP (0x90) để "khử" byte rác sau jcc / jmp-vào-giữa-lệnh,
    giúp disassembler (Ghidra/IDA/radare2) căn thẳng hàng lại và hiện đúng code.
  - HOẶC đổi đúng 1 byte opcode (vd 0x74 'jz' -> 0xEB 'jmp short') để ép một
    điều kiện giả (opaque predicate) thành nhảy vô điều kiện.
  - Luôn GHI RA FILE MỚI (không đụng file gốc), kèm hexdump TRƯỚC/SAU quanh offset
    để kiểm tra bằng mắt.

KHÔNG tải/chạy binary lạ bằng script này — đây chỉ là công cụ chỉnh byte tĩnh (offline).

Cách dùng:
  # 1) NOP hoá 1 byte rác E8 tại offset 0x401 (vd byte rác sau jz/jnz):
  python realign_helper.py sample.exe 0x401 --len 1

  # 2) NOP hoá 5 byte (vd nuốt trọn một 'call rel32' giả):
  python realign_helper.py sample.exe 0x401 --len 5

  # 3) Đổi 1 byte: 0x74 (jz) -> 0xEB (jmp short) tại offset 0x120:
  python realign_helper.py sample.exe 0x120 --set 0xEB

  # 4) Chỉ xem hexdump quanh offset mà KHÔNG patch (--dry-run):
  python realign_helper.py sample.exe 0x120 --len 1 --dry-run

Lưu ý: OFFSET ở đây là FILE OFFSET (vị trí byte trong file trên đĩa), KHÔNG phải
địa chỉ ảo (VA/RVA). Trong IDA/Ghidra dùng chức năng "jump to file offset" hoặc tự
quy đổi VA -> file offset qua bảng section trước khi patch. (# TODO: thêm quy đổi tự động)
"""

import argparse
import os
import sys

# Ép stdout/stderr sang UTF-8 để in tiếng Việt không lỗi trên console Windows (cp1252).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass  # bản Python quá cũ hoặc stream đã bị thay thế -> bỏ qua

NOP = 0x90  # opcode NOP trên x86/x64


def hexdump(data, center, width=16, context=2):
    """In hexdump quanh vị trí 'center'.

    center : offset trung tâm cần soi.
    width  : số byte mỗi dòng (mặc định 16).
    context: số DÒNG hiển thị trước và sau dòng chứa 'center'.
    Dòng chứa offset trung tâm được đánh dấu '>>'.
    """
    # Căn về đầu dòng chứa center, rồi lùi/tiến theo số dòng context.
    line_start = (center // width) * width
    start = max(0, line_start - context * width)
    end = min(len(data), line_start + (context + 1) * width)

    out = []
    for base in range(start, end, width):
        chunk = data[base:base + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        # Phần ASCII in được, byte không in được thay bằng '.'
        ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        marker = ">>" if base <= center < base + width else "  "
        # Đánh dấu thêm vị trí byte center bằng dấu '^' ở dòng dưới sẽ rối,
        # nên chỉ cần marker '>>' ở đầu dòng là đủ để định vị.
        out.append(f"{marker} {base:08X}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(out)


def make_out_path(in_path):
    """Sinh tên file xuất: 'ten.ext' -> 'ten.patched.ext'."""
    root, ext = os.path.splitext(in_path)
    return f"{root}.patched{ext}"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Patch byte rác anti-disassembly -> NOP, hoặc đổi 1 byte opcode. "
                    "Ghi ra file mới, kèm hexdump trước/sau."
    )
    ap.add_argument("file", help="File đầu vào (binary cần patch).")
    ap.add_argument("offset", help="FILE OFFSET bắt đầu patch (hex 0x.. hoặc thập phân).")

    # Hai chế độ loại trừ nhau: NOP một vùng, HOẶC set đúng 1 byte.
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--len", type=int, metavar="N",
                      help="Ghi NOP (0x90) cho N byte kể từ offset.")
    mode.add_argument("--set", metavar="BYTE",
                      help="Đổi ĐÚNG 1 byte tại offset thành giá trị BYTE (vd 0xEB).")

    ap.add_argument("-o", "--out", help="Đường dẫn file xuất (mặc định: *.patched.*).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Chỉ hiển thị hexdump trước/sau, KHÔNG ghi file.")
    args = ap.parse_args(argv)

    # Parse offset: hỗ trợ cả 0x.. lẫn thập phân.
    try:
        offset = int(args.offset, 0)
    except ValueError:
        ap.error(f"offset không hợp lệ: {args.offset!r}")

    # Đọc toàn bộ file vào bytearray (để sửa được).
    try:
        with open(args.file, "rb") as f:
            data = bytearray(f.read())
    except OSError as e:
        ap.error(f"không mở được file: {e}")

    size = len(data)
    if not (0 <= offset < size):
        ap.error(f"offset {offset:#x} nằm ngoài file (kích thước {size:#x}).")

    # Xác định vùng/byte sẽ bị thay đổi và nội dung mới.
    if args.len is not None:
        if args.len <= 0:
            ap.error("--len phải > 0.")
        if offset + args.len > size:
            ap.error(f"vùng patch [{offset:#x}, {offset + args.len:#x}) vượt quá file.")
        patch_end = offset + args.len
        new_bytes = bytes([NOP]) * args.len
        action = f"NOP hoá {args.len} byte tại {offset:#x}"
    else:
        # Chế độ --set: đổi đúng 1 byte.
        try:
            val = int(args.set, 0)
        except ValueError:
            ap.error(f"--set không hợp lệ: {args.set!r}")
        if not (0 <= val <= 0xFF):
            ap.error("--set phải trong khoảng 0x00..0xFF.")
        patch_end = offset + 1
        new_bytes = bytes([val])
        action = f"đổi byte tại {offset:#x}: {data[offset]:#04x} -> {val:#04x}"

    # --- Hiển thị TRƯỚC ---
    print(f"[*] File   : {args.file}  ({size} bytes)")
    print(f"[*] Hành động: {action}")
    print("\n===== HEXDUMP TRƯỚC =====")
    print(hexdump(data, offset))

    # Áp patch lên bản sao trong bộ nhớ.
    data[offset:patch_end] = new_bytes

    print("\n===== HEXDUMP SAU =====")
    print(hexdump(data, offset))

    if args.dry_run:
        print("\n[dry-run] Không ghi file. Bỏ cờ --dry-run để lưu thật.")
        return 0

    out_path = args.out or make_out_path(args.file)
    # An toàn: không ghi đè file gốc trừ khi người dùng cố tình chỉ định trùng tên.
    if os.path.abspath(out_path) == os.path.abspath(args.file):
        ap.error("file xuất trùng file gốc — hãy đặt --out khác để tránh ghi đè bản gốc.")
    try:
        with open(out_path, "wb") as f:
            f.write(data)
    except OSError as e:
        ap.error(f"không ghi được file xuất: {e}")

    print(f"\n[+] Đã ghi file đã patch: {out_path}")
    print("[i] Mở lại bằng Ghidra/IDA/radare2 và re-disassemble để kiểm tra luồng.")
    return 0


# TODO (mở rộng khi cần trong giải):
#   - Quy đổi VA/RVA -> file offset tự động bằng cách đọc PE/ELF section headers
#     (vd dùng pefile / lief) để nhập thẳng địa chỉ ảo từ IDA.
#   - Chế độ "ép jmp rel32": ghi E9 + rel32 cho mẫu 'push addr; ret' (tính rel32 từ đích).
#   - Chế độ patch nhiều offset một lượt (nhận danh sách từ file .txt).
#   - Tự nhận diện mẫu rogue byte (vd quét 74 ?? 75 ?? E8 ...) và gợi ý offset cần NOP.

if __name__ == "__main__":
    sys.exit(main())
