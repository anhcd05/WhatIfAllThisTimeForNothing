# seh-crackme

- **Category:** Reversing
- **File đề:** `seh-crackme.zip` — 60.084 byte — MD5 `55a2c49b065416cfe442c1be90600ae3`. Bên trong: `seh-crack.exe` (giải nén 62.464 byte, CRC32 **`0x4fdbfd7a`**). ⚠️ `.exe` bị **mã hóa ZipCrypto** nên không trích được tĩnh (xem phần Flag).

## Tóm tắt đề
Reverse một file thực thi để tìm "key" đúng rồi lấy flag. Lời giải gốc minh họa bằng Cutter. Điểm đặc biệt: code quyết định key **ẩn trong trình xử lý ngoại lệ (exception handler)** được kích hoạt bằng lỗi **chia-cho-0**, kèm chống debug — nên chạy thẳng trong debugger dễ bị lệch luồng.

## Phân tích (chi tiết: header ZIP + logic SEH)
**Trinh sát ZIP (xác minh thật bằng `xxd` + `zipfile`):** local file header của `seh-crackme.zip`:
```
0000: 50 4B 03 04 14 00 01 00 08 00 32 32 4F 59 7A FD   PK........22OYz.
0010: DB 4F 14 EA 00 00 00 F4 00 00 0D 00 00 00 52 65   .O............Re
0020: 76 65 72 73 65 4D 65 2E 65 78 65 D5 89 D9 C6 09   verseMe.exe.....
```
Giải mã: `50 4B 03 04` = local header; `14 00` = version 2.0; **`01 00`** = general purpose flag ⇒ **bit 0 = 1 = encrypted**; **`08 00`** = method 8 = deflate; CRC32 (LE `7A FD DB 4F`) = **`0x4FDBFD7A`**; comp size `0x0000EA14` = 59.924; filename len `0x000D` = 13 ("seh-crack.exe"). `python zipfile` xác nhận lại: `flag_bits=0x1`, `compress_type=8`, **không** có extra field AES `0x9901` ⇒ là **ZipCrypto cổ điển (PKWARE)**, không phải AES. Ngay sau tên file (offset `0x2B`) là **12 byte encryption header** `D5 89 D9 C6 09 CF 2A 9D BE EB E4 F2`, rồi mới tới luồng deflate đã mã hóa.

**Nguyên lý ZipCrypto (PKWARE):** 3 khóa 32-bit `key0/key1/key2` khởi tạo từ mật khẩu; cập nhật qua bảng CRC-32:
```
update_keys(c):
    key0 = crc32(key0, c)                      # đa thức 0xEDB88320
    key1 = (key1 + (key0 & 0xff)) * 134775813 + 1
    key2 = crc32(key2, key1 >> 24)
decrypt_byte(): tmp = key2 | 2; return ((tmp * (tmp ^ 1)) >> 8) & 0xff
```
Giải mỗi byte: `plain = c XOR decrypt_byte()` rồi `update_keys(plain)` (**feedback bằng plaintext**). Byte thứ 12 của header sau giải mã phải bằng `(CRC32 >> 24) = 0x4F` → dùng làm "check byte" loại mật khẩu sai tức thì (vì sao `unzip` báo sai rất nhanh). Khóa nội bộ 2^96 lớn nhưng **Biham–Kocher** hạ xuống khả thi khi biết ≥12 byte plaintext của **luồng đã deflate** (công cụ `bkcrack`).

**Logic SEH Crackme (tái dựng từ solution PDF, không chạy):**
- `main` kiểm tra tham số dòng lệnh và `IsDebuggerPresent` nhưng **không** xử lý giá trị tham số theo luồng thường.
- Code đích nằm trong **exception handler** kích hoạt bởi **chia-cho-0 (SEH)**.
- Trong handler có đoạn so sánh input với **các mảnh chuỗi hard-code**; ghép đúng **offset/thứ tự** cho ra key.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Đọc header ZIP để xác định loại mã hóa:** VÌ SAO: phân biệt ZipCrypto vs AES quyết định hướng bẻ khóa; ở đây bit0=1 + không có `0x9901` ⇒ ZipCrypto.
- **Known-plaintext ZipCrypto (bkcrack):** VÌ SAO: ZipCrypto cổ điển yếu — biết ≥12 byte plaintext của luồng deflate → khôi phục trực tiếp `(key0,key1,key2)` không cần mật khẩu.
- **Static RE + đặt bẫy tại exception handler (Cutter/Ghidra):** VÌ SAO: logic thật ẩn trong SEH chia-0 + có `IsDebuggerPresent`; chạy thẳng debugger làm sai luồng → đọc tĩnh graph, theo con trỏ handler.

## Lời giải chi tiết (bước + lệnh sạch)
1. *(Nếu có công cụ)* bẻ ZipCrypto bằng known-plaintext:
   ```bash
   bkcrack -L seh-crackme.zip                                  # xem thông tin
   bkcrack -C seh-crackme.zip -c seh-crack.exe -p <known_deflate_bytes> -o <offset>
   bkcrack -C seh-crackme.zip -c seh-crack.exe -k <k0> <k1> <k2> -d seh-crack.exe
   ```
2. Mở `.exe` bằng Cutter/Ghidra; **đặt bẫy tại exception handler** (không chạy thẳng); vượt `IsDebuggerPresent` (patch trả 0 / ScyllaHide).
3. Đọc các mảnh chuỗi hard-code trong handler, ghép theo offset → key; nhập key → nhận flag.

## Flag
flag{...}

> **Nguồn không nêu.** `SOLUTIONS_VN.md` ghi rõ: `.exe` trong ZIP bị mã hóa **ZipCrypto**, môi trường không có `bkcrack`/`hashcat`, đã thử ~40 mật khẩu ngữ cảnh đều sai → **không trích được `.exe` để disassembly**, và solution PDF gốc **không in flag/key**. Do đó giá trị flag chính xác chưa xác định được từ tài liệu hiện có; chỉ nêu phương pháp. (Lưu ý: tên file nội bộ trong ZIP là `ReverseMe.exe`, khớp bản nháp `ReverseMe.md`.)

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** `main` có `IsDebuggerPresent` + arguments "không xử lý"; có thao tác chia tạo divide-by-zero; logic ẩn trong SEH/exception handler. ZIP báo "incorrect password" rất nhanh (check byte ZipCrypto).
- **Quy trình:** (1) đọc header ZIP xác định mã hóa (ZipCrypto vs AES `0x9901`); (2) nếu ZipCrypto + có plaintext deflate → `bkcrack`; (3) đọc tĩnh `main`, tìm khối thiết lập handler + điểm cố tình gây ngoại lệ, theo con trỏ handler tới code thật; (4) gom fragment theo offset → ghép key; (5) nếu buộc dynamic: cấu hình debugger pass/ignore đúng loại exception.
- **Công cụ:** `xxd`/`zipfile`, `bkcrack`, Cutter/Ghidra/IDA, ScyllaHide.
- **Bẫy:** biết plaintext **chưa nén** (`MZ`, DOS stub) là **không đủ** — ZipCrypto mã hóa luồng **đã deflate**; debugger bắt divide-by-zero làm sai luồng; ghép fragment sai thứ tự → key sai.
