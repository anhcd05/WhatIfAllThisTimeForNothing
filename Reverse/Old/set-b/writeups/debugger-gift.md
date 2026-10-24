# debugger-gift

- **Category:** Binary
- **File đề:** `debugger-gift/present.zip` (17375 bytes, md5 `1ad90fb03793391a6c1f05c2e8c246db`) chứa `present.exe` (bản nén UPX). Repo kèm `present-unpack.exe` (đã gỡ UPX, md5 `432a864ed1b5f0afe7567d0072511480`) và `present-patched.exe` (đã patch, md5 `b22705c0e277d66103bb9c661d427b7d`). PE32 console Intel i386, 14 sections, EntryPoint `0x12d0`, ImageBase `0x400000`.

## Tóm tắt đề

File `present.exe` khi chạy chỉ in `Oops...`. Nó bị **nén UPX**, bên trong có dùng **`IsDebuggerPresent()`** (anti-debug) và giấu một chuỗi Base64 chính là flag. Phải gỡ UPX, hiểu luồng rẽ nhánh và lấy flag ra.

## Phân tích (chi tiết)

**Gỡ UPX trước.** File gốc packed (section `UPX0`/`UPX1`, entropy cao). `upx -d present.exe -o present-unpack.exe` để lộ mã gốc.

`strings -a present-unpack.exe | grep -iE "oops|debug|flag"` cho: `Oops...`, `Debugger`, `IsDebuggerPresent`, và symbol `_flag` (file còn debug info). Đọc IAT bằng `pefile` xác nhận import `IsDebuggerPresent` từ KERNEL32.

Disassembly `_main` (`objdump -d -M intel present-unpack.exe`):

```asm
00401410 <_main>:
  40141f: mov BYTE  [esp+0x5f], 0x1          ; cờ nội bộ = 1
  401424: mov DWORD [esp+0x14], 0x68786d5a   ; dựng chuỗi trên stack (dword #1)
  40142c: mov DWORD [esp+0x18], 0x5574335a   ; dword #2
  ...                                         ; tổng 13 dword liên tiếp -> 1 chuỗi Base64
  401484: mov DWORD [esp+0x44], 0x3d3d5166   ; dword #13 ("fQ==")
  4014c4: call <_IsDebuggerPresent@0>        ; eax = có debugger?
  4014c9: test eax, eax
  4014cb: jne  4014f5                         ; nếu CÓ debugger -> in "Debugger"
  4014cd: movzx eax, BYTE [esp+0x5f]          ; eax = 1
  4014d2: xor  eax, 0x1                        ; eax = 1 ^ 1 = 0
  4014d5: test al, al
  4014d7: je   4014e7         ; <== opcode 74 ; vì al==0 -> NHẢY tới in "Oops..."
  4014d9: lea  eax, [esp+0x14]                 ; (nhánh KHÔNG nhảy) -> puts(chuỗi Base64 = FLAG)
  4014e0: call <_puts>
  4014e7: ... call _printf ("Oops...")        ; chuỗi tại 0x405044
  4014f5: ... call _printf ("Debugger")       ; chuỗi tại 0x40504c
```

Logic:
- Không debugger + cờ=1 → `1 ^ 1 = 0` → `je` nhảy → in **"Oops..."** (đường chạy mặc định).
- Có debugger → in **"Debugger"**.
- Muốn tới `puts(chuỗi Base64)` (in flag) thì `je` tại `0x4014d7` phải **không** nhảy, tức cần `al != 0`.

**Hướng sai đã loại:** tưởng phải "đánh lừa IsDebuggerPresent" (patch nhánh `jne 4014f5`). Nhưng nhánh đó chỉ rẽ sang "Debugger"; nhánh quyết định in flag là `je 4014d7`. Patch đúng chỗ là đổi `je` (opcode `74`) → `jne` (opcode `75`).

**Chuỗi flag nằm sẵn trên stack.** 13 dword little-endian ghép lại thành một chuỗi Base64 — không cần chạy, chỉ cần đọc byte và decode.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **`upx -d` gỡ nén** — VÌ file packed chỉ chứa stub, đọc tĩnh không thấy mã gốc.
- **Nhận diện & bỏ qua anti-debug `IsDebuggerPresent`** — VÌ nó chỉ rẽ sang nhánh "Debugger"; biết được để không patch nhầm.
- **Patch `jz`→`jnz` (74→75)** — VÌ đảo 1 byte điều kiện là cách kinh điển đổi luồng để chương trình đi vào nhánh in flag.
- **Giải mã chuỗi stack bằng Python (static)** — VÌ flag đã có sẵn dạng Base64 trong lệnh `mov`; decode offline là nhanh và an toàn nhất.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

**Bước 1 — Gỡ UPX.**

```bash
upx -d present.exe -o present-unpack.exe
```

**Bước 2 — Giải mã chuỗi stack (không cần chạy).** Ghép 13 dword little-endian rồi Base64-decode:

```python
import struct, base64
dw = [0x68786d5a,0x5574335a,0x554e5652,0x42563058,0x666c3155,0x664e5653,0x43564552,
      0x48645556,0x664a5652,0x464a4655,0x4f563055,0x68454356,0x3d3d5166]
b = b''.join(struct.pack('<I', d) for d in dw)
print(b.decode())                    # ZmxhZ3tURVNUX0VBU1lfSVNfREVCVUdHRVJfUFJFU0VOVCEhfQ==
print(base64.b64decode(b).decode())  # flag{TEST_EASY_IS_DEBUGGER_PRESENT!!}
```

**Bước 3 (hướng thay thế) — Patch rồi chạy trong VM.** Chỉ cần sửa 1 byte tại file-offset 2263 (0-based): `0x74` (je) → `0x75` (jne). Kiểm chứng với bản `present-patched.exe` do repo cung cấp:

```bash
cmp -l present-unpack.exe present-patched.exe
# 2264 164 165   -> giá trị OCTAL: 0o164=0x74 (je) -> 0o165=0x75 (jne), đúng 1 byte
```

Chạy bản patched in ra chuỗi Base64 ở trên → decode ra flag. (Cách không patch: chạy trong debugger và sửa cờ ZF, hoặc sửa giá trị `[esp+0x5f]` lúc runtime.)

## Flag

```
flag{TEST_EASY_IS_DEBUGGER_PRESENT!!}
```

Chơi chữ "present" (món quà / IsDebugger**Present**) — bài dạy nhận diện & vô hiệu hóa anti-debug.

## Gặp lại thì xử lý thế nào (playbook)

1. File `.exe` entropy cao / section `UPX0` ⇒ gỡ `upx -d` trước khi làm bất cứ gì.
2. Thấy import `IsDebuggerPresent`/`CheckRemoteDebuggerPresent`/`NtQueryInformationProcess` ⇒ có anti-debug; xác định đúng nhánh *quyết định in flag* chứ không chỉ nhánh "bị bắt debugger".
3. Chuỗi dựng bằng loạt `mov DWORD [esp+off], imm` là **stack string**: ghép theo đúng offset, thường ra Base64/plaintext.
4. Patch điều kiện: `74`↔`75` (je/jne), `0F 84`↔`0F 85` (je/jne near). Dùng `cmp -l` so sánh với bản mẫu để xác nhận chỉ 1 byte đổi.
5. Luôn chỉ chạy exe lạ trong VM cách ly.
