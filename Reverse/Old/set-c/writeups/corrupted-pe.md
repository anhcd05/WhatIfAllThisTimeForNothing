# corrupted-pe

- **Category:** Reverse Engineering / Forensics (PE header repair)
- **File đề:** `challenges/corrupted-pe/corrupted.exe` (114698 byte, md5 `01d9f9e15295f86d368fde1e19dfc283`); kèm `description.txt` và `fix_corrupted.py` (script vá sẵn).

## Tóm tắt đề

Một file thực thi "đã bị tampered" nên không chạy được. Nhiệm vụ: **khôi phục** file rồi chạy (không tham số) để lấy flag. Định dạng: `flag{string}`.

Toàn bộ phân tích dưới đây là **tĩnh**: chỉ đọc/ghi byte và đọc disassembly, **không thực thi** binary.

## Phân tích (chi tiết: offset/magic bytes thật)

### 1. Vì sao file "không nhận ra"

`file corrupted.exe` trả về:

```
corrupted.exe: TTComp archive data, binary, 1K dictionary
```

`file` đoán nhầm vì 2 byte đầu **không phải** `MZ` — nó khớp ngẫu nhiên một chữ ký định dạng khác. Đây là bằng chứng đầu tiên rằng header đã hỏng.

### 2. Mổ 64 byte đầu file hỏng (xxd thật trên file)

```
00000000: 0004 9901 4001 b1a3 0000 5a5a 9000 0300  ....@.....ZZ....
00000010: 0000 0400 0000 ffff 0000 b800 0000 0000  ................
00000020: 0000 4000 0000 0000 0000 0000 0000 0000  ..@.............
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0001 0000 0e1f ba0e 00b4  ................
```

Phân tích từng vùng, so với một **DOS header chuẩn**:

| Offset (file hỏng) | Byte | Ý nghĩa |
|---|---|---|
| `0x00`–`0x09` | `00 04 99 01 40 01 b1 a3 00 00` | **10 byte rác chèn thêm** — không thuộc cấu trúc PE |
| `0x0A`–`0x0B` | `5a 5a` (`"ZZ"`) | *Đáng lẽ* là magic `MZ` nhưng byte đầu bị đổi `4D`→`5A` (M→Z) |
| `0x0C`… | `90 00 03 00 00 00 04 00 00 00 ff ff …` | Khớp y hệt `e_cblp, e_cp, e_crlc…` của DOS header chuẩn |

Mẫu `90 00 03 00 00 00 04 00` ngay sau magic là chữ ký **rất đặc trưng** của DOS header do MSVC/MinGW sinh → xác nhận: chỉ sai **10 byte đầu + 1 byte magic**, phần còn lại nguyên vẹn.

### 3. Cấu trúc PE cần nhớ (để biết "tại sao" sửa như vậy)

- **Magic bytes:** mọi PE/Windows exe phải bắt đầu bằng `4D 5A` = ASCII `"MZ"` (DOS header). Nếu 2 byte đầu sai, Windows loader từ chối nạp.
- **`e_lfanew` tại offset `0x3C`:** 4 byte little-endian, trỏ tới NT header (bắt đầu bằng `PE\0\0` = `50 45 00 00`).

Sau khi bỏ 10 byte rác, offset trong file dịch lùi 10. Offset `0x3C` của file **đã sửa** tương ứng offset `0x46` của file hỏng. Tại đó các byte là `00 01 00 00` → `e_lfanew = 0x00000100`. NT signature `PE\0\0` nằm tại offset `0x100` của file đã sửa (= offset `0x10A` file gốc).

### 4. Hai lỗi và cách sửa

```
corrupted: 00 04 99 01 40 01 b1 a3 00 00 | 5a 5a 90 00 03 00 00 00 04 00 ...
                  (10 byte rác)             ZZ ...
restored :                                   4d 5a 90 00 03 00 00 00 04 00 ...  -> "MZ"
```

1. **Thừa 10 byte rác ở đầu** → bỏ `data[:10]`. Byte kế là `5a 5a`.
2. **Magic sai** → cần `4d 5a` (`MZ`) nhưng đang `5a 5a` (`ZZ`). Ép byte[0] `0x5A`→`0x4D` (`'Z'`→`'M'`). Byte[1] đã sẵn `0x5A` (`Z`). → Thành `MZ`.

*Vì sao đúng 10 byte và chỉ sửa 1 byte?* Vì sau khi bỏ 10 byte, phần còn lại khớp hoàn toàn cấu trúc PE **trừ** byte đầu (`Z` thay vì `M`). Không sửa thêm gì khác → chứng tỏ chỉ 2 lỗi này.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **PE header repair / file carving:** nhận ra file "không chạy" vì magic sai. VÌ SAO nhận ra: `file` báo định dạng lạ, nhưng xa hơn trong file có chuỗi `This program cannot be run in DOS mode`, bảng import KERNEL32 → chắc chắn là PE hỏng header, chỉ cần vá đầu file.
- **Nhận diện byte rác prepend:** tìm vị trí mà **từ đó trở đi** khớp mẫu DOS header chuẩn (`90 00 03 00 00 00 04 00`). Đây là cách chắc ăn để biết "bỏ bao nhiêu byte" thay vì đoán mò.
- **Đọc disassembly thay vì chạy:** VÌ SAO — yêu cầu "không execute binary tải về". Flag dựng từ format string trong `main`, đọc được tĩnh bằng Ghidra/IDA/objdump → an toàn và vẫn ra flag.

## Lời giải chi tiết (chạy lại được)

### Bước 1 — Vá file (data-only, KHÔNG exec)

`fix_corrupted.py`:

```python
def fix_corrupted_exe(input_file, output_file):
    data = open(input_file, 'rb').read()
    data = data[10:]            # 1) bỏ 10 byte rác đầu  -> "ZZ..."
    data = b'M' + data[1:]      # 2) ép byte[0] 0x5A->0x4D ('Z'->'M') -> "MZ..."
    open(output_file, 'wb').write(data)

fix_corrupted_exe("corrupted.exe", "restored.exe")
```

```bash
python3 fix_corrupted.py        # corrupted.exe -> restored.exe
```

### Bước 2 — Kiểm chứng PE hợp lệ (đọc, không chạy)

```bash
xxd -l 16 restored.exe
# 00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000   MZ..............
```

Bằng `pefile` (chỉ parse, không thực thi):

```
Machine:    0x14c   -> IMAGE_FILE_MACHINE_I386  (PE32, 32-bit)
e_lfanew:   0x100
Signature:  0x4550  -> b"PE\0\0"
Subsystem:  3       -> WINDOWS_CUI (console)
EntryPoint: 0x160f (RVA)   ImageBase: 0x400000
Sections: .text (VA 0x1000) .rdata (VA 0x14000) .data (VA 0x1b000) .reloc (VA 0x1d000)
```

### Bước 3 — Đọc `main` để ráp flag (disassembly tĩnh)

`objdump -d -M intel restored.exe`, đoạn ráp flag:

```asm
4012a6:  push 0x4141c8        ; -> "now"
4012ab:  push 0x4141c0        ; -> "magic"
4012b0:  push 0x414214        ; -> "the"
4012b5:  push 0x414198        ; -> "find"
4012ba:  push 0x41b03c        ; -> "flag{%sing_%s_%s_%s!}\n"
         call printf
```

Đọc nội dung tại từng VA (đổi VA→file offset qua section):

```
0x414198 -> b'find'     0x414214 -> b'the'
0x4141c0 -> b'magic'    0x4141c8 -> b'now'
0x41b03c -> b'flag{%sing_%s_%s_%s!}\n'
```

C đẩy tham số lên stack **phải→trái**, nên thứ tự in thật là `printf(fmt, "find", "the", "magic", "now")`. Quy tắc `%sing` với `"find"` → `find`+`ing` = `finding`. Ghép lại:

```c
printf("flag{%sing_%s_%s_%s!}\n", "find", "the", "magic", "now");
// => finding_the_magic_now!
```

> Chi tiết thêm (từ `strings restored.exe`): chương trình còn là một "flag encoder" — chạy không tham số thì in flag, chạy có tham số thì "mã hóa" (có chuỗi seed `7qrnsZ6fJuTHe4Ia`, `Usage: %s <flag>`, `Obfuscated: %s`). Ta **không chạy**; mọi kết luận suy từ disassembly + strings. Import chỉ có KERNEL32 (console thường, `WriteConsoleW` là đường ra của `printf`); `IsDebuggerPresent` chỉ là boilerplate CRT, không phải anti-debug.

## Flag

```
flag{finding_the_magic_now!}
```

"Finding the magic now" — chơi chữ với **magic bytes** vừa phải sửa.

## Gặp lại thì xử lý thế nào (playbook)

- **Dấu hiệu dạng bài:** file "exe hỏng không chạy"; `file` báo data/định dạng lạ; nhưng bên trong vẫn có dấu vết PE/ELF (`This program cannot be run in DOS mode`, tên DLL import).
- **Quy trình:**
  1. Hexdump đầu file (`xxd -l 64`). Kỳ vọng `4D 5A` (PE) hoặc `7F 45 4C 46` (ELF).
  2. Nếu lệch: dò xem có **byte rác prepend** không bằng cách tìm vị trí mà từ đó khớp mẫu header chuẩn. Mẫu DOS: `MZ 90 00 03 00 00 00 04 00`. Mẫu ELF: `7F 45 4C 46`.
  3. Căn chỉnh: bỏ byte thừa và/hoặc sửa magic sao cho `e_lfanew` tại `0x3C` trỏ đúng tới `PE\0\0`.
  4. Kiểm bằng `pefile`/`readelf` (parse, không chạy). Nếu ngại chạy exe lạ: `objdump -d` đọc `main` rồi ráp flag thủ công.
- **Bẫy hay gặp:** (a) chỉ sửa magic mà quên bỏ byte rác (hoặc ngược lại) → vẫn hỏng; (b) đoán sai số byte rác → lệch toàn bộ offset; (c) `strings | grep flag` ra `flag{%sing_%s_%s_%s!}` rồi **dừng** mà quên nối `find+ing` → flag thiếu chữ.
- **Checklist ngắn:** magic đúng chưa? có byte prepend? `e_lfanew@0x3C` → `PE\0\0`? đọc `main`/chạy sandbox không args.
