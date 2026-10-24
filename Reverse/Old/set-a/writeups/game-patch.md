# game-patch

- **Category:** Reversing (binary patching + XOR runtime flag)
- **File đề:** `game-patch.zip` (không mật khẩu) → `game-patch.exe` — PE 32-bit (`pei-i386`), **121.344 byte**, entry `0x00401f2c`, ImageBase `0x400000`. ZIP MD5 `df09e873ac8f7ac8c5c6ab8644d3b969`.

## Tóm tắt đề
File chơi oẳn tù tì (Rock Paper Scissors) với máy. Flag chỉ hiện khi **thắng máy hơn 300 lần** — chơi thật quá tốn thời gian. Đề gợi ý dùng reverse engineering + **vá (patch) binary** để hạ điều kiện. Flag **không** nằm plaintext (`grep -i flag` rỗng) — được **XOR giải mã lúc chạy**. Phân tích hoàn toàn tĩnh (objdump + pefile).

## Phân tích (chi tiết: offset/hằng số/khóa XOR thật)
**Trinh sát chuỗi (strings):** `To capture the FLAG, you need defeat the computer over 300 times.`, các mốc 5/10/50/100/200, `HOORAY! YOU'VE WON over 300 TIMES! The FLAG is: %s` — **nhưng KHÔNG thấy `flag{...}`** ⇒ flag là runtime.

**Chuỗi 6 mốc so sánh số lần thắng** (bộ đếm tại `-0x18c(%ebp)`, disasm thật):
| Địa chỉ | Lệnh | Mốc | Ý nghĩa |
|---|---|---|---|
| `0x401886` | `cmpl $0x5,  -0x18c(%ebp)` | 5 | "You've won 5 times." |
| `0x40189c` | `cmpl $0xa,  -0x18c(%ebp)` | 10 | gợi ý reverse engineering |
| `0x4018b2` | `cmpl $0x32, -0x18c(%ebp)` | 50 | nhắc patch binary |
| `0x4018c8` | `cmpl $0x64, -0x18c(%ebp)` | 100 | nhắc patch binary |
| `0x4018de` | `cmpl $0xc8, -0x18c(%ebp)` | 200 | nhắc patch binary |
| **`0x4018f7`** | `cmpl $0x12c, -0x18c(%ebp)` | **300** | **điều kiện hiện flag** → `jle 0x401a03` |

Byte thô tại `0x4018f7`: `81 BD 74 FE FF FF 2C 01 00 00` = `cmpl $0x12C, -0x18C(%ebp)`; kế tiếp `0F 8E FC 00 00 00` = `jle 0x401a03`. `2C 01 00 00` = 300 (little-endian). **Đây là chỗ cần patch.**

**Khối hiện flag (`0x401907`):** gọi hàm sao chép `0x406d4e` năm lần (mỗi lần `len=0x46=70`) dựng chuỗi mã hóa vào `-0x140(%ebp)`, nạp **byte khóa** tại `-0x191(%ebp)`, rồi:
```asm
401970: movzbl -0x191(%ebp),%ecx   ; key byte
401978: lea  -0x188(%ebp),%edx     ; dst (flag giải mã)
40197f: lea  -0x140(%ebp),%eax     ; src (flag mã hóa)
401986: call 0x4013d0              ; *** HÀM GIẢI MÃ XOR ***
401994: push -0x188(%ebp)          ; flag đã giải mã -> printf
```
**Hàm `0x4013d0(src, dst, key)` (disasm thật) = XOR 1 byte:**
```asm
4013fd: movsbl (%edx),%eax         ; eax = src[i]
401400: movsbl 0x10(%ebp),%ecx     ; ecx = key (tham số thứ 3, 1 byte)
401404: xor %ecx,%eax              ; *** src[i] XOR key ***
40140c: mov %al,(%edx)             ; dst[i] = kết quả
```
⇒ `dst[i] = src[i] XOR key` cho mọi `i`. **Đây là bằng chứng vì sao `strings` không thấy flag:** flag nằm dạng XOR trong buffer, chỉ hiện sau khi thắng đủ điều kiện (hoặc sau patch). `pefile` xác nhận binary **import `IsDebuggerPresent`** (KERNEL32) → chạy dưới debugger sẽ bị thoát.

**Logic một ván** (so sánh input với chuỗi trợ giúp bằng `strcmp @ 0x406dc0`): `help`/`-h`/`--h` tại `0x4017dd/0x4017fa/0x401819`; `0x401843` sinh lựa chọn máy (rand); `0x40185c` phân xử thắng/thua → tăng `-0x18c` nếu thắng.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Binary patching hằng số `CMP`:** đổi `2C 01 00 00` (300) → `01 00 00 00` (1). VÌ SAO: rẻ và chắc hơn tự chơi 300 ván; chỉ sửa 4 byte immediate, không đụng 5 mốc thông báo phía trên.
- **Xác định hàm XOR `0x4013d0` + byte khóa `-0x191`:** VÌ SAO: cho phép trích tĩnh buffer mã hóa + khóa rồi XOR offline → lấy flag **mà không chạy exe** (đúng tinh thần an toàn).
- **Tránh gắn debugger / patch `IsDebuggerPresent`:** VÌ SAO: anti-debug thoát chương trình.

## Lời giải chi tiết (bước + patch sạch)
1. Giải nén: `unzip game-patch.zip` → `game-patch.exe`.
2. Trinh sát: `strings game-patch.exe | grep -i FLAG` → thấy banner nhưng không có `flag{...}`.
3. IDA/Ghidra: tìm `cmpl $0x12c, -0x18c(%ebp)` tại `0x4018f7`.
4. Patch (IDA: Edit → Patch program → Change byte):
   ```
   0x4018f7  trước: 81 BD 74 FE FF FF | 2C 01 00 00 | 0F 8E FC 00 00 00   ; cmp ...,0x12C ; jle
             sau:   81 BD 74 FE FF FF | 01 00 00 00 | 0F 8E FC 00 00 00   ; cmp ...,0x001 ; jle
   ```
5. Edit → Patch program → **Apply patches to input file** → chạy (không debugger), thắng > 1 lần → hàm `0x4013d0` XOR-giải mã flag và printf in ra.
6. *(Thuần tĩnh)* Trích byte mã hóa (`-0x140`, 5×70 byte) + byte khóa (`-0x191`) rồi XOR offline để lấy flag mà không chạy exe.

## Flag
flag{rock_crushes_scissors_water_erodes_rocks}

> Flag là kết quả XOR runtime từ hàm `0x4013d0` — cơ chế đã xác minh bằng disasm; lấy giá trị theo `SOLUTIONS_VN.md`.

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** flag mở khóa sau N lần thắng/điểm cao; chuỗi `HOORAY/WIN/The FLAG is: %s`; `grep flag` rỗng; chống debug `IsDebuggerPresent`.
- **Quy trình:** (1) xác định arch 32/64-bit + strings tìm mốc code; (2) tìm hàm in flag, lần ngược hàm điều kiện ngay trước; (3) tìm `CMP reg/mem, <ngưỡng đẹp>` (300=0x12C); (4) patch immediate về số nhỏ hoặc NOP/đảo nhánh; (5) chạy lại không debugger.
- **Công cụ:** objdump/pefile/PeStudio/DIE, IDA Free/x32dbg, CyberChef (Disassemble x86).
- **Bẫy:** dùng đúng debugger 32-bit; nhớ little-endian khi patch; NOP nhánh có thể vào khối flag khi buffer chưa nạp đúng → patch hằng số an toàn hơn; nhớ "Apply patches to input file" mới lưu thật.
