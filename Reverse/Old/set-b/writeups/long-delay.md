# long-delay

- **Category:** Binary
- **File đề:** `long-delay/sleep` (ELF 64-bit x86-64, 8880 bytes, md5 `d85883e7aa9057a7be6f2d6baadeefd0`, sha1 `c608591d124355a57c7c0ba2c93f280b944a58b0`, not stripped). Bản patch tham khảo: `long-delay/sleep-patched` (md5 `80f66c3645cf9725db7ab4a01de03072`). Repo còn kèm ảnh output `sleep-patched.png`.

## Tóm tắt đề

Một chương trình ELF Linux in dòng `I'm so sleepy...` rồi **gọi `sleep()` với một giá trị cực lớn** nên treo gần như vĩnh viễn. Sau khi "ngủ" xong nó mới gọi một hàm tự chế tên `xor` để in flag. Nhiệm vụ: lấy flag mà không phải chờ ~82 năm.

## Phân tích (chi tiết)

`file sleep` → `ELF 64-bit LSB executable, x86-64, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, GNU/Linux 2.6.32, BuildID f3aa54ff..., not stripped`. Entry point `0x4004c0`, biên bằng GCC 5.4.0 (Ubuntu 16.04). "Not stripped" nên `nm` còn đọc được tên hàm.

`strings -a sleep` **không** cho ra flag — chỉ thấy `"I'm so sleepy..."`, `"sleep"`, `"sleep.c"`. Đây là tín hiệu rằng flag **được sinh lúc chạy (runtime)**, không nằm sẵn ở dạng text trong file.

`nm sleep` cho thấy có hàm tên `xor` (`00000000004005b6 T xor`) và một import `sleep@@GLIBC_2.2.5`. Có hàm tự chế tên `xor` + `strings` không có flag ⇒ flag được dựng bằng phép XOR lúc chạy.

Disassembly `main` (`objdump -d -M intel sleep`):

```asm
0000000000400614 <main>:
  40061c: c7 45 fc 00 da f8 9a   mov DWORD PTR [rbp-0x4], 0x9af8da00   ; delay = 0x9AF8DA00
  400623: bf d4 06 40 00         mov edi, 0x4006d4                     ; địa chỉ chuỗi "I'm so sleepy..."
  400628: e8 ..                  call 400480 <puts@plt>
  40062d: 8b 45 fc               mov eax, [rbp-0x4]
  400630: 89 c7                  mov edi, eax                          ; edi = tham số đầu của sleep()
  400632: e8 ..                  call 4004a0 <sleep@plt>               ; sleep(0x9AF8DA00)
  40063c: e8 ..                  call 4005b6 <xor>                     ; xor() -> in flag
```

Giá trị delay thật là `0x9AF8DA00` = **2.600.000.000** giây (~82 năm). Theo System V AMD64 ABI, tham số nguyên thứ nhất của `sleep()` truyền qua `edi`; `sleep()` nhận `unsigned int` 32-bit nên 2,6 tỷ giây vẫn nằm vừa trong 32-bit.

> **Lưu ý đính chính:** một số writeup ghi delay là "0x2600000000" — sai. Giá trị đúng trong lệnh máy là `0x9AF8DA00`; nếu đọc nhầm `0x2600000000` thì con số ~163 tỷ không vừa `unsigned int` 32-bit.

Disassembly hàm `xor` (vòng lặp i = 0..0x16 = 22, tổng 23 vòng):

```asm
00000000004005b6 <xor>:
  4005be: mov DWORD PTR [rbp-0x4], 0x0     ; i = 0
loop (4005c7):
  mov edx, [rax*4 + 0x601060]             ; edx = arr[i]
  mov eax, [(i+1)*4 + 0x601060]           ; eax = arr[i+1]
  xor edx, eax                            ; edx = arr[i] ^ arr[i+1]
  mov [(i+1)*4 + 0x601060], edx           ; arr[i+1] = arr[i] ^ arr[i+1]   (XOR dồn tiền tố)
  mov eax, [i*4 + 0x601060]               ; eax = arr[i]  (đã được cập nhật ở vòng trước)
  call putchar                            ; putchar(arr[i])
  add DWORD PTR [rbp-0x4], 1              ; i++
  cmp DWORD PTR [rbp-0x4], 0x16 ; jle loop ; lặp khi i <= 22
```

Mảng `arr` nằm ở section `.data`, virtual address `0x601060`. Trích bằng `objdump -s -j .data` (mỗi phần tử là 1 dword little-endian, chỉ byte thấp có nghĩa):

```
0x601060: 46 2a 0d 06 47 49 1a 53 53 42 02 00 43 41 5f 09 38 39 56 42 41 40 07   (23 giá trị)
```

Thuật toán: mỗi vòng cập nhật `arr[i+1] = arr[i] ^ arr[i+1]` (XOR tiền tố dồn) rồi `putchar(arr[i])`. Ký tự đầu in ra là `arr[0] = 0x46 = 'F'`.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Đọc immediate value trong disassembly để biết delay** — VÌ delay là hằng số nhúng thẳng trong lệnh `mov`; không cần chạy, chỉ cần đọc byte.
- **Mô phỏng hàm `xor` bằng Python (static decode)** — VÌ flag được sinh runtime bằng XOR dồn, `strings` vô dụng; mô phỏng chính xác thuật toán sẽ cho flag mà **không chạy binary** (an toàn, tránh chờ ~82 năm).
- **Patch byte immediate (hướng thay thế)** — VÌ nếu muốn chạy thật thì đổi delay về 0; tìm 4 byte little-endian `00 DA F8 9A` và sửa thành `00 00 00 00`.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

**Bước 1 — Trinh sát tĩnh.**

```bash
file sleep              # xác nhận ELF x86-64 not stripped
strings -a sleep        # không có flag -> flag sinh runtime
nm sleep | grep ' T '   # thấy hàm 'xor' đáng ngờ
objdump -d -M intel sleep   # đọc main + xor
objdump -s -j .data sleep   # trích mảng arr tại 0x601060
```

**Bước 2 — Giải mã tĩnh (không chạy binary).** Mô phỏng đúng vòng lặp `xor`:

```python
arr = [0x46,0x2a,0x0d,0x06,0x47,0x49,0x1a,0x53,0x53,0x42,0x02,0x00,
       0x43,0x41,0x5f,0x09,0x38,0x39,0x56,0x42,0x41,0x40,0x07] + [0]  # arr[23] thuộc .bss = 0
out = []
i = 0
while i <= 0x16:                 # cmp i,0x16 ; jle  -> i = 0..22
    arr[i+1] = arr[i] ^ arr[i+1] # arr[i+1] = arr[i] ^ arr[i+1]
    out.append(arr[i])           # putchar(arr[i])
    i += 1
print(''.join(map(chr, out)))    # -> Flag is s133p1ng_f0r3st
```

Kết quả: `Flag is s133p1ng_f0r3st` (23 ký tự, khớp số vòng lặp).

**Bước 3 (hướng thay thế) — Patch delay rồi chạy trong VM cách ly.**

```bash
# radare2: tìm và sửa immediate little-endian 00 DA F8 9A -> 00 00 00 00
r2 -w ./sleep
> / 00daf89a            # tìm offset byte immediate
> wx 00000000 @ <offset>
> q
# hoặc trong IDA: tới lệnh 'mov [rbp-4], 0x9AF8DA00' -> Edit > Patch bytes -> Apply patches to input file
```

Chạy bản vá in ra `I'm so sleepy...` rồi `Flag is s133p1ng_f0r3st` (khớp ảnh `sleep-patched.png`).

## Flag

```
flag{s133p1ng_f0r3st}
```

"sleeping forest" — output in `Flag is s133p1ng_f0r3st`, nộp theo định dạng `flag{...}`.

## Gặp lại thì xử lý thế nào (playbook)

1. `strings` không ra flag + có hàm tự chế (`xor`, `decode`, ...) ⇒ flag sinh runtime, phải reverse hàm đó.
2. Với bài "chương trình ngủ quá lâu", đừng chờ: đọc immediate truyền vào `sleep`/`nanosleep`.
3. Ba cách vô hiệu hóa delay: (a) patch byte immediate về 0; (b) `LD_PRELOAD` một `sleep()` giả trả về ngay; (c) dùng gdb nhảy qua lời gọi `sleep`.
4. Luôn ưu tiên mô phỏng thuật toán decode bằng Python (độc lập môi trường, không cần chạy file lạ).
5. Cẩn thận little-endian khi dò byte immediate trong file.
