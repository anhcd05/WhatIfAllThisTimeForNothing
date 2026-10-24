# missing-library

- **Category:** OS
- **File đề:** `missing-library/04dca129c011213979aded2e7bef71d3.zip` (4588 bytes, md5 `04dca129c011213979aded2e7bef71d3` — **khớp tên**, file nguyên bản; sha1 `7b57fbc78f278303beff68a5134c723683963185`). Giải nén ra `main.exe` (ELF 64-bit x86-64, dynamically linked, not stripped, 6721 B) và `libflag.so` (ELF 64-bit shared object, not stripped, 6337 B). Repo kèm ảnh output `flag.png`.

## Tóm tắt đề

Chạy `main.exe` báo lỗi thiếu thư viện. Logic in flag nằm trong `libflag.so`, nhưng flag được **sinh runtime** bằng `rand()` nên `strings` không thấy. Hai hướng giải: (A) mô phỏng `rand()` offline; (B) chỉ cho `ld.so` tìm thấy `libflag.so` rồi chạy.

## Phân tích (chi tiết)

**Nền tảng shared library.** `.so` nạp lúc chạy bởi dynamic linker `ld.so`. Chương trình khai báo thư viện cần ở entry `NEEDED` trong `.dynamic`. `ld.so` tìm `.so` theo thứ tự: (1) RPATH → (2) `LD_LIBRARY_PATH` → (3) RUNPATH → (4) cache `/etc/ld.so.cache` → (5) `/lib`, `/usr/lib`. Không thấy → lỗi `cannot open shared object file`.

Trinh sát:

```bash
file main.exe libflag.so          # main.exe: ELF exec; libflag.so: ELF shared object
readelf -d main.exe | grep NEEDED
#   (NEEDED)  Shared library: [libflag.so]
#   (NEEDED)  Shared library: [libc.so.6]
nm -D main.exe | grep print_flag
#                 U print_flag     <-- undefined, lấy từ libflag.so
strace ./main.exe 2>&1 | grep -i libflag
#   openat(..., "/.../libflag.so", ...) = -1 ENOENT   (lặp ở nhiều thư mục)
```

`main` cực ngắn — chỉ gọi `print_flag`:

```asm
00000000004005c4 <main>:
  4005c8: mov eax,0x0
  4005cd: call 4004b8 <print_flag@plt>     ; toàn bộ logic ở libflag.so
  4005d7: leave ; ret
```

⇒ flag nằm ở `libflag.so`. Không có RPATH/RUNPATH (readelf xác nhận) nên `ld.so` chỉ tìm theo cache + đường mặc định → không có `libflag.so` → `ENOENT`. Tên bài "Shared" + flag "specify_the_library" khẳng định: **chỉ định vị trí thư viện**.

`strings libflag.so` chỉ có `print_flag`, `flag.c` — flag không ở dạng text. Disassembly `print_flag`:

```asm
000000000000060c <print_flag>:
  ; dựng mảng 25 dword tại [rbp-0x80..]:
  ;   0x07,0x0a,0x3e,0x52,0x4c,0x69,0x24,0x09,0x0d,0x2c,0x36,0x58,0x30,0x46,
  ;   0x0a,0x54,0x45,0x23,0x52,0x40,0x5d,0x17,0x2c,0x4d,0x21
  6c4: mov DWORD [rbp-0x14], 0x19     ; đếm = 25
  6cb: mov edi, 0x7c5 ; call srand    ; srand(0x7c5 = 1989)
loop:
  mov ebx, [rbp+i*4-0x80]             ; ebx = arr[i]
  call rand                          ; r = rand()
  lea eax, [rbx + (r%100)]           ; ký tự = arr[i] + (r % 100)
  call putchar
  ; i++ ; cmp i,25 ; jl loop
  mov edi, 0xa ; call putchar        ; in '\n'
```

Thuật toán: `char[i] = arr[i] + (rand() % 100)` với `srand(1989)`. Hằng `0x51EB851F` + `sar 5` compiler sinh ra là **magic-number division** để tính `r % 100` nhanh (không dùng `div`).

**glibc `rand()` xác định:** cùng seed cho cùng dãy số, dùng thuật toán TYPE_3 additive feedback → mô phỏng được offline để tính y hệt dãy mà binary tạo ra.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **`readelf -d` + `strace` chẩn đoán thiếu `.so`** — VÌ cần biết thư viện nào thiếu và `ld.so` tìm ở đâu để hiểu lỗi.
- **Mô phỏng glibc `rand()` TYPE_3 bằng Python (hướng A)** — VÌ flag sinh runtime, `strings` vô dụng; mô phỏng chính xác dãy số cho flag mà không chạy binary.
- **`LD_LIBRARY_PATH=.` (hướng B)** — VÌ chỉ cần trỏ `ld.so` vào thư mục chứa `libflag.so` là chương trình tự in flag; đúng ý nghĩa "specify the library".

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

**Hướng A — Giải mã tĩnh (không chạy binary).** Tái hiện glibc `rand()` + áp công thức:

```python
def glibc_rand_seq(seed, n):              # TYPE_3 additive feedback của glibc
    r = [seed & 0xffffffff]
    for i in range(1, 31):
        hi, lo = divmod(r[i-1], 127773)
        w = 16807*lo - 2836*hi
        r.append(w + 2147483647 if w < 0 else w)
    for i in range(31, 34): r.append(r[i-31])
    for i in range(34, 344): r.append((r[i-31] + r[i-3]) & 0xffffffff)
    out = []
    for _ in range(n):
        r.append((r[-31] + r[-3]) & 0xffffffff)
        out.append((r[-1] >> 1) & 0x7fffffff)
    return out

arr = [0x07,0x0a,0x3e,0x52,0x4c,0x69,0x24,0x09,0x0d,0x2c,0x36,0x58,0x30,0x46,
       0x0a,0x54,0x45,0x23,0x52,0x40,0x5d,0x17,0x2c,0x4d,0x21]
rs = glibc_rand_seq(1989, len(arr))
print(''.join(chr((a + (r % 100)) & 0xff) for a, r in zip(arr, rs)))
# -> flag{specify_the_library}
```

Kết quả: `flag{specify_the_library}` (25 ký tự, khớp số đếm `0x19`).

**Hướng B — Cho `ld.so` tìm thấy thư viện (chạy trong VM):**

```bash
unzip 04dca129c011213979aded2e7bef71d3.zip
chmod +x main.exe
LD_LIBRARY_PATH=. ./main.exe        # trỏ đường tìm .so vào thư mục hiện tại
#   -> flag{specify_the_library}
# hoặc: sudo cp libflag.so /usr/lib/ && sudo ldconfig && ./main.exe
```

(Ảnh `flag.png` trong repo xác nhận output `flag{specify_the_library}`.)

## Flag

```
flag{specify_the_library}
```

"hãy chỉ định vị trí thư viện" — dạy cơ chế nạp shared library, `strace`, `LD_LIBRARY_PATH`.

## Gặp lại thì xử lý thế nào (playbook)

1. Lỗi `cannot open shared object file` ⇒ `readelf -d` xem `NEEDED`, `strace` xem `ld.so` tìm `.so` ở đâu.
2. Thử `LD_LIBRARY_PATH=.` hoặc `patchelf --set-rpath . main.exe` trước khi nghĩ đến reverse.
3. `strings` không có flag + thấy `srand/rand` ⇒ flag sinh runtime: mô phỏng đúng biến thể PRNG (glibc TYPE_3, KHÔNG phải LCG kiểu Windows).
4. `0x51EB851F` + dịch phải là magic-number division cho `/100` — nhận ra để suy `r % 100`.
5. Luôn chạy binary lạ trong VM/Docker.
