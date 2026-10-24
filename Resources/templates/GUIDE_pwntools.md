# Hướng dẫn dùng template Pwntools — Cyber SEA Game 2026 (Reverse / Pwn)

Hai template Python đi kèm:

- `tmpl_pwntools.py` — khung khai thác binary (pwn): BOF, ret2libc, ROP, leak + ASLR.
- `tmpl_pwn_interact.py` — tự động hoá tương tác & brute từng ký tự (dành cho reverse/keygen).

Pwntools kiểm tra: phiên bản mới nhất **4.15.0** (10/2025). API trong template là API ổn định, chạy tốt từ 4.1x trở lên.

---

## 1) Khi nào dùng

- **Bài Pwn** (stack overflow, format string, ret2libc, ROP, heap...): dùng `tmpl_pwntools.py`. Nó lo giúp bạn việc kết nối process/remote, đóng gói địa chỉ (`p64/u64`), nạp `ELF`/`libc`, dựng chuỗi `ROP`, gắn `GDB`.
- **Bài Reverse có binary nhận input rồi báo đúng/sai** (check password, keygen, flag checker): dùng `tmpl_pwn_interact.py` để brute tự động từng ký tự theo tín hiệu (nội dung/độ dài/thời gian), thay vì ngồi nhập tay.
- Khi chỉ cần "gõ tay thử" trước: chạy `tmpl_pwntools.py` rồi dùng `io.interactive()` (mặc định template đã mở sẵn interactive).

---

## 2) Cài đặt

- **Kali Linux (khuyên dùng để pwn):** pwntools thường có sẵn. Nếu thiếu:
  ```bash
  pip install --upgrade pwntools
  ```
- **Windows host:** `pip install pwntools` chạy được cho phần script/logic, **nhưng** `process()` chạy ELF Linux và `gdb.attach` thì phải dùng **WSL/Kali**. Khuyến nghị: viết/sửa script trên Windows, **chạy khai thác trong Kali VM/WSL**.
- Kiểm tra: `python3 -c "import pwn; print(pwn.__version__)"`
- Công cụ nên cài kèm: `gdb` + **pwndbg** hoặc **GEF** (xem stack/thanh ghi), `ropgadget`/`ROPgadget`, `one_gadget`, `patchelf` (vá libc), `seccomp-tools`.

---

## 3) Hai template làm gì

| Template | Vai trò | Điểm chính |
|---|---|---|
| `tmpl_pwntools.py` | Khung pwn tổng quát | `context`, `start()` chọn LOCAL/REMOTE/GDB qua argv, nạp `ELF`+`libc`, hàm tắt `sla/sl/ru...`, demo `cyclic`, skeleton `ROP` 2 giai đoạn, `gdb.debug` |
| `tmpl_pwn_interact.py` | Brute/tương tác tự động | `attempt()` gửi 1 ứng viên & đo thời gian; 3 chiến thuật brute: theo nội dung `(A)`, theo độ dài `(B)`, theo thời gian `(C)` |

---

## 4) Cách dùng từng bước + chỗ TODO cần sửa

### A. `tmpl_pwntools.py`

1. Sửa phần **(1) CẤU HÌNH**:
   - `BINARY` = đường dẫn binary (`./chall`).
   - `LIBC` = libc đề cho (để `None` nếu không có).
   - `HOST`, `PORT` = thông tin server remote.
2. Kiểm tra `context.arch` = `amd64` (64-bit) hay `i386` (32-bit). Nếu nạp được ELF, `context.binary = elf` sẽ **tự set đúng** — cứ để vậy.
3. (Nếu dùng GDB) sửa `context.terminal` cho đúng môi trường và đặt breakpoint trong `GDBSCRIPT` (ví dụ `b *vuln`).
4. Viết logic khai thác trong **`main()`** (đã có sẵn khung ret2libc 2 giai đoạn, chỉ cần bỏ comment và chỉnh `offset`, delim prompt).
5. Chạy:
   ```bash
   python3 tmpl_pwntools.py          # local
   python3 tmpl_pwntools.py GDB      # local + gdb
   python3 tmpl_pwntools.py REMOTE   # remote
   python3 tmpl_pwntools.py DEBUG    # in hết traffic
   ```

**Các TODO trong file:** `BINARY`, `LIBC`, `HOST`, `PORT`, `context.arch`, `context.terminal`, breakpoint trong `GDBSCRIPT`, `offset` (từ cyclic), các delim prompt trong `sla(...)`.

### B. `tmpl_pwn_interact.py`

1. Sửa **(1) CẤU HÌNH**: `BINARY`/`HOST`/`PORT`, `CHARSET` (thu gọn nếu biết dạng flag), `FLAG_PREFIX` (vd `CSG{`), `MAX_LEN`.
2. Sửa hàm **`attempt()`** cho khớp giao diện binary: prompt trong `sendlineafter`, cách đọc phản hồi (`recvall`/`recvline`/`recvuntil`).
3. Chọn chiến thuật trong `main()`:
   - `(A)` sửa `is_good(out)` cho đúng dấu hiệu "đúng" (vd `b"Correct" in out`).
   - `(B)` kiểm tra chiều thay đổi độ dài (`>` hay `<`).
   - `(C)` tăng `rounds` nếu nhiễu nhiều.
4. Chạy: `python3 tmpl_pwn_interact.py` (thêm `REMOTE`/`DEBUG` nếu cần).

**Các TODO trong file:** `BINARY/HOST/PORT`, `CHARSET`, `FLAG_PREFIX`, `MAX_LEN`, prompt & cách recv trong `attempt()`, điều kiện `is_good()`.

---

## 5) Giải thích từng phần (API chính)

- **`context`**: cấu hình toàn cục — `arch` (`amd64`/`i386`), `os`, `endian`, `log_level` (`debug`/`info`/`warning`). `context.binary = ELF(...)` là cách gọn nhất để set đúng kiến trúc.
- **`process([path])`** vs **`remote(host, port)`**: tạo "tube" (kênh I/O) tới binary local / server. Cùng một bộ hàm recv/send dùng được cho cả hai.
- **Gửi/nhận**:
  - `send/sendline` (gửi / gửi + `\n`).
  - `sendafter(delim, data)` / `sendlineafter(delim, data)` — chờ thấy `delim` rồi mới gửi (rất hay dùng để khớp menu/prompt).
  - `recv(n)` / `recvn(n)` (đúng n byte) / `recvline()` / `recvuntil(delim, drop=True)`.
  - Nên dùng **bytes** (`b"..."`) cho delim/data.
- **`ELF(path)`**: đọc binary → `elf.symbols`, `elf.got`, `elf.plt`, `elf.search(...)`, đặt `elf.address` để rebase PIE.
- **libc + ASLR**: leak 1 địa chỉ hàm libc (vd `puts`) → `libc.address = leak - libc.symbols['puts']` → mọi symbol khác tự đúng.
- **`cyclic(n)` / `cyclic_find(x)`**: tạo chuỗi De Bruijn để tìm **offset** tràn. Crash xong lấy giá trị ở RIP/RSP rồi `cyclic_find` ra số byte đệm. (64-bit: giá trị rơi vào stack, có thể cần `cyclic_find(p64(value))`.)
- **`p64/p32`** đóng gói số → bytes; **`u64/u32`** giải ngược (nhớ `.ljust(8, b"\x00")` khi leak thiếu byte).
- **`ROP(elf)`**: tìm gadget `rop.find_gadget(["pop rdi","ret"])`, dựng chuỗi. 64-bit truyền tham số qua thanh ghi (`rdi, rsi, rdx...`); thêm 1 `ret` để căn stack 16-byte (lỗi `movaps`).
- **`gdb.attach(io, script)`** / **`gdb.debug([path], script)`**: debug trực tiếp; `gdb.debug` tắt ASLR sẵn — tiện so khớp địa chỉ local.
- **`ssh(host, user, password=/keyfile=)`**: khi chall chạy qua SSH (`sh.process(...)`, `sh.remote(...)`).

---

## 6) Ví dụ áp dụng (ret2libc 64-bit)

Bài cho `chall` (NX bật, không PIE) + `libc.so.6`, in prompt `> ` và có BOF ở hàm đọc input.

1. Tìm offset: chạy GDB, gửi `cyclic(200)`, crash, đọc `$rsp` → `cyclic_find(...)` ra **40**.
2. Trong `tmpl_pwntools.py`: đặt `BINARY`, `LIBC`, `offset=40`.
3. Giai đoạn 1 (`build_rop_leak`): `puts(puts@got)` rồi `ret2main` → leak địa chỉ `puts`.
4. Tính `libc_base = leak - libc.symbols['puts']`.
5. Giai đoạn 2 (`build_rop_system`): `pop rdi; "/bin/sh"; system`.
6. `io.interactive()` → `cat flag.txt`.

(Khung code 6 bước này đã có sẵn dạng comment trong `main()` của `tmpl_pwntools.py`.)

---

## 7) Cạm bẫy thường gặp

- **Newline**: `sendline` thêm `\n`; nếu chall đọc bằng `scanf("%s")`/`gets` thì `\n` có thể làm lệch. Dùng `send` khi cần kiểm soát từng byte.
- **Buffering**: output có thể chưa xổ ra ngay → dùng `recvuntil(delim)` theo mốc chắc chắn, đừng đoán số byte. Với timing side-channel, buffering làm nhiễu → đo trung vị nhiều lần.
- **Arch 32 vs 64**: nhầm `p32/p64`, nhầm cách truyền tham số (32-bit đẩy qua stack, 64-bit qua thanh ghi) là lỗi phổ biến nhất. Đặt `context.binary = elf` để tránh.
- **ASLR**: local có thể khác remote. Test local nên `gdb.debug` (tắt ASLR); khi khai thác thật phải leak động, **không hardcode** địa chỉ libc.
- **Căn stack 16-byte**: ret2libc 64-bit hay lỗi `movaps` → thêm 1 gadget `ret` trước khi gọi `system`.
- **libc đúng phiên bản**: dùng đúng `libc.so.6` đề cho; nếu cần, `patchelf --set-interpreter ... --replace-needed ...` cho binary khớp libc.
- **Remote reset**: nhiều chall reset mỗi lần kết nối → brute phải tạo tube mới mỗi lần thử (template đã làm vậy trong `attempt()`), đánh đổi là chậm hơn.
- **Windows**: `process()`/`gdb` ELF **không chạy trực tiếp** trên Windows — dùng WSL/Kali.
- **Charset brute**: để charset quá rộng → rất chậm. Thu gọn theo dạng flag (hex, chữ thường...) khi có thể.

---

## 8) Tham khảo

- Tài liệu chính thức: https://docs.pwntools.com/ (và bản dev: https://pwntools.readthedocs.io/en/dev/intro.html)
- Getting Started: https://docs.pwntools.com/en/latest/intro.html
- Changelog / phiên bản: https://data.safetycli.com/changelogs/pwn (mới nhất 4.15.0)
- pwn.college — khoá pwntools: https://pwn.college/
- Cheat sheet cộng đồng: https://gist.github.com/anvbis/64907e4f90974c4bdd930baeb705dedf
- one_gadget: https://github.com/david942j/one_gadget · ROPgadget: https://github.com/JonathanSalwan/ROPgadget
- pwndbg: https://github.com/pwndbg/pwndbg · GEF: https://github.com/hugsy/gef
