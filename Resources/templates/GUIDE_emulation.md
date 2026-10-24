# GUIDE: Emulate hàm (Unicorn) & Gọi thẳng hàm (ctypes)

Tài liệu hướng dẫn dùng 2 template:
- `tmpl_unicorn.py` — chạy mô phỏng (emulate) **một hàm/đoạn code** trích từ binary bằng Unicorn Engine.
- `tmpl_ctypes.py` — nạp `.dll`/`.so` của đề và **gọi thẳng** hàm bằng ctypes.

Dành cho Cyber SEA Game 2026 (mảng Reverse). Mục tiêu: **tái dùng thuật toán của đề** mà không phải port tay sang Python.

---

## 1. Khi nào dùng?

Dùng 2 kỹ thuật này khi gặp bài RE có **thuật toán check/transform phức tạp** (nhiều vòng lặp, S-box, trộn bit, state lớn) mà port tay sang Python vừa lâu vừa dễ sai:

| Tình huống | Nên dùng |
|---|---|
| Chỉ cần chạy lại **1 hàm thuần tính toán** (không I/O, không syscall), muốn an toàn, không muốn thực thi cả binary | **Unicorn** (`tmpl_unicorn.py`) |
| Đề cho sẵn / trích được **shared library** (`.so`/`.dll`) chứa hàm xử lý; muốn gọi nhanh ở tốc độ native | **ctypes** (`tmpl_ctypes.py`) — **chỉ trong sandbox** |
| Hàm có gọi hàm ngoài, dùng nhiều địa chỉ tuyệt đối, cấp phát heap... | ctypes thường dễ hơn; Unicorn phải tự dựng nhiều thứ |
| Không tin tưởng binary / không có sandbox | **Unicorn** (không thực thi toàn bộ binary) |

Nguyên tắc: **ưu tiên Unicorn cho an toàn**; chỉ dùng ctypes khi cần tốc độ/tiện và đang ở VM cách ly.

---

## 2. Cài đặt

Chuẩn bị trước ở nhà (được phép `pip install`):

```bash
# Unicorn (bắt buộc cho tmpl_unicorn.py)
pip install unicorn

# (khuyến nghị) Capstone để tự disassemble bytes khi debug
pip install capstone

# ctypes: CÓ SẴN trong Python chuẩn, KHÔNG cần cài.
```

Kiểm tra nhanh:
```bash
python -c "import unicorn; print('unicorn', unicorn.__version__)"
python -c "import ctypes; print('ctypes OK')"
```

> Trên Kali: nếu dùng Python hệ thống bị "externally managed", tạo venv:
> `python3 -m venv ~/ctfenv && source ~/ctfenv/bin/activate && pip install unicorn capstone`

---

## 3. Hai template làm gì?

### `tmpl_unicorn.py`
- Tạo CPU ảo x86/x86-64, **map bộ nhớ** (code + stack + data).
- **Ghi bytes** của hàm vào vùng code, **set thanh ghi/tham số** theo calling convention.
- Chạy `emu_start(begin, until)` tới khi hàm `ret`, rồi **đọc kết quả** ở `RAX`/`EAX` hoặc trong bộ nhớ.
- Có **hook `UC_HOOK_CODE`** để trace từng lệnh / dừng khẩn cấp.
- Có **mẫu brute** gọi emulate nhiều lần để dò flag từng byte.

### `tmpl_ctypes.py`
- **Nạp** `.so`/`.dll` của đề (`CDLL`/`WinDLL`).
- Khai báo **`argtypes`/`restype`**, truyền **chuỗi/buffer** (`c_char_p`, `create_string_buffer`), nhận kết quả.
- Có **mẫu brute** gọi hàm nhiều lần.
- ⚠️ Có **chốt an toàn** (biến môi trường `I_AM_IN_SANDBOX=1`) vì nó **thực thi code của đề**.

---

## 4. Cách dùng từng bước

### 4A. Lấy code bytes & địa chỉ hàm (cho Unicorn)

**Từ Ghidra:**
1. Mở binary, tới hàm cần emulate (double-click trong Symbol Tree / Functions).
2. Xem **địa chỉ đầu hàm** ở Listing (vd `0x001011a0`) và **image base** (Window → Memory Map, cột *Start*).
3. Lấy bytes: bôi đen vùng hàm trong Listing → chuột phải → **Copy Special → Byte String** (hoặc xem cột Bytes). Dán vào `FUNC_CODE`.
4. Nếu hàm dùng **địa chỉ tuyệt đối** (call/lea tới địa chỉ cứng), đặt `CODE_BASE` = image base thật và `FUNC_ADDR` = địa chỉ hàm.

**Từ objdump (Linux/ELF):**
```bash
# Liệt kê hàm + địa chỉ
objdump -d target | grep '<ten_ham>:'
# Disassemble 1 hàm (xem địa chỉ bắt đầu/kết thúc)
objdump -d target --disassemble=ten_ham
# Lấy raw bytes theo file-offset (dùng khi nạp từ file)
#   -> xác định file offset bằng: readelf -S target (xem .text: Address vs Offset)
#   rva = vaddr_ham - vaddr_text ; file_off = off_text + rva
```

**Từ radare2:** `pdf @ sym.ten_ham` để xem; `p8 <len> @ sym.ten_ham` để in bytes hex.

Sau đó trong `tmpl_unicorn.py`:
- Dán bytes vào `FUNC_CODE`, hoặc dùng `load_code_from_file(uc, path, file_offset, length, load_addr)`.
- Đặt `CODE_BASE`, `FUNC_ADDR` khớp (xem mục 7 về địa chỉ tuyệt đối).
- Sửa `setup_stack_and_args` cho đúng **calling convention** (SysV vs Windows x64 vs 32-bit cdecl).
- Sửa `run_function(...)` args, và cách đọc kết quả.
- Chạy: `python tmpl_unicorn.py` (demo add chạy trước để sanity-check).

### 4B. Lấy tên hàm export (cho ctypes)

```bash
# Linux .so
nm -D libtarget.so          # xem các symbol 'T' (text, exported)
objdump -T libtarget.so

# Windows .dll
dumpbin /exports target.dll     # (Developer Command Prompt)
# hoặc: python -c "import pefile;print([e.name for e in pefile.PE('target.dll').DIRECTORY_ENTRY_EXPORT.symbols])"
```

Kiểm tra kiến trúc (phải khớp với Python 32/64-bit):
```bash
file libtarget.so            # ELF 64-bit ...
```

Sau đó trong `tmpl_ctypes.py`:
- Đặt `LIB_PATH`.
- Sửa `declare_signatures()`: tên hàm + `argtypes`/`restype`.
- Chạy **trong VM**: `I_AM_IN_SANDBOX=1 python3 tmpl_ctypes.py`.

---

## 5. Giải thích từng phần

### Unicorn
- **`Uc(UC_ARCH_X86, UC_MODE_64)`**: tạo CPU ảo x86 64-bit (đổi `UC_MODE_32` cho 32-bit).
- **`mem_map(addr, size, prot)`**: cấp vùng nhớ. `addr`/`size` phải align 0x1000.
- **`mem_write(addr, data)` / `mem_read(addr, n)`**: ghi/đọc bộ nhớ ảo.
- **`reg_write(reg, val)` / `reg_read(reg)`**: set/đọc thanh ghi.
- **`emu_start(begin, until, timeout, count)`**: chạy từ `begin` tới khi IP = `until` (hoặc hết `timeout` µs / `count` lệnh). Ta đặt `until` = return-address giả để dừng khi hàm `ret`.
- **`hook_add(UC_HOOK_CODE, cb)`**: gọi `cb(uc, address, size, user_data)` trước mỗi lệnh — để trace/dừng.
- **Stack**: tự map vùng stack, đặt `RSP` ở giữa, push 1 return-address giả để hàm `ret` nhảy về đúng `until`.

### ctypes
- **`CDLL(path)`** (cdecl / Linux .so, Windows x64) hoặc **`WinDLL(path)`** (stdcall, Windows 32-bit).
- **`argtypes`/`restype`**: *bắt buộc* khai báo đúng, nếu không con trỏ 64-bit bị cắt thành int → crash.
- **`c_char_p`**: nhận `bytes` (chỉ-đọc). **`create_string_buffer(n)`**: buffer ghi được cho hàm C ghi vào.
- **`.raw`** của buffer: lấy toàn bộ bytes (kể cả NUL ở giữa); **`.value`**: cắt tại NUL đầu tiên.

---

## 6. Ví dụ

### Ví dụ Unicorn (đã có sẵn trong template — hàm `add`)
Bytes `48 89 F8 48 01 F0 C3` = `mov rax,rdi; add rax,rsi; ret`:
```
$ python tmpl_unicorn.py
[demo] add(12, 30) = 42  (kỳ vọng 42)
```
Đây là bài test chứng minh pipeline (map → write → set reg → run → read RAX) hoạt động. Thay `FUNC_CODE` bằng hàm thật của đề để dùng.

### Ví dụ ctypes (ý tưởng)
Giả sử `libtarget.so` có `int check(const char*)`:
```python
lib = load_library("./libtarget.so")
lib.check.argtypes = [c_char_p]; lib.check.restype = c_int
print(call_check(lib, b"CTF{test}"))   # True nếu đúng flag
```

### Mẫu brute từng byte
Cả hai template đều có hàm brute: với mỗi vị trí `i`, thử mọi ký tự, giữ ký tự làm **output[i]** khớp `target[i]` (áp dụng khi mỗi byte output phụ thuộc 1 byte input — xor/sbox từng byte). Sửa `target`, độ dài, chữ ký hàm cho đúng đề.

---

## 7. Cạm bẫy (đọc kỹ!)

### Unicorn
- **Align page**: `mem_map` cần `addr` & `size` là bội số `0x1000`. Sai → `UC_ERR_ARG`.
- **Căn chỉnh stack (stack alignment)**: x64 SysV yêu cầu `RSP % 16 == 0` *trước* `call`. Nếu hàm dùng lệnh SSE (`movaps`) mà stack lệch → crash `UC_ERR_*`. Template đã căn 16 rồi push return-address — nếu vẫn lỗi, thử đẩy/bớt 8 byte.
- **Địa chỉ tuyệt đối**: nếu hàm `call`/đọc dữ liệu theo địa chỉ cứng (vd `mov rax,[0x404040]`), bạn **phải** map code tại đúng image base và map luôn vùng dữ liệu đó (ghi nội dung thật từ file). Thiếu → `UC_ERR_FETCH_UNMAPPED` / `UC_ERR_READ_UNMAPPED`.
- **Hàm gọi hàm ngoài** (malloc, memcpy, hàm khác của đề): Unicorn không có libc. Phải hoặc (a) map luôn các hàm đó, hoặc (b) **hook** để giả lập (viết hook cho `UC_HOOK_CODE` chặn tại địa chỉ call, tự xử lý rồi set RIP qua). Phức tạp → cân nhắc ctypes.
- **`emu_start` không dừng**: luôn đặt `timeout`/`count` khi brute để tránh treo vô hạn.
- **Calling convention**: SysV (Linux x64) = RDI,RSI,RDX,RCX,R8,R9. **Windows x64** = RCX,RDX,R8,R9 (+ shadow space 32 byte trên stack!). 32-bit cdecl = đẩy stack. Chọn sai → đọc tham số rác.
- **Endianness/kích thước**: `to_bytes(8,"little")` cho x64, `4` cho x86.

### ctypes
- **AN TOÀN (quan trọng nhất)**: `CDLL`/`WinDLL` **thực thi code của đề** (kể cả `DllMain`/constructor khi *vừa load*). **Chỉ chạy trong Kali VM/sandbox cách ly**, snapshot trước, không mount ổ quan trọng, cân nhắc tắt mạng. Chỉ nạp **binary của đề**. Template có chốt `I_AM_IN_SANDBOX=1`.
- **Quên `argtypes`/`restype`**: mặc định ctypes coi mọi thứ là `int` 32-bit → con trỏ 64-bit bị cắt → crash/kết quả sai. Luôn khai báo.
- **Buffer chỉ-đọc vs ghi-được**: truyền `bytes` vào tham số mà hàm **ghi vào** sẽ hỏng bộ nhớ. Dùng `create_string_buffer(n)` cho tham số output.
- **Kiến trúc & phụ thuộc**: Python 64-bit chỉ nạp lib 64-bit. `.dll` thiếu dependency cùng thư mục → `OSError`. Dùng `file`/`dumpbin` kiểm tra trước.
- **str vs bytes**: luôn truyền `bytes` (encode chuỗi: `s.encode()`), ctypes không tự encode `str` cho `c_char_p`.
- **Đường dẫn .so**: Linux không tìm `.so` trong cwd — dùng `./lib.so` hoặc đường dẫn tuyệt đối.

---

## 8. Tham khảo

- Unicorn Engine — docs & Python samples: https://github.com/unicorn-engine/unicorn (thư mục `bindings/python/`)
- Unicorn API reference: https://www.unicorn-engine.org/docs/
- Python ctypes: https://docs.python.org/3/library/ctypes.html
- Capstone (disassembler, hỗ trợ debug bytes): https://www.capstone-engine.org/
- System V AMD64 ABI (calling convention Linux x64): https://gitlab.com/x86-psABIs/x86-64-ABI
- Microsoft x64 calling convention: https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
