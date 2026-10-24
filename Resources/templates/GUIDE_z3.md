# Hướng dẫn dùng z3 cho Reverse / Crypto (Cyber SEA Game 2026)

File đi kèm: **`tmpl_z3.py`** (template chạy được, có 3 ví dụ: cơ bản, ràng buộc
byte, và mẫu **"1000 phương trình"**).

> TL;DR: z3 là "máy giải ngược" — bạn mô tả *điều kiện* mà input đúng phải thỏa,
> z3 tự tìm input. Cực mạnh khi có **hàng trăm/nghìn ràng buộc** kiểu
> **modular / bitwise** mà giải tay bất khả thi.

---

## 1. Khi nào dùng z3 (so với angr)

| Tình huống | Công cụ nên dùng |
|---|---|
| Đã **reverse ra công thức check** (xor/cộng/nhân/so sánh, bảng hằng số) và muốn giải ngược ra flag | **z3** ✅ |
| Hệ **nhiều ràng buộc modular/bitwise** (uint8/uint32 wrap, xor, shift, and/or) | **z3** ✅ |
| Check có **nhánh rẽ (if/else) phức tạp** nhưng vẫn là số học/bit | z3 (dùng `If`) ✅ |
| **Chưa reverse được logic**, chỉ có binary và muốn "tìm input tới đoạn in WIN" | **angr** (symbolic execution tự khám phá đường đi) |
| Có syscall/IO/vòng lặp khổng lồ, path explosion | angr (+ hooks) hoặc giải tay |
| Hệ **tuyến tính SỐ NGUYÊN thuần, dày đặc, KHÔNG modulo** | **numpy/sympy/sage** (đại số tuyến tính), **KHÔNG z3** (xem mục 7) |

Quy tắc ngón tay cái: **biết công thức → z3; không biết đường đi → angr.** Hai
công cụ bổ sung nhau: angr tìm ra ràng buộc, rồi có thể export sang z3 để giải.

---

## 2. Cài đặt

```bash
pip install z3-solver          # import trong Python là:  import z3
python -c "import z3; print(z3.get_version_string())"   # kiểm tra, vd 4.13+ / 5.x
```

- Windows (host thi): nếu in tiếng Việt lỗi `UnicodeEncodeError`, template đã tự
  `sys.stdout.reconfigure(encoding="utf-8")`. Hoặc đặt `set PYTHONUTF8=1`.
- Kali VM: cài y hệt. z3 là thuần Python wheel nên không cần build.

---

## 3. Template `tmpl_z3.py` làm gì

Chạy `python tmpl_z3.py` sẽ in ra 3 ví dụ, tất cả đều giải < 0.1s:

- **PART 1 — Cơ bản:** flag 8 byte, minh hoạ các loại ràng buộc: tổng (`Sum` +
  `ZeroExt`), xor, hiệu/cộng (wrap 8-bit), tiền tố/hậu tố đã biết. Có kiểm tra
  **nghiệm duy nhất**.
- **PART 2 — Ràng buộc byte (rolling xor + cộng dồn):** tái tạo đúng vòng lặp
  `acc ^= f[i]; enc[i] = f[i] + acc` của binary. Cho thấy khi hàm **không đơn ánh**
  thì phải thêm ràng buộc **định dạng flag** để khóa nghiệm duy nhất.
- **PART 3 — ⭐ "1000 phương trình":** hệ tuyến tính **mod 256** với **1000 ràng
  buộc**, sinh toàn bộ bằng **vòng lặp** (không gõ tay), giải trong ~0.08s. Đây là
  trọng tâm (xem mục 6).

Ngoài ra có `cheatsheet()` (docstring) tra nhanh "logic C → ràng buộc z3".

---

## 4. Cách map logic check → ràng buộc z3 (từng bước)

**Bước 1 — Xác định ẩn số.** Flag dài `n` byte → tạo `n` biến BitVec 8-bit:
```python
f = [BitVec(f"f{i}", 8) for i in range(n)]
```
Mỗi biến là một byte chưa biết. (Hàm `make_flag_vars(n)` trong template.)

**Bước 2 — Ràng buộc miền giá trị.** Flag thường in được:
```python
for b in f: s.add(UGE(b, 0x20), ULE(b, 0x7e))   # dùng so sánh KHÔNG DẤU!
```

**Bước 3 — Dịch TỪNG phép check thành 1 ràng buộc.** Đọc code đã reverse, mỗi
phép so sánh/ràng buộc → một `s.add(...)`. Giữ nguyên **đúng kiểu số học** của
binary (wrap theo độ rộng, bitwise…). Ví dụ:

| Code C đã reverse | Ràng buộc z3 |
|---|---|
| `if (f[3] ^ f[1] != 0x2A) wrong;` | `s.add(f[3] ^ f[1] == 0x2A)` |
| `if ((uint8_t)(f[0]+f[5]) != 0x9C) wrong;` | `s.add(f[0] + f[5] == 0x9C)` |
| `if ((f[2]>>4) != 7) wrong;` (logic) | `s.add(LShR(f[2], 4) == 7)` |
| `s += A[r][c]*f[c]; ... if (s!=b[r])` | `s.add(Sum([A[r][c]*f[c] ...]) == b[r])` |

**Bước 4 — Giải và trích flag.**
```python
if s.check() == sat:
    m = s.model()
    flag = bytes(m[b].as_long() for b in f)
    print(flag)
```

**Bước 5 — Kiểm tra duy nhất.** Thêm "khác nghiệm vừa tìm" rồi `check()` lại; nếu
`unsat` ⇒ nghiệm duy nhất (yên tâm). Nếu `sat` ⇒ ràng buộc chưa đủ chặt, cần thêm
(vd định dạng flag). Hàm `find_second_solution(...)` trong template làm sẵn.

---

## 5. Giải thích các thành phần z3 hay dùng

- `BitVec('x', 8)` — số nguyên **fixed-width 8-bit**, mô phỏng đúng `uint8_t`:
  `+ - *` **tự wrap mod 256**, có đủ bitwise `^ & | ~ << >>`. Đây là lựa chọn mặc
  định cho byte.
- `BitVecVal(v, w)` — **hằng số** BitVec rộng `w` bit.
- `Int('x')` — số nguyên **toán học không giới hạn** (không wrap). Chỉ dùng khi
  bài là số học thuần, nhỏ, và không có modulo.
- `Solver()`, `s.add(c)`, `s.check()` → trả `sat`/`unsat`/`unknown`, `s.model()`.
- `s.push()/s.pop()` — lưu/khôi phục trạng thái (để thử ràng buộc tạm).
- `Sum([...])`, `And/Or/Not`, `If(cond, a, b)`, `Distinct([...])`.
- `ZeroExt(k, x)` — nới `x` thêm `k` bit 0 ở trên (mở rộng **không dấu**) → tránh
  tràn khi cộng/nhân nhiều số. `SignExt(k, x)` cho mở rộng **có dấu**.
- So sánh **không dấu**: `ULT ULE UGT UGE`; chia/mod không dấu: `UDiv URem`.
- Dịch phải **logic** (điền 0): `LShR(x, k)`. Xoay bit: `RotateLeft/RotateRight`.
- `s.set("timeout", 15000)` — đặt timeout (ms) để `check()` trả `unknown` thay vì
  treo vô hạn (rất nên dùng khi thử nghiệm).

---

## 6. ⭐ Mẫu "1000 phương trình" (giải HỆ RÀNG BUỘC LỚN)

**Vấn đề:** binary chứa ma trận hệ số `A[m][n]` và vector `b[m]`, check tính
`s = Σ_c A[r][c]*f[c]` (mod 256 vì `uint8_t`) rồi so với `b[r]`, lặp `m = 1000`
hàng. Giải tay bất khả thi.

**Nguyên tắc vàng: KHÔNG gõ tay từng phương trình — SINH bằng vòng lặp.**

```python
# 1) NẠP hằng số A, b từ binary (đừng chép tay 1000 số!)
raw = open("chall.bin", "rb").read()
import struct
A_flat = struct.unpack_from("<%di" % (m*n), raw, OFFSET_A)   # vd int32 LE
b      = struct.unpack_from("<%dB" % m,      raw, OFFSET_B)   # vd byte
A = [list(A_flat[r*n:(r+1)*n]) for r in range(m)]            # reshape m x n

# 2) SINH 1000 ràng buộc bằng for-loop
f = [BitVec(f"f{i}", 8) for i in range(n)]
s = Solver()
for x in f: s.add(UGE(x, 0x20), ULE(x, 0x7e))
for r in range(m):
    s.add(Sum([BitVecVal(A[r][c], 8) * f[c] for c in range(n)]) == b[r])  # mod 256

# 3) Giải
print(s.check())                      # sat
m_ = s.model(); print(bytes(m_[x].as_long() for x in f))
```

**Cách lấy A, b:** `struct.unpack_from` từ `.rodata`; hoặc copy mảng từ
IDA/Ghidra; hoặc `gdb`/script dump ra JSON rồi `json.load`. Sau đó `reshape`.

**Hiệu năng thực đo (máy thi, n=24, m=1000):**

| Kiểu hệ | Thời gian | Ghi chú |
|---|---|---|
| **Mod 256 THƯA** (mỗi pt ~4 ẩn), BitVec8 | **~0.07s**, nghiệm **duy nhất** ✅ | Ngon nhất |
| Mod 256 **dày đặc** (mỗi pt ~24 ẩn), BitVec8 | ~0.75s, **không** duy nhất ⚠️ | Mod làm mất đơn trị |
| Tuyến tính **số nguyên dày đặc KHÔNG mod** (Int) | **TREO > 90s** ❌ | Dùng numpy/sympy! |
| GF(2)/xor 1-bit, 1000 pt | **timeout 15s = unknown** ❌ | z3 mặc định không khử Gauss GF(2) |

→ z3 toả sáng với ràng buộc **modular/bitwise/thưa**. Hệ **tuyến tính số nguyên
dày đặc** là việc của **đại số tuyến tính** (mục 7).

---

## 7. Cạm bẫy (đọc kỹ — hay mất giờ nhất)

1. **BitVec vs Int.** Byte/`uintN` có wrap hoặc bitwise → **BitVec** (đúng ngữ
   nghĩa CPU). Số học thuần không wrap → `Int`. Dùng sai kiểu = sai nghiệm hoặc
   treo.
2. **Overflow / wrap.** `+ - *` trên BitVec **tự wrap** theo độ rộng. Muốn tổng/
   tích **không** wrap (giống `uint32` khi tính trên byte) → **`ZeroExt`** lên đủ
   rộng *trước khi* cộng/nhân. Ngược lại, nếu binary **cố ý** wrap (`uint8_t s`),
   hãy giữ đúng độ rộng để z3 wrap giùm.
3. **Signed vs unsigned.** Toán tử `< <= > >=`, `/ %`, `>>` mặc định là **CÓ
   DẤU**. Với byte/so sánh không dấu phải dùng `ULT/ULE/UGT/UGE`, `UDiv/URem`, và
   **`LShR`** cho dịch phải logic (toán tử `>>` là dịch *số học*, giữ bit dấu).
4. **Printable / miền giá trị.** Nhớ ràng buộc `0x20..0x7e` (bằng `UGE/ULE`), nếu
   không z3 có thể trả byte `\x00` hợp lệ về mặt toán nhưng không phải flag.
5. **Nghiệm không duy nhất.** Nhiều check **không đơn ánh** (xor+add, mod…). Luôn
   chạy `find_second_solution`; nếu còn nghiệm khác, thêm ràng buộc **định dạng
   flag** (`CSG{...}`, độ dài, chỉ chữ/số) để khóa.
6. **Hiệu năng.** (a) Hệ **số nguyên dày đặc không mod** → dùng **numpy/sympy**
   (`sympy.linsolve`, `numpy.linalg.solve`, hoặc Gauss mod p), KHÔNG z3. (b) GF(2)
   lớn → dùng khử Gauss nhị phân (tự viết / sage) thay vì z3 mặc định. (c) Luôn
   đặt `s.set("timeout", ...)` khi thử để tránh treo. (d) Hệ **thưa/modular** mới
   là sân nhà của z3.
7. **Thứ tự phép toán.** Khi mô phỏng vòng lặp có biến tích luỹ (`acc`), phải cập
   nhật `acc` **đúng thứ tự** như code gốc (xem PART 2) — sai thứ tự = unsat.
8. **`.as_long()`** để lấy giá trị số từ model (cả BitVec lẫn Int). Ghép byte:
   `bytes(m[b].as_long() for b in f)`.

---

## 8. Tham khảo

- Z3 Python — Getting Started / Programming Z3 (microsoft.github.io/z3guide)
- Z3 Python API: https://z3prover.github.io/api/html/namespacez3py.html
- HackTricks — Satisfiability Modulo Theories (Z3): dùng z3 trong reversing
- `pip install z3-solver` (PyPI) — bản đã kiểm thử ở đây: **z3-solver 5.3.1.0**
- Khi z3 không hợp: `sympy` (giải hệ ký hiệu), `numpy` (số), angr (symbolic exec).
