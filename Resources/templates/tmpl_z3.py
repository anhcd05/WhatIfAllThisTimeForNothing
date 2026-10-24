#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 TEMPLATE Z3 CHO REVERSE / CRYPTO  -  Cyber SEA Game 2026
================================================================================
 Mục tiêu: Dùng z3 (SMT solver) để GIẢI NGƯỢC input (flag) từ logic check đã
           reverse ra. Rất mạnh khi bài có HÀNG TRĂM/NGHÌN RÀNG BUỘC tuyến tính
           hoặc bitwise mà giải tay thì bất khả thi ("hệ 1000 phương trình").

 Cài đặt:  pip install z3-solver          (import tên module là `z3`)
 Chạy:     python tmpl_z3.py

 Ý tưởng cốt lõi:
   1) Khai báo mỗi byte của flag là 1 biến BitVec 8-bit (ẩn số).
   2) Dịch TỪNG phép check trong binary -> 1 constraint (ràng buộc) z3.
   3) Gọi solver.check(); nếu sat -> solver.model() cho giá trị từng byte.
   4) Ghép byte -> chuỗi flag. Kiểm tra nghiệm có DUY NHẤT không.

 Mẹo quan trọng cho "hệ 1000 phương trình":
   - KHÔNG gõ tay từng phương trình. Nạp hằng số (lấy từ binary / dump) vào
     một list/ma trận rồi SINH constraint bằng VÒNG LẶP for (xem PART 3).
================================================================================
"""

import sys
# Ép stdout sang UTF-8 để in tiếng Việt không lỗi trên console Windows (cp1252).
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from z3 import (
    BitVec, BitVecVal, BitVecs,      # biến & hằng số kiểu vector bit (số nguyên fixed-width)
    Int,                             # biến số nguyên toán học (không wrap) - dùng khi cần
    Solver, sat, unsat,              # solver + hằng kết quả
    And, Or, Not, If, Sum, Distinct, # các bộ kết nối logic hữu ích
    simplify,                        # rút gọn biểu thức (tiện debug/ép kiểu)
    ULT, ULE, UGT, UGE, URem, UDiv,  # phép so sánh/chia KHÔNG DẤU (unsigned)
)


# =============================================================================
# TIỆN ÍCH CHUNG
# =============================================================================
def make_flag_vars(n, name="f"):
    """Tạo n biến BitVec 8-bit: f0, f1, ... (mỗi biến = 1 byte của flag)."""
    return [BitVec(f"{name}{i}", 8) for i in range(n)]


def add_printable(solver, flag, lo=0x20, hi=0x7e):
    """Ràng buộc mỗi byte nằm trong vùng ký tự in được (ASCII 0x20..0x7e).

    LƯU Ý: byte là 8-bit UNSIGNED -> phải dùng so sánh KHÔNG DẤU (ULE/UGE),
    nếu dùng <=, >= mặc định thì z3 coi là CÓ DẤU và sẽ sai với byte >= 0x80.
    """
    for b in flag:
        solver.add(UGE(b, lo))   # b >= 0x20 (unsigned)
        solver.add(ULE(b, hi))   # b <= 0x7e (unsigned)


def model_to_bytes(model, flag):
    """Trích giá trị các byte từ model -> bytes. .as_long() lấy giá trị số."""
    return bytes(model[b].as_long() for b in flag)


def find_second_solution(solver, flag, first_bytes):
    """Kiểm tra nghiệm có DUY NHẤT không.

    Cách làm: thêm ràng buộc "khác nghiệm đầu tiên" (ÍT NHẤT 1 byte khác) rồi
    check lại. unsat => nghiệm duy nhất (yên tâm). sat => còn nghiệm khác =>
    logic ràng buộc CHƯA đủ chặt, flag có thể không đúng.
    """
    solver.push()  # lưu trạng thái để lát pop ra, không làm bẩn solver gốc
    solver.add(Or([b != BitVecVal(v, 8) for b, v in zip(flag, first_bytes)]))
    res = solver.check()
    second = model_to_bytes(solver.model(), flag) if res == sat else None
    solver.pop()
    return second


# =============================================================================
# PART 1 - VÍ DỤ CƠ BẢN: ràng buộc tổng / xor / so sánh với hằng số
# =============================================================================
def demo_basic():
    """
    Giả sử reverse ra logic check (viết bằng C) như sau, flag dài 8 ký tự:

        char f[8];
        // (a) tổng tất cả byte = 0x02C5
        // (b) f[0] ^ f[1] = 0x15
        // (c) f[2] + f[3] = 0xDA           (cộng WRAP 8-bit!)
        // (d) f[4] * 3 = 0x0129            (tính trên không gian rộng hơn)
        // (e) f[5] = f[0] + 0x10
        // (f) biết trước: f[6]='3', f[7]='}'   (vd hậu tố flag)
        // (g) tiền tố: f[0]='C' (vd flag "CSG...")
    """
    print("\n" + "=" * 70)
    print("PART 1 - Ví dụ cơ bản (tổng / xor / nhân / so sánh hằng)")
    print("=" * 70)

    from z3 import ZeroExt

    # Flag mẫu 8 ký tự để SINH ra các hằng số (ở bài thật các hằng này lấy từ
    # binary; ở đây tính ra để template luôn chạy ĐÚNG và cho nghiệm DUY NHẤT).
    secret = b"C0d3{Z3}"                         # TODO: bài thật KHÔNG có dòng này
    n = len(secret)

    # Các hằng số reverse ra (ở đây derive từ secret). Mỗi hằng = 1 phép check:
    K1 = secret[0] ^ secret[1]                   # (b) xor
    K2 = (secret[2] - secret[1]) & 0xFF          # (c) hiệu (wrap 8-bit)
    K3 = secret[3] ^ secret[2]                   # (d) xor chuỗi
    K4 = (secret[4] - secret[3]) & 0xFF          # (e) hiệu (wrap)
    K5 = secret[5] ^ secret[4]                   # (f) xor chuỗi
    K6 = (secret[6] - secret[5]) & 0xFF          # (g) hiệu (wrap)
    SUM = sum(secret)                            # (a) tổng (kiểm tra chéo)

    f = make_flag_vars(n)
    s = Solver()
    add_printable(s, f)

    # (0) Byte đã biết: tiền tố + hậu tố flag (rất hay gặp: "CSG{....}").
    s.add(f[0] == ord('C'))
    s.add(f[7] == ord('}'))

    # (a) Tổng tất cả byte = SUM. DÙNG Sum + ÉP kiểu rộng để tránh wrap 8-bit
    #     ngoài ý muốn: mỗi f[i] 8-bit, cộng 8 cái có thể tràn -> nới lên 16-bit.
    #     ZeroExt(k, bv) nối thêm k bit 0 ở trên (mở rộng KHÔNG DẤU).
    s.add(Sum([ZeroExt(8, b) for b in f]) == BitVecVal(SUM, 16))          # (a)

    # (b)..(g) Chuỗi quan hệ xor/hiệu giữa các byte kề nhau -> "khóa" từng byte
    #          theo byte trước, nên kết hợp với f[0] đã biết => nghiệm DUY NHẤT.
    s.add(f[0] ^ f[1] == K1)                     # (b) xor hai byte = hằng
    s.add(f[2] - f[1] == K2)                     # (c) hiệu (tự wrap 8-bit)
    s.add(f[3] ^ f[2] == K3)                     # (d)
    s.add(f[4] - f[3] == K4)                     # (e)
    s.add(f[5] ^ f[4] == K5)                     # (f)
    s.add(f[6] - f[5] == K6)                     # (g)

    if s.check() == sat:
        m = s.model()
        data = model_to_bytes(m, f)
        print("  [sat] flag =", data.decode(errors="replace"))
        print("  hex       =", data.hex())
        dup = find_second_solution(s, f, data)
        print("  Duy nhất? ", "CÓ (tốt)" if dup is None else f"KHÔNG - còn: {dup!r}")
    else:
        print("  [unsat] Ràng buộc mâu thuẫn - kiểm tra lại logic reverse.")


# =============================================================================
# PART 2 - VÍ DỤ RÀNG BUỘC BYTE: cộng dồn (rolling) + xor theo chuỗi
# =============================================================================
def demo_byte_chain():
    """
    Mẫu check kiểu "rolling xor / cộng dồn" rất hay gặp:

        uint8_t acc = KEY0;                 // seed
        for (i = 0; i < n; i++) {
            acc = acc ^ f[i];               // xor dồn
            enc[i] = f[i] + acc;            // (wrap 8-bit)
        }
        // so sánh enc[] với mảng hằng ENC[] lấy từ binary

    Ta tái tạo đúng y hệt luồng tính bằng biến z3 -> mỗi vòng lặp thêm constraint.
    """
    print("\n" + "=" * 70)
    print("PART 2 - Ràng buộc byte: rolling xor + cộng dồn")
    print("=" * 70)

    # Giả lập: tạo flag thật rồi tính ENC[] để template chạy ra kết quả.
    # TODO: Khi làm bài THẬT -> XÓA phần giả lập, thay ENC/KEY0 bằng giá trị
    #       DUMP TỪ BINARY (xem PART 3 cách nạp hằng số).
    KEY0 = 0x5A
    secret = b"CSG{r0ll1ng}"            # chỉ dùng để sinh ENC mẫu
    enc_const = []
    acc_real = KEY0
    for ch in secret:
        acc_real ^= ch
        enc_const.append((ch + acc_real) & 0xFF)   # & 0xFF = wrap 8-bit
    n = len(secret)

    # ---- Phần GIẢI bằng z3 (đây mới là thứ cần giữ lại) ----
    f = make_flag_vars(n)
    s = Solver()
    add_printable(s, f)

    acc = BitVecVal(KEY0, 8)            # biến tích luỹ, khởi tạo = seed
    for i in range(n):
        acc = acc ^ f[i]               # cập nhật acc GIỐNG HỆT code gốc
        # enc[i] = f[i] + acc  (wrap 8-bit) phải bằng hằng enc_const[i]
        s.add(f[i] + acc == BitVecVal(enc_const[i], 8))

    # LƯU Ý: phép (f[i] + (acc ^ f[i])) KHÔNG đơn ánh -> nhiều f[i] cho cùng enc[i],
    # nên chỉ với enc[] thôi là CHƯA đủ chặt (xem find_second_solution báo trùng).
    # Thực tế flag luôn có ĐỊNH DẠNG biết trước -> thêm ràng buộc tiền tố/hậu tố
    # để "khóa" nghiệm về đúng flag duy nhất (đây là mẹo rất hay dùng!).
    for i, ch in enumerate(b"CSG{"):   # tiền tố
        s.add(f[i] == ch)
    s.add(f[n - 1] == ord('}'))        # hậu tố

    if s.check() == sat:
        data = model_to_bytes(s.model(), f)
        print("  [sat] flag =", data.decode(errors="replace"))
        dup = find_second_solution(s, f, data)
        print("  Duy nhất? ", "CÓ (tốt)" if dup is None else f"KHÔNG - còn: {dup!r}")
    else:
        print("  [unsat] Kiểm tra lại seed/thứ tự phép toán/wrap.")


# =============================================================================
# PART 3  ***  MẪU "1000 PHƯƠNG TRÌNH"  ***  (QUAN TRỌNG NHẤT)
# =============================================================================
def demo_linear_system():
    """
    TÌNH HUỐNG THỰC TẾ:
      Binary chứa MA TRẬN hệ số A (m x n) và VECTOR kết quả b (m phần tử). Check
      tính một tổ hợp tuyến tính của các byte flag theo MODULO 256 (uint8) rồi so
      sánh với b. Đây là dạng RẤT HAY GẶP (checksum/hash tuyến tính, "ma trận bí mật"):

          for (r = 0; r < m; r++) {
              uint8_t s = 0;                       // <-- uint8 => TỰ WRAP mod 256
              for (c = 0; c < n; c++)
                  s += A[r][c] * f[c];             // tổ hợp tuyến tính các byte
              if (s != b[r]) return WRONG;         // m phương trình
          }

      Với m ~ 1000 phương trình -> giải tay bất khả thi, nhưng z3 "nuốt" gọn trong
      ~0.1s. BÍ QUYẾT: nạp A, b từ dữ liệu rồi SINH constraint bằng for-loop,
      TUYỆT ĐỐI không gõ tay.

    *** CHỌN KIỂU BIẾN CHO ĐÚNG (quyết định HIỆU NĂNG - đọc kỹ) ***
      - Có MODULO (uint8/uint16/uint32 tự wrap) hoặc có bitwise (xor/shift/and):
        -> DÙNG BitVec đúng độ rộng. z3 giải cực nhanh kể cả 1000 pt. (template này)
      - Hệ tuyến tính SỐ NGUYÊN "thuần", DÀY ĐẶC, KHÔNG modulo (mỗi pt dùng gần hết
        các ẩn): z3 CHẬM/TREO! Đây là bài của ĐẠI SỐ TUYẾN TÍNH, hãy dùng
        numpy/sympy (Gauss) hoặc sage, KHÔNG dùng z3. (xem GUIDE phần "Cạm bẫy")
      - Hệ THƯA (mỗi pt chỉ liên quan vài ẩn): z3 xử lý tốt nhờ lan truyền ràng buộc.

    CÁCH LẤY A, b TỪ BINARY (chọn 1):
      - Đọc section .data/.rodata bằng Python:
            raw = open("chall.bin","rb").read()
            import struct
            A_flat = struct.unpack_from("<%di" % (m*n), raw, OFFSET_A)  # int32 LE
            b      = struct.unpack_from("<%dB" % m,      raw, OFFSET_B)  # byte
            A = [list(A_flat[r*n:(r+1)*n]) for r in range(m)]           # reshape
      - Hoặc copy mảng từ IDA/Ghidra, hoặc script gdb dump ra JSON rồi json.load.
    """
    print("\n" + "=" * 70)
    print("PART 3 - MẪU '1000 PHƯƠNG TRÌNH' (hệ tuyến tính lớn, mod 256)")
    print("=" * 70)

    import random, time

    # ----- (A) Giả lập dữ liệu để template CHẠY ĐƯỢC ngay -----
    # TODO BÀI THẬT: thay toàn bộ block (A) này bằng A, b_const NẠP TỪ BINARY.
    n = 24                               # số ẩn (độ dài flag)
    m = 1000                             # <<< SỐ PHƯƠNG TRÌNH (1000!)
    secret = (b"CSG{z3_solves_1000_eqs}"[:n]).ljust(n, b"_")

    # Hệ THƯA: mỗi phương trình chỉ đụng tới K ẩn (giống nhiều check thực tế, và
    # giúp nghiệm DUY NHẤT + z3 chạy nhanh). Với A dày đặc + mod 256 thì vẫn ra
    # nghiệm nhưng THƯỜNG KHÔNG duy nhất (nhiều ẩn bù trừ nhau mod 256).
    K = 4
    A_rows = []                          # mỗi phần tử: list (cột, hệ số)
    b_const = []
    rng = random.Random(1337)            # seed cố định -> tái lập được
    for r in range(m):
        cols = rng.sample(range(n), K)
        coefs = [rng.randint(1, 255) for _ in cols]
        rhs = sum(coefs[k] * secret[cols[k]] for k in range(K)) & 0xFF  # wrap 256
        A_rows.append(list(zip(cols, coefs)))
        b_const.append(rhs)

    # ----- (B) Giải bằng z3 dùng BitVec 8-bit (TỰ WRAP mod 256) -----
    f = make_flag_vars(n)                # 24 byte ẩn, 8-bit
    s = Solver()
    add_printable(s, f)

    # *** VÒNG LẶP SINH 1000 CONSTRAINT - KHÔNG gõ tay ***
    # Phép +, * trên BitVec 8-bit tự động wrap mod 256 -> khớp đúng uint8 của C.
    for r in range(m):
        terms = [BitVecVal(coef, 8) * f[col] for (col, coef) in A_rows[r]]
        s.add(Sum(terms) == BitVecVal(b_const[r], 8))

    print(f"  Đã nạp {m} phương trình, {n} ẩn (BitVec8/mod256). Đang giải...")
    t0 = time.time()
    res = s.check()
    dt = time.time() - t0

    if res == sat:
        data = model_to_bytes(s.model(), f)
        print(f"  [sat] trong {dt:.2f}s  ->  flag = {data.decode(errors='replace')}")
        # Kiểm tra duy nhất (quan trọng với hệ mod: dễ có nhiều nghiệm).
        dup = find_second_solution(s, f, data)
        print("  Duy nhất? ", "CÓ (tốt)" if dup is None else f"KHÔNG - còn: {dup!r}")
    else:
        print(f"  [{res}] trong {dt:.2f}s - hệ vô nghiệm hoặc nạp sai A/b/offset.")


# =============================================================================
# MỘT SỐ MẪU CONSTRAINT HAY DÙNG (tham khảo nhanh, không chạy)
# =============================================================================
def cheatsheet():
    """
    Bảng tra nhanh: logic trong binary  ->  constraint z3 tương ứng.

    | Logic (C)                         | z3                                    |
    |-----------------------------------|---------------------------------------|
    | f[i] == 0x41                      | s.add(f[i] == 0x41)                   |
    | f[i] ^ f[j] == k                  | s.add(f[i] ^ f[j] == k)               |
    | f[i] + f[j] == k   (uint8 wrap)   | s.add(f[i] + f[j] == k)               |
    | (f[i] << 3) | (f[i] >> 5) == k    | s.add(RotateLeft(f[i], 3) == k)       |
    | f[i] >> 4 == k   (logical)        | s.add(LShR(f[i], 4) == k)  # KHÔNG >> |
    | f[i] / 7 == k    (unsigned)       | s.add(UDiv(f[i], 7) == k)             |
    | f[i] % 7 == k    (unsigned)       | s.add(URem(f[i], 7) == k)             |
    | f[i] < 0x80      (unsigned)       | s.add(ULT(f[i], 0x80))                |
    | tất cả byte khác nhau             | s.add(Distinct(f))                    |
    | tổng không wrap                   | ZeroExt rồi Sum (xem PART 1/3)        |
    | if (c) a else b                   | If(c, a, b)                           |

    GHI NHỚ BẪY LỚN NHẤT:
      - >> trên BitVec là dịch SỐ HỌC (arithmetic, giữ dấu). Muốn dịch LOGIC
        (điền 0) phải dùng LShR(x, k).
      - <, <=, >, >= mặc định là CÓ DẤU. Byte so sánh phải dùng ULT/ULE/UGT/UGE.
      - +,-,* trên BitVec TỰ WRAP theo độ rộng bit. Muốn không wrap -> ZeroExt.
    """
    pass


# =============================================================================
if __name__ == "__main__":
    demo_basic()
    demo_byte_chain()
    demo_linear_system()
    print("\nXong. Sửa các khối 'TODO' theo bài thật của bạn.")
