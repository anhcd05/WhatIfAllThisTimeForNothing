#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tmpl_ctypes.py
==============
TEMPLATE: Nạp thư viện (.dll / .so) CỦA ĐỀ và gọi THẲNG hàm check/transform
bằng ctypes, để tái dùng nguyên thuật toán mà không phải port tay.

Khi nào dùng:
    - Đề cung cấp (hoặc ta trích được) một shared library chứa hàm xử lý
      (vd libcheck.so / check.dll với hàm `check(char* input)` hoặc
      `transform(char* in, char* out, int len)`).
    - Thuật toán phức tạp (nhiều vòng, state lớn) -> gọi lại hàm gốc nhanh &
      chính xác hơn Unicorn, lại không cần lo calling convention ở mức byte.

===============================================================================
⚠️⚠️⚠️  CẢNH BÁO AN TOÀN - BẮT BUỘC ĐỌC  ⚠️⚠️⚠️
-------------------------------------------------------------------------------
ctypes.CDLL / WinDLL sẽ NẠP VÀ THỰC THI code gốc của đề NGAY TRONG tiến trình
Python của bạn (full quyền của user). Điều này đồng nghĩa:

  * Bất kỳ hàm khởi tạo nào (DllMain trên Windows, constructor .init trên
    Linux) sẽ CHẠY ngay khi load — TRƯỚC khi bạn gọi hàm nào.
  * Binary độc hại có thể: xoá file, cài backdoor, lộ dữ liệu, thoát sandbox.

=> CHỈ chạy file này trong:
     - KALI VM / máy ảo CÁCH LY (snapshot trước, không mount ổ host quan trọng,
       tốt nhất tắt mạng hoặc dùng host-only), HOẶC
     - container/sandbox dùng-một-lần.
=> CHỈ nạp binary CỦA ĐỀ (từ nguồn ban tổ chức), KHÔNG nạp binary lạ.
=> KHÔNG BAO GIỜ chạy template này trực tiếp trên máy Windows host thi đấu.

Nếu chỉ cần chạy lại 1 hàm thuần tính toán (không I/O), cân nhắc dùng Unicorn
(tmpl_unicorn.py) vì nó KHÔNG thực thi toàn bộ binary -> an toàn hơn nhiều.
===============================================================================

ctypes có sẵn trong Python chuẩn, KHÔNG cần pip install.
Tài liệu: https://docs.python.org/3/library/ctypes.html

CÁC PHẦN CÓ "# TODO" LÀ CHỖ BẠN PHẢI SỬA CHO TỪNG ĐỀ.
"""

import ctypes
import os
import sys
from ctypes import (
    c_char_p,     # con trỏ char* (chuỗi C, kết thúc bằng NUL)
    c_void_p,     # con trỏ void*
    c_int,        # int (32-bit)
    c_uint,       # unsigned int
    c_size_t,     # size_t
    c_ubyte,      # unsigned char
    create_string_buffer,  # cấp buffer ghi được (mutable) cho hàm C ghi vào
    POINTER,
    byref,
)


# ---------------------------------------------------------------------------
# 1. NẠP THƯ VIỆN
# ---------------------------------------------------------------------------
# - Linux (.so):  ctypes.CDLL("./libcheck.so")
# - Windows (.dll, cdecl):   ctypes.CDLL("check.dll")
# - Windows (.dll, stdcall): ctypes.WinDLL("check.dll")   <- ít gặp với x64
#
# LƯU Ý ĐƯỜNG DẪN:
#   * Dùng đường dẫn TUYỆT ĐỐI hoặc "./ten.so" — Linux mặc định KHÔNG tìm .so
#     trong thư mục hiện tại.
#   * .dll có thể cần các .dll phụ thuộc nằm cùng thư mục (hoặc trong PATH).
#   * Phải khớp kiến trúc: Python 64-bit chỉ nạp được thư viện 64-bit, 32-bit
#     chỉ nạp 32-bit. (Kiểm tra: `file libcheck.so` / `dumpbin /headers x.dll`).
# ---------------------------------------------------------------------------

# TODO: đổi đường dẫn tới thư viện CỦA ĐỀ.
LIB_PATH = "./libtarget.so"     # vd Windows: r"C:\ctf\target.dll"


def load_library(path=LIB_PATH):
    """Nạp thư viện, tự chọn CDLL/WinDLL theo nền tảng.

    Trả về đối tượng library. Ném lỗi rõ ràng nếu không nạp được.
    """
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Không thấy thư viện: {path}")

    print(f"[ctypes] CẢNH BÁO: sắp NẠP & THỰC THI code gốc từ {path}")
    print("[ctypes] Đảm bảo bạn đang ở trong VM/sandbox cách ly!")

    if sys.platform == "win32":
        # Mặc định thử CDLL (cdecl / x64). Đổi sang WinDLL nếu hàm là __stdcall.
        return ctypes.CDLL(path)      # TODO: dùng ctypes.WinDLL(path) nếu stdcall
    else:
        return ctypes.CDLL(path)


# ---------------------------------------------------------------------------
# 2. KHAI BÁO CHỮ KÝ HÀM (argtypes / restype)
# ---------------------------------------------------------------------------
# BẮT BUỘC khai báo đúng argtypes & restype. Nếu bỏ qua, ctypes mặc định coi
# tham số & giá trị trả về là C int (32-bit) -> con trỏ 64-bit bị cắt -> CRASH
# hoặc kết quả rác. Đây là lỗi #1 khi dùng ctypes trên x64.
#
# Ánh xạ kiểu C -> ctypes thường gặp:
#   int            -> c_int
#   unsigned int   -> c_uint
#   char*          -> c_char_p (chỉ-đọc) hoặc buffer (ghi được)
#   void*          -> c_void_p
#   size_t         -> c_size_t
#   unsigned char* -> POINTER(c_ubyte)
# ---------------------------------------------------------------------------

def declare_signatures(lib):
    """Khai báo prototype cho các hàm sẽ dùng.

    TODO: đổi TÊN HÀM và kiểu cho khớp với đề. Lấy tên hàm export:
      - Linux: `nm -D libtarget.so`  hoặc `objdump -T libtarget.so`
      - Windows: `dumpbin /exports target.dll`
    """
    # Ví dụ A: int check(const char* input)  -> trả 1 nếu đúng, 0 nếu sai.
    lib.check.argtypes = [c_char_p]
    lib.check.restype = c_int

    # Ví dụ B: void transform(const char* in, char* out, int len)
    #   'out' là buffer ghi được -> khai báo c_char_p vẫn nhận create_string_buffer,
    #   nhưng rõ ràng hơn nên dùng c_void_p / POINTER(c_ubyte) cho tham số ghi.
    lib.transform.argtypes = [c_char_p, c_void_p, c_int]
    lib.transform.restype = None

    return lib


# ---------------------------------------------------------------------------
# 3. GỌI HÀM - CÁC MẪU TRUYỀN THAM SỐ
# ---------------------------------------------------------------------------

def call_check(lib, candidate: bytes) -> bool:
    """Gọi hàm check(char*) với chuỗi ứng viên, trả True/False.

    - candidate: bytes (KHÔNG phải str). Nếu có str, encode: s.encode().
    - c_char_p nhận bytes trực tiếp; ctypes tự thêm NUL kết thúc.
    """
    ret = lib.check(candidate)      # candidate là bytes -> c_char_p
    return ret != 0


def call_transform(lib, data: bytes, out_len: int) -> bytes:
    """Gọi transform(in, out, len): hàm ghi kết quả vào buffer 'out'.

    - Dùng create_string_buffer(out_len) để cấp vùng nhớ GHI ĐƯỢC cho hàm C.
      (c_char_p từ bytes là CHỈ-ĐỌC; hàm ghi vào đó sẽ hỏng/crash.)
    """
    out = create_string_buffer(out_len)     # buffer mutable, zero-filled
    lib.transform(data, out, out_len)
    return out.raw[:out_len]                 # .raw lấy toàn bộ bytes (kể cả NUL)


def call_returning_pointer(lib):
    """MẪU: hàm trả về char* (vd encrypt() cấp phát & trả con trỏ chuỗi).

    Khai báo restype = c_char_p -> ctypes tự đọc chuỗi C tới NUL thành bytes.
    Nếu hàm trả con trỏ tới vùng nhị phân có NUL ở giữa, dùng restype =
    POINTER(c_ubyte) rồi tự đọc theo độ dài.
    """
    # TODO: khai báo & gọi theo đề; đây chỉ là khung minh hoạ.
    # lib.encrypt.argtypes = [c_char_p]
    # lib.encrypt.restype = c_char_p
    # result = lib.encrypt(b"input")   # result là bytes
    # return result
    raise NotImplementedError("TODO: điền theo hàm thật của đề")


# ---------------------------------------------------------------------------
# 4. MẪU BRUTE-FORCE QUA CTYPES
# ---------------------------------------------------------------------------
# Vì gọi hàm gốc rất nhanh (native speed), brute qua ctypes thường nhanh hơn
# Unicorn nhiều lần. Hai mẫu:
#   A) check() trả bool cho cả chuỗi -> nếu brute toàn bộ bất khả thi, cần
#      check có đặc tính dò được từng byte (vd so khớp dừng sớm + đo thời gian,
#      hoặc đề lộ hàm kiểm tra từng ký tự).
#   B) transform()/encrypt() biến input->output, so với target -> dò từng byte
#      khi mỗi byte output phụ thuộc 1 byte input. (mẫu bên dưới)
# ---------------------------------------------------------------------------

def brute_with_check(lib):
    """MẪU A: brute toàn chuỗi bằng check() (chỉ khả thi nếu không gian nhỏ,
    hoặc check() cho phép dò tăng dần)."""
    charset = bytes(range(0x20, 0x7F))
    FLAG_LEN = 16            # TODO
    recovered = bytearray(b"?" * FLAG_LEN)

    # Chiến thuật "từng byte" chỉ đúng nếu check() đọc tới ký tự sai thì dừng/
    # trả tín hiệu phân biệt được (vd side-channel). Nhiều đề KHÔNG như vậy ->
    # khi đó phải tìm hàm khác (transform) hoặc dùng cờ nội bộ. Giữ làm khung:
    for i in range(FLAG_LEN):
        for c in charset:
            cand = bytes(recovered[:i]) + bytes([c]) + b"\x00" * (FLAG_LEN - i - 1)
            if call_check(lib, cand):
                # TODO: thường check() chỉ True khi TOÀN BỘ đúng; logic này cần
                # điều chỉnh theo hành vi thật của hàm.
                recovered[i] = c
                break
    return bytes(recovered)


def brute_with_transform(lib):
    """MẪU B: dò flag từng byte giả định transform xử lý độc lập từng byte.

    TODO: thay tên hàm, chữ ký, độ dài, target cho đúng đề.
    """
    FLAG_LEN = 16
    OUT_LEN = 16
    # TODO: target = output đúng mà đề so sánh (lấy từ binary/đề bài).
    target = bytes([0x00] * OUT_LEN)

    charset = bytes(range(0x20, 0x7F))
    recovered = bytearray(b"?" * FLAG_LEN)

    for i in range(FLAG_LEN):
        for c in charset:
            cand = bytes(recovered[:i]) + bytes([c]) + b"\x00" * (FLAG_LEN - i - 1)
            out = call_transform(lib, cand, OUT_LEN)
            if out[i] == target[i]:
                recovered[i] = c
                print(f"[brute] byte {i:2d} = {chr(c)!r} -> {bytes(recovered)!r}")
                break
        else:
            print(f"[brute] không tìm được byte {i}, dừng.")
            break

    print(f"[brute] FLAG (phỏng đoán) = {bytes(recovered)!r}")
    return bytes(recovered)


# ---------------------------------------------------------------------------
# 5. ENTRY POINT
# ---------------------------------------------------------------------------

def main():
    # Chốt an toàn: bắt người dùng xác nhận đang ở sandbox trước khi nạp.
    # (Gỡ/đổi tuỳ ý, nhưng NÊN giữ để tránh lỡ tay chạy trên host.)
    if os.environ.get("I_AM_IN_SANDBOX") != "1":
        print("DỪNG: đặt biến môi trường I_AM_IN_SANDBOX=1 để xác nhận bạn đang")
        print("      chạy trong VM/sandbox cách ly rồi chạy lại.")
        print("      vd (Kali):  I_AM_IN_SANDBOX=1 python3 tmpl_ctypes.py")
        sys.exit(1)

    lib = load_library(LIB_PATH)
    declare_signatures(lib)

    # Ví dụ gọi đơn:
    # print("check('test') =", call_check(lib, b"test"))

    # Khi cấu hình xong, bật brute:
    # brute_with_transform(lib)


if __name__ == "__main__":
    main()
