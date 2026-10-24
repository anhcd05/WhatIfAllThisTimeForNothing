#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tmpl_unicorn.py
===============
TEMPLATE: Emulate (chạy mô phỏng) MỘT hàm / một đoạn code được trích ra từ
binary mục tiêu bằng Unicorn Engine.

Ý tưởng: Thay vì đọc hiểu + port tay thuật toán check/transform phức tạp sang
Python, ta chỉ cần:
    1) Lấy raw bytes của hàm (từ Ghidra / objdump / radare2 / IDA).
    2) Map vùng nhớ cho code + stack trong Unicorn.
    3) Ghi bytes vào vùng code, set thanh ghi/tham số theo calling convention.
    4) Chạy emu_start() từ địa chỉ đầu hàm tới địa chỉ cuối (ret / 1 lệnh sau).
    5) Đọc kết quả ở thanh ghi (vd RAX) hoặc trong bộ nhớ.

Ưu điểm: KHÔNG thực thi toàn bộ binary của đề (an toàn hơn ctypes), chỉ chạy
đúng vùng code CPU mà ta kiểm soát hoàn toàn (không syscall, không I/O).

Cài đặt:  pip install unicorn
Tài liệu: https://github.com/unicorn-engine/unicorn  (docs/python-sample)

CÁC PHẦN CÓ "# TODO" LÀ CHỖ BẠN PHẢI SỬA CHO TỪNG ĐỀ.
"""

from unicorn import (
    Uc,
    UC_ARCH_X86,
    UC_MODE_64,
    UC_MODE_32,
    UC_HOOK_CODE,
    UC_PROT_ALL,
    UcError,
)
# Import các hằng số thanh ghi x86/x86-64 (UC_X86_REG_RAX, ...)
from unicorn.x86_const import (
    UC_X86_REG_RSP,
    UC_X86_REG_RBP,
    UC_X86_REG_RIP,
    UC_X86_REG_RAX,
    UC_X86_REG_RDI,
    UC_X86_REG_RSI,
    UC_X86_REG_RDX,
    UC_X86_REG_RCX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    # 32-bit (nếu dùng mode 32):
    UC_X86_REG_ESP,
    UC_X86_REG_EAX,
)

# ---------------------------------------------------------------------------
# 1. CẤU HÌNH BỐ TRÍ BỘ NHỚ (MEMORY LAYOUT)
# ---------------------------------------------------------------------------
# Lưu ý: Unicorn chỉ dùng được địa chỉ đã được mem_map. Các địa chỉ phải
# ALIGN theo page 4KB (0x1000). Kích thước map cũng phải là bội số của 0x1000.
#
# QUAN TRỌNG VỀ "ĐỊA CHỈ TUYỆT ĐỐI":
#   - Nếu code của đề có lệnh nhảy/tham chiếu dữ liệu theo địa chỉ TUYỆT ĐỐI
#     (vd call 0x401500, mov rax,[0x404000]) thì bạn PHẢI map code đúng tại
#     base address gốc trong binary (vd 0x400000) để các địa chỉ đó khớp.
#   - Nếu hàm là position-independent (chỉ dùng rip-relative và không gọi hàm
#     ngoài) thì base address tuỳ ý cũng được.
# ---------------------------------------------------------------------------

# Địa chỉ nền nơi nạp code. Đặt khớp với image base trong Ghidra nếu cần.
CODE_BASE = 0x400000          # TODO: đổi cho khớp base thật nếu có địa chỉ tuyệt đối
CODE_SIZE = 0x100000          # 1 MB vùng code (bội số 0x1000)

# Stack: cấp 1 vùng riêng, đặt RSP ở GIỮA vùng để stack có chỗ "mọc xuống"
# (x86 stack grows down) và vẫn còn chỗ cho tham số ghi "lên trên".
STACK_BASE = 0x300000
STACK_SIZE = 0x100000         # 1 MB
STACK_TOP = STACK_BASE + STACK_SIZE - 0x1000   # chừa 1 page đệm ở đỉnh

# Vùng nhớ phụ để chứa dữ liệu vào/ra (buffer input, con trỏ chuỗi...).
DATA_BASE = 0x200000
DATA_SIZE = 0x10000          # 64 KB


# ---------------------------------------------------------------------------
# 2. NẠP CODE BYTES CỦA HÀM
# ---------------------------------------------------------------------------
# Có 2 cách lấy bytes:
#   (a) Dán trực tiếp bytes trích từ Ghidra/objdump (nhanh, đủ cho 1 hàm nhỏ).
#   (b) Đọc nguyên file binary rồi cắt theo file-offset của hàm (chính xác hơn
#       với hàm lớn). Xem hàm load_code_from_file() bên dưới.
# ---------------------------------------------------------------------------

# (a) Dán bytes trực tiếp. Đây CHỈ LÀ VÍ DỤ MINH HOẠ (một hàm add rất đơn giản):
#       mov  rax, rdi      ; 48 89 F8
#       add  rax, rsi      ; 48 01 F0
#       ret                ; C3
# TODO: thay bằng bytes thật của hàm đề.
FUNC_CODE = bytes.fromhex("4889F8" "4801F0" "C3")

# Địa chỉ đầu hàm trong không gian địa chỉ đã map.
# Nếu bạn chỉ dán riêng bytes của hàm, ta ghi nó tại CODE_BASE và start = CODE_BASE.
# Nếu bạn nạp nguyên file tại image base, FUNC_ADDR = địa chỉ hàm trong Ghidra.
FUNC_ADDR = CODE_BASE        # TODO: đổi nếu nạp nguyên file (vd 0x4011A0)


def load_code_from_file(uc, path, file_offset, length, load_addr):
    """(Tuỳ chọn) Đọc 'length' bytes từ file binary tại 'file_offset' rồi ghi
    vào vùng nhớ Unicorn tại 'load_addr'.

    - file_offset: offset trong FILE (không phải địa chỉ ảo). Trong Ghidra, dùng
      cột 'file offset'; với objdump xem cột ngoài cùng bên trái của .text.
    - load_addr: địa chỉ ảo bạn muốn code nằm (thường = image base + rva).
    """
    with open(path, "rb") as f:
        f.seek(file_offset)
        blob = f.read(length)
    uc.mem_write(load_addr, blob)
    return blob


# ---------------------------------------------------------------------------
# 3. HOOK TRACE (tuỳ chọn) - in từng lệnh được thực thi
# ---------------------------------------------------------------------------
# Hook rất hữu ích để:
#   - Debug: xem CPU chạy tới đâu, giá trị thanh ghi thế nào.
#   - Dừng khẩn cấp: nếu phát hiện code chạy ra ngoài vùng mong muốn (lạc),
#     gọi uc.emu_stop().
# Bật/tắt bằng biến TRACE bên dưới (bật sẽ chậm, chỉ dùng khi debug).
# ---------------------------------------------------------------------------

TRACE = False  # TODO: đặt True khi cần xem từng lệnh

def hook_code(uc, address, size, user_data):
    """Được gọi TRƯỚC khi mỗi lệnh thực thi."""
    # Đọc raw bytes của lệnh hiện tại để tiện đối chiếu disassembly.
    code = uc.mem_read(address, size)
    rax = uc.reg_read(UC_X86_REG_RAX)
    print(f"[trace] {address:#010x}  size={size:<2}  bytes={code.hex():<16}  RAX={rax:#x}")
    # Ví dụ dừng nếu chạy tới địa chỉ cấm:
    # if address == 0xDEADBEEF:
    #     uc.emu_stop()


# ---------------------------------------------------------------------------
# 4. KHỞI TẠO EMULATOR + CHẠY MỘT LẦN
# ---------------------------------------------------------------------------

def make_emulator(mode=UC_MODE_64):
    """Tạo đối tượng Unicorn, map toàn bộ các vùng nhớ cần thiết.

    Trả về Uc đã sẵn sàng (chưa ghi code). Dùng lại object này nhiều lần khi
    brute để đỡ tốn chi phí map lại.
    """
    uc = Uc(UC_ARCH_X86, mode)

    # Map các vùng. UC_PROT_ALL = đọc/ghi/thực thi (đơn giản cho CTF).
    uc.mem_map(CODE_BASE, CODE_SIZE, UC_PROT_ALL)
    uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    uc.mem_map(DATA_BASE, DATA_SIZE, UC_PROT_ALL)

    if TRACE:
        uc.hook_add(UC_HOOK_CODE, hook_code)

    return uc


def setup_stack_and_args(uc, args, mode=UC_MODE_64):
    """Khởi tạo stack và nạp tham số theo calling convention.

    - args: list số nguyên (giá trị thanh ghi / con trỏ) truyền cho hàm.
    - 64-bit (System V, dùng trên Linux/Kali): thứ tự RDI, RSI, RDX, RCX, R8, R9.
      * CẢNH BÁO: Windows x64 dùng RCX, RDX, R8, R9 (khác!). Nếu emulate binary
        Windows thì sửa mapping bên dưới.
    - 32-bit (cdecl): tham số đẩy lên STACK, phải tay đẩy đúng thứ tự ngược.

    CĂN CHỈNH STACK (rất hay quên):
      Trước lệnh CALL, RSP phải chia hết cho 16 ở x64 SysV. Khi vào hàm, CPU đã
      push return-address nên RSP ≡ 8 (mod 16) ngay sau prologue. Ở đây ta
      KHÔNG thực sự CALL mà nhảy thẳng vào hàm, nên ta đặt RSP sao cho hàm chạy
      ổn. Cách an toàn: để RSP căn 16, rồi tự push 1 return-address giả.
    """
    if mode == UC_MODE_64:
        # Đặt RSP căn 16 rồi push return-address giả để hàm có chỗ 'ret' về.
        rsp = STACK_TOP & ~0xF          # căn xuống bội số 16
        fake_ret = CODE_BASE + CODE_SIZE - 0x10  # 1 địa chỉ hợp lệ đã map
        rsp -= 8
        uc.mem_write(rsp, fake_ret.to_bytes(8, "little"))
        uc.reg_write(UC_X86_REG_RSP, rsp)
        uc.reg_write(UC_X86_REG_RBP, rsp)

        # System V AMD64 (Linux). Với Windows x64 đổi thành: RCX,RDX,R8,R9.
        arg_regs = [
            UC_X86_REG_RDI,
            UC_X86_REG_RSI,
            UC_X86_REG_RDX,
            UC_X86_REG_RCX,
            UC_X86_REG_R8,
            UC_X86_REG_R9,
        ]
        for reg, val in zip(arg_regs, args):
            uc.reg_write(reg, val)
        # Tham số thứ 7 trở đi phải push lên stack (ít gặp trong CTF) -> TODO.
        return fake_ret
    else:
        # 32-bit cdecl: push return-address giả rồi push args theo thứ tự NGƯỢC.
        rsp = STACK_TOP & ~0xF
        fake_ret = CODE_BASE + CODE_SIZE - 0x10
        for val in reversed(args):
            rsp -= 4
            uc.mem_write(rsp, val.to_bytes(4, "little"))
        rsp -= 4
        uc.mem_write(rsp, fake_ret.to_bytes(4, "little"))
        uc.reg_write(UC_X86_REG_ESP, rsp)
        return fake_ret


def run_function(uc, func_addr, args, mode=UC_MODE_64, timeout=0, max_insns=0):
    """Chạy hàm một lần với 'args', trả về giá trị trả về (RAX/EAX).

    - func_addr: địa chỉ đầu hàm (đã khớp với nơi code được ghi).
    - timeout: micro-giây, 0 = vô hạn. Nên đặt >0 khi brute để tránh treo.
    - max_insns: số lệnh tối đa, 0 = vô hạn. Chốt chặn chống vòng lặp vô tận.
    """
    fake_ret = setup_stack_and_args(uc, args, mode)
    try:
        # emu_start(begin, until, timeout, count). 'until' = địa chỉ dừng khi
        # IP chạm tới. Ta dừng tại fake_ret (nơi hàm 'ret' nhảy về).
        uc.emu_start(func_addr, fake_ret, timeout=timeout, count=max_insns)
    except UcError as e:
        # Lỗi hay gặp: UC_ERR_FETCH_UNMAPPED (nhảy ra vùng chưa map -> địa chỉ
        # tuyệt đối sai), UC_ERR_READ_UNMAPPED (đọc con trỏ chưa set).
        raise RuntimeError(f"Unicorn lỗi khi chạy: {e} (RIP={uc.reg_read(UC_X86_REG_RIP):#x})")

    ret_reg = UC_X86_REG_RAX if mode == UC_MODE_64 else UC_X86_REG_EAX
    return uc.reg_read(ret_reg)


# ---------------------------------------------------------------------------
# 5. HÀM TIỆN ÍCH: GHI BUFFER INPUT VÀO BỘ NHỚ
# ---------------------------------------------------------------------------

def write_buffer(uc, data, addr=DATA_BASE):
    """Ghi 'data' (bytes) vào bộ nhớ tại 'addr', trả về 'addr' (con trỏ)."""
    uc.mem_write(addr, data)
    return addr


# ---------------------------------------------------------------------------
# 6. VÍ DỤ CHẠY ĐƠN (sanity check với hàm add mẫu)
# ---------------------------------------------------------------------------

def demo_single():
    """Demo: gọi hàm 'add(a, b)' bằng code bytes mẫu ở FUNC_CODE."""
    uc = make_emulator(UC_MODE_64)
    uc.mem_write(CODE_BASE, FUNC_CODE)      # ghi code vào vùng đã map
    result = run_function(uc, FUNC_ADDR, args=[12, 30], timeout=1_000_000)
    print(f"[demo] add(12, 30) = {result}  (kỳ vọng 42)")


# ---------------------------------------------------------------------------
# 7. MẪU BRUTE-FORCE: DÒ FLAG TỪNG BYTE QUA EMULATE
# ---------------------------------------------------------------------------
# Kịch bản điển hình: đề có hàm check(buf) trả về 0/1, hoặc hàm transform(buf)
# biến input thành output mà ta so với target. Ta emulate nhiều lần để dò.
#
# Hai chiến thuật thường dùng:
#   A) Hàm check trả True/False cho cả chuỗi -> brute từng ký tự nếu check có
#      tính "cộng dồn" (vd so khớp tới byte sai thì thoát sớm). Khó nếu không.
#   B) Hàm transform(input) -> output; ta tính output cho mọi ứng viên 1 byte
#      và so với target[i]. Hiệu quả khi mỗi byte output chỉ phụ thuộc 1 byte
#      input (xor/sbox từng byte). Đây là mẫu minh hoạ bên dưới.
# ---------------------------------------------------------------------------

def brute_flag_per_byte():
    """MẪU: dò flag từng byte giả định hàm transform xử lý độc lập từng byte.

    TODO: thay FUNC_CODE, FUNC_ADDR, calling convention, cách truyền buffer,
    cách đọc output và 'target' cho đúng đề.
    """
    FLAG_LEN = 16                       # TODO: độ dài flag thật
    # TODO: target = output đúng (lấy từ đề, vd mảng bytes so sánh trong binary)
    target = bytes([0x00] * FLAG_LEN)   # placeholder

    # Bảng ký tự ứng viên (printable). Thu hẹp nếu biết charset flag.
    charset = bytes(range(0x20, 0x7F))

    uc = make_emulator(UC_MODE_64)
    uc.mem_write(CODE_BASE, FUNC_CODE)  # ghi code 1 lần, tái dùng nhiều lần

    recovered = bytearray(b"?" * FLAG_LEN)
    for i in range(FLAG_LEN):
        for c in charset:
            # Dựng input ứng viên: các byte đã biết + byte đang thử + đệm.
            candidate = bytes(recovered[:i]) + bytes([c]) + b"\x00" * (FLAG_LEN - i - 1)
            buf_ptr = write_buffer(uc, candidate)

            # Gọi transform(buf_ptr, len) -> trả con trỏ/ghi output tại DATA.
            # TODO: sửa args & cách đọc output cho khớp chữ ký hàm đề.
            run_function(uc, FUNC_ADDR, args=[buf_ptr, FLAG_LEN], timeout=1_000_000)

            # Đọc output (giả sử hàm ghi output đè lên buf hoặc vùng khác).
            out = uc.mem_read(buf_ptr, FLAG_LEN)
            if out[i] == target[i]:
                recovered[i] = c
                print(f"[brute] byte {i:2d} = {chr(c)!r}  -> {bytes(recovered)!r}")
                break
        else:
            print(f"[brute] không tìm được byte {i}, dừng.")
            break

    print(f"[brute] FLAG (phỏng đoán) = {bytes(recovered)!r}")
    return bytes(recovered)


# ---------------------------------------------------------------------------
# 8. ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Chạy demo sanity trước để chắc chắn Unicorn hoạt động trên máy bạn.
    demo_single()

    # Khi đã cấu hình xong cho đề, bật dòng dưới để brute:
    # brute_flag_per_byte()
