#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  TEMPLATE angr (Symbolic Execution) - Cyber SEA Game 2026 / Reverse
# -----------------------------------------------------------------------------
#  Muc dich: Khung san co de giai cac bai Reverse dang "kiem tra input"
#            (keygen / flag checker) bang symbolic execution, KHONG can
#            dich tay toan bo logic.
#
#  Cach dung nhanh:
#     1. Doc phan "# TODO" va sua lai cho dung binh cua ban.
#     2. Chon 1 trong 3 mau (A / B / C) o cuoi file bang bien MODE.
#     3. Chay:  python tmpl_angr.py
#
#  Tai lieu di kem: GUIDE_angr.md (doc truoc khi dung).
#
#  LUU Y AN TOAN: chi chay voi binary CUA DE BAI (tin cay). Khong chay
#  binary la tren may that; neu nghi ngo, chay trong VM/sandbox.
# =============================================================================

import logging
import sys

import angr      # pip install angr
import claripy   # di kem angr, dung de tao bien symbolic (BVS/BVV)

# Giam bot log rac cua angr (chi hien WARNING tro len).
# Khi debug muon xem nhieu hon: doi ERROR -> INFO / DEBUG.
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)


# =============================================================================
#  CAU HINH CHUNG  -- SUA O DAY
# =============================================================================

# TODO: Duong dan toi file binary cua de bai.
BINARY = "./chall"

# TODO: Chon mau se chay: "A", "B", hoac "C" (xem mo ta ben duoi).
MODE = "A"

# TODO: Do dai input (so byte) ban doan flag/key can. Dieu chinh cho khop.
INPUT_LEN = 32


# =============================================================================
#  TIEN ICH DUNG CHUNG
# =============================================================================

def make_symbolic_bytes(name, length):
    """Tao mot danh sach cac byte symbolic (moi byte 8 bit) va noi lai thanh
    mot BitVector dai 'length*8' bit.

    Tra ve: (bv_tong, danh_sach_tung_byte)
      - bv_tong : dung de nap vao stdin / buffer / argv.
      - danh_sach_tung_byte : dung de dat rang buoc len tung ky tu (vd printable).
    """
    byte_list = [claripy.BVS(f"{name}_{i}", 8) for i in range(length)]
    return claripy.Concat(*byte_list), byte_list


def constrain_printable(state, byte_list):
    """Rang buoc moi byte nam trong khoang in duoc (0x20..0x7e).

    Giup solver KHONG tra ve nhung ky tu dieu khien vo nghia va thuong giup
    hoi tu nhanh hon. Neu flag co the chua byte dac biet, hay noi long lai.
    """
    for b in byte_list:
        state.solver.add(b >= 0x20)   # TODO: can thi doi thanh 0x21 (bo space)
        state.solver.add(b <= 0x7e)


def constrain_charset(state, byte_list, charset):
    """Phuong an chat hon printable: ep moi byte thuoc mot tap ky tu cho truoc.
    Vi du charset = b"abcdef0123456789" cho flag dang hex.
    """
    for b in byte_list:
        state.solver.add(claripy.Or(*[b == c for c in charset]))


# =============================================================================
#  MAU A -- find / avoid theo DIA CHI hoac theo CHUOI, stdin symbolic
# -----------------------------------------------------------------------------
#  Dung khi: chuong trinh doc input tu stdin (scanf/fgets/read) roi in ra
#  "Correct"/"Wrong" (hoac rong ra 2 nhanh success/fail ro rang).
#
#  Co 2 cach xac dinh dich:
#    A1) Theo DIA CHI: biet dia chi lenh cua nhanh "in Correct" (find) va
#        nhanh "in Wrong" (avoid). Tim dia chi bang IDA/Ghidra/objdump.
#    A2) Theo CHUOI STDOUT: khong can dia chi, chi can biet chuoi in ra khi
#        dung/sai. De dung nhat, nen uu tien cach nay neu duoc.
# =============================================================================

def solve_mode_A():
    print("[*] MODE A: stdin symbolic + find/avoid")

    proj = angr.Project(BINARY, auto_load_libs=False)

    # Tao input symbolic cho stdin.
    flag, flag_bytes = make_symbolic_bytes("flag", INPUT_LEN)

    # entry_state: bat dau tu entry point cua chuong trinh.
    #   - stdin=flag : nap bien symbolic lam du lieu stdin.
    #   - add_options ZERO_FILL_* : vung nho/thanh ghi chua khoi tao se duoc
    #     dien 0 thay vi tao them bien symbolic -> giam path explosion, bot
    #     canh bao "unconstrained".
    state = proj.factory.entry_state(
        stdin=flag,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )

    # (Tuy chon) rang buoc printable de ket qua doc duoc.
    constrain_printable(state, flag_bytes)

    simgr = proj.factory.simulation_manager(state)

    # ------------------------------------------------------------------
    #  CHON 1 TRONG 2 KIEU DICH (find/avoid). Bo comment kieu ban dung.
    # ------------------------------------------------------------------

    # --- A1) Theo DIA CHI ---------------------------------------------
    # TODO: thay bang dia chi that (vd 0x401337). Co the la list dia chi.
    # FIND_ADDR  = 0x400000
    # AVOID_ADDR = 0x400000
    # simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

    # --- A2) Theo CHUOI in ra stdout (fd=1) ---------------------------
    # Thuong ben vung hon vi khong phu thuoc dia chi tuyet doi.
    # TODO: sua "Correct" / "Wrong" cho khop thong bao that cua binary.
    simgr.explore(
        find=lambda s: b"Correct" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong" in s.posix.dumps(1),
    )

    _report(simgr)


# =============================================================================
#  MAU B -- input symbolic nap vao BUFFER trong bo nho hoac vao ARGV
# -----------------------------------------------------------------------------
#  Dung khi:
#    B1) Ham kiem tra nhan con tro toi mot buffer (vd check(char *buf)):
#        ta tu dung state o giua ham, ghi bien symbolic vao bo nho, dat con
#        tro, roi explore. Dung blank_state de bat dau tai dia chi mong muon.
#    B2) Chuong trinh lay input tu tham so dong lenh argv[1].
# =============================================================================

def solve_mode_B():
    print("[*] MODE B: symbolic vao buffer / argv + rang buoc printable")

    proj = angr.Project(BINARY, auto_load_libs=False)

    # -------------------- B2) ARGV (de hon, lam mac dinh) --------------
    flag, flag_bytes = make_symbolic_bytes("arg", INPUT_LEN)

    # argv[0] = ten chuong trinh (khong anh huong), argv[1] = input symbolic.
    state = proj.factory.full_init_state(
        args=[BINARY, flag],
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    constrain_printable(state, flag_bytes)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(
        find=lambda s: b"Correct" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong" in s.posix.dumps(1),
    )
    _report(simgr, symbolic_bv=flag, label="argv[1]")

    # -------------------- B1) BUFFER trong bo nho (mau tham khao) ------
    # Bo comment khi ban muon bat dau tu GIUA ham check(buf):
    #
    # CHECK_ADDR = 0x401200   # TODO: dia chi dau ham check / diem muon bat dau
    # BUF_ADDR   = 0x4040000  # TODO: dia chi vung nho tu chon de dat buffer
    #
    # st = proj.factory.blank_state(
    #     addr=CHECK_ADDR,
    #     add_options={
    #         angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
    #         angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    #     },
    # )
    # flag2, flag2_bytes = make_symbolic_bytes("buf", INPUT_LEN)
    # st.memory.store(BUF_ADDR, flag2)          # ghi bien symbolic vao buffer
    # constrain_printable(st, flag2_bytes)
    #
    # # Truyen con tro buffer vao ham. Tuy ABI:
    # #   - x86-64 Linux (SysV): tham so 1 o RDI.
    # #       st.regs.rdi = BUF_ADDR
    # #   - x86 32-bit (cdecl): tham so day qua stack (can push thu cong).
    # st.regs.rdi = BUF_ADDR                     # TODO: chinh theo kien truc/ABI
    #
    # sm = proj.factory.simulation_manager(st)
    # sm.explore(find=0x401337, avoid=0x401350)  # TODO: dia chi dung/sai
    # _report(sm, symbolic_bv=flag2, label="buffer")


# =============================================================================
#  MAU C -- HOOK / bo qua ham nhieu bang SimProcedure
# -----------------------------------------------------------------------------
#  Dung khi: co ham lam angr "mac ket" hoac gay path explosion, vi du:
#    - Ham chong debug (ptrace/IsDebuggerPresent) -> hook de luon tra 0.
#    - scanf/printf phuc tap -> hook de kiem soat du lieu.
#    - Ham bam/hash nang -> thay the bang ham don gian.
#    - Ham in output -> bo qua de chay nhanh hon.
# =============================================================================

class SkipProcedure(angr.SimProcedure):
    """SimProcedure "rong": khong lam gi, tra ve 0. Dung de bo qua 1 ham."""

    def run(self, *args):
        return 0


class ReturnValueProcedure(angr.SimProcedure):
    """Hook tra ve mot gia tri co dinh (dat qua .retval).
    Vi du de ep ham chong-debug tra ve "khong co debugger".
    """

    def run(self, *args):
        return self.retval


def solve_mode_C():
    print("[*] MODE C: hook/bo qua ham nhieu + find/avoid")

    # use_sim_procedures=True: angr tu thay cac ham libc pho bien bang
    # SimProcedure co san (nhanh + on dinh hon). Thuong nen bat.
    proj = angr.Project(BINARY, auto_load_libs=False, use_sim_procedures=True)

    # ------------------------------------------------------------------
    #  Vi du cac kieu hook. Bo comment cai ban can.
    # ------------------------------------------------------------------

    # (1) Hook theo DIA CHI ham: bo qua ham chong-debug tai dia chi X.
    # TODO: thay dia chi ham can bo qua.
    # proj.hook(0x401500, SkipProcedure())

    # (2) Hook theo TEN ham (symbol) neu binary con symbol:
    # proj.hook_symbol("anti_debug", SkipProcedure())

    # (3) Hook tra ve gia tri co dinh (vd IsDebuggerPresent -> 0):
    # p = ReturnValueProcedure()
    # p.retval = 0
    # proj.hook_symbol("IsDebuggerPresent", p)

    # (4) Hook 1 lenh/doan ngan bang ham inline, va nhay qua 'length' byte:
    # @proj.hook(0x401234, length=5)   # length = so byte lenh goc bi thay the
    # def patch_jump(state):
    #     state.regs.eax = 1           # vi du: ep ket qua kiem tra = dung

    # Sau khi hook xong, chay nhu Mau A.
    flag, flag_bytes = make_symbolic_bytes("flag", INPUT_LEN)
    state = proj.factory.entry_state(
        stdin=flag,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    constrain_printable(state, flag_bytes)

    simgr = proj.factory.simulation_manager(state)

    # Meo chong het RAM khi avoid nhieu: xoa stash 'avoid' sau moi buoc.
    simgr.explore(
        find=lambda s: b"Correct" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong" in s.posix.dumps(1),
        step_func=lambda lsm: lsm.drop(stash="avoid"),
    )

    _report(simgr)


# =============================================================================
#  IN KET QUA
# =============================================================================

def _report(simgr, symbolic_bv=None, label="stdin"):
    """In ket qua tim duoc.

    - Neu input di qua stdin: dung state.posix.dumps(0) de lay noi dung stdin
      ma solver da suy ra.
    - Neu input la buffer/argv: truyen 'symbolic_bv' de eval truc tiep BitVector.
    """
    if simgr.found:
        found = simgr.found[0]

        if symbolic_bv is None:
            # Lay lai stdin (fd=0) da bi rang buoc de dat trang thai "Correct".
            data = found.posix.dumps(0)
            print(f"[+] TIM THAY! Input ({label}) =")
            print("    raw   :", data)
            try:
                print("    ascii :", data.decode("latin-1"))
            except Exception:
                pass
        else:
            # eval BitVector symbolic thanh bytes cu the.
            data = found.solver.eval(symbolic_bv, cast_to=bytes)
            print(f"[+] TIM THAY! Input ({label}) =")
            print("    raw   :", data)
            try:
                print("    ascii :", data.decode("latin-1"))
            except Exception:
                pass
    else:
        print("[-] KHONG tim thay duong di thoa man.")
        print("    Goi y: kiem tra lai find/avoid, INPUT_LEN, rang buoc ky tu,")
        print("    hoac dung MODE C de hook bot ham nhieu.")
        # Debug them: xem con bao nhieu state va o dau.
        print("    stashes:", {k: len(v) for k, v in simgr.stashes.items() if v})


# =============================================================================
#  CHUONG TRINH CHINH
# =============================================================================

def main():
    dispatch = {"A": solve_mode_A, "B": solve_mode_B, "C": solve_mode_C}
    fn = dispatch.get(MODE.upper())
    if fn is None:
        print(f"[!] MODE khong hop le: {MODE!r}. Chon 'A', 'B' hoac 'C'.")
        sys.exit(1)
    fn()


if __name__ == "__main__":
    main()
