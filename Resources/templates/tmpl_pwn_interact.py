#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  TEMPLATE TUONG TAC / BRUTE BINARY  -  Cyber SEA Game 2026 (Reverse / Pwn)
# -----------------------------------------------------------------------------
#  Muc dich: TU DONG HOA viec "noi chuyen" voi mot binary kiem tra input
#            (kieu keygen / check password / check flag). Dung cho REVERSE,
#            khong chi pwn.
#
#  Co 3 ky thuat brute "tung ky tu" theo tin hieu phan hoi:
#    (A) THEO NOI DUNG  : output bao "dung/sai" (Correct/Wrong, OK/Nope...).
#    (B) THEO DO DAI    : moi ky tu dung lam do dai output doi (vd in them 1 dong).
#    (C) THEO THOI GIAN : moi ky tu dung lam chuong trinh xu ly lau hon
#                         (timing side-channel, vd so sanh tung byte roi break).
#
#  CACH CHAY:
#    python3 tmpl_pwn_interact.py            # LOCAL process ./target
#    python3 tmpl_pwn_interact.py REMOTE     # ket noi HOST:PORT
#    python3 tmpl_pwn_interact.py DEBUG      # in het goi/nhan (log_level=debug)
#
#  AN TOAN: KHONG chay binary la khong tin tuong. Day la KHUNG mau.
# =============================================================================

from pwn import *   # noqa: F401,F403
import sys, time, string

# =============================================================================
#  (1) CAU HINH
# =============================================================================
BINARY = "./target"         # TODO: binary can reverse
HOST   = "127.0.0.1"        # TODO
PORT   = 1337               # TODO

ARGS       = [a.upper() for a in sys.argv[1:]]
USE_REMOTE = "REMOTE" in ARGS
DEBUG      = "DEBUG" in ARGS

context.clear()
context.log_level = "debug" if DEBUG else "warning"   # warning: do brute se in rat nhieu
context.arch = "amd64"      # TODO: 'amd64' hoac 'i386'

# Bang ky tu thu, sap theo thu tu hay gap trong flag/CTF (chinh neu can).
CHARSET = string.ascii_letters + string.digits + "_{}!?@#$%^&*()-+=./"
# TODO: neu flag co dinh dang, thu gon charset lai cho nhanh (vd chi hex: "0123456789abcdef")

FLAG_PREFIX = "CSG{"        # TODO: tien to flag da biet (de "" neu chua biet)
MAX_LEN     = 50            # TODO: do dai toi da du doan cua flag


# =============================================================================
#  (2) HAM KET NOI  -  tao tube moi moi lan thu (vi nhieu chall reset moi lan nhap sai)
# =============================================================================
def start():
    if USE_REMOTE:
        return remote(HOST, PORT)
    return process([BINARY])


# =============================================================================
#  (3) MOT LAN THU  -  gui 1 chuoi ung vien, tra ve (output, thoi_gian)
# -----------------------------------------------------------------------------
#  Day la "trung tam" can sua theo giao dien cua binary:
#    - sua prompt trong sendlineafter cho khop ("Enter password: ", "> ", ...)
#    - sua cach doc phan hoi (recvline / recvall / recvuntil)
# =============================================================================
def attempt(guess):
    """Gui 'guess' cho binary, tra ve (output_bytes, elapsed_seconds)."""
    io = start()
    t0 = time.perf_counter()
    try:
        # io.sendlineafter(b"password: ", guess.encode())   # TODO: khop prompt thuc te
        io.sendline(guess.encode())                         # TODO: hoac gui thang neu khong co prompt
        # Doc phan hoi. Chon 1 trong cac cach sau cho phu hop:
        try:
            out = io.recvall(timeout=2)        # doc toi khi dong ket noi (tot cho chall thoat sau 1 lan)
        except EOFError:
            out = b""
        # out = io.recvline(timeout=2)         # neu chi can 1 dong phan hoi
        # out = io.recvuntil(b"\n", timeout=2) # doc den newline
    finally:
        elapsed = time.perf_counter() - t0
        io.close()
    return out, elapsed


# =============================================================================
#  (A) BRUTE THEO NOI DUNG OUTPUT  -  pho bien nhat
# -----------------------------------------------------------------------------
#  Y tuong: binary bao "dung tung phan" (vd flag check tung ky tu, in "Correct"
#  khi phan da nhap la tien to dung). Ta thu tung ky tu, giu lai ky tu nao lam
#  output xuat hien dau hieu "dung hon".
# =============================================================================
def is_good(out):
    """Tra ve True neu output cho thay ung vien 'dung (tien to)'. SUA theo bai."""
    # TODO: thay dieu kien nay bang dau hieu thuc te cua binary.
    #   - neu dung -> xuat hien chuoi: return b"Correct" in out
    #   - neu sai  -> xuat hien chuoi: return b"Wrong" not in out
    return b"Correct" in out or b"Access granted" in out

def brute_by_content():
    known = FLAG_PREFIX
    log.warning("[A] Brute theo noi dung, bat dau tu: %r", known)
    for _ in range(len(known), MAX_LEN):
        found = False
        for ch in CHARSET:
            guess = known + ch
            out, _t = attempt(guess)
            if is_good(out):
                known += ch
                found = True
                log.warning("  -> %r", known)
                if known.endswith("}"):     # da du flag
                    return known
                break
        if not found:
            log.warning("Khong tien them duoc o vi tri %d. Dung lai.", len(known))
            break
    return known


# =============================================================================
#  (B) BRUTE THEO DO DAI OUTPUT  -  khi output thay doi kich thuoc theo so byte dung
# -----------------------------------------------------------------------------
#  Y tuong: moi ky tu dung lam chuong trinh in them (hoac bot) -> len(out) doi.
#  Ta chon ky tu lam len(out) KHAC voi "chuan sai" (baseline).
# =============================================================================
def brute_by_length():
    known = FLAG_PREFIX
    log.warning("[B] Brute theo do dai output")
    for _ in range(len(known), MAX_LEN):
        best_ch, best_len = None, -1
        for ch in CHARSET:
            out, _t = attempt(known + ch)
            if len(out) > best_len:         # TODO: co the la '<' tuy chieu doi do dai
                best_len, best_ch = len(out), ch
        if best_ch is None:
            break
        known += best_ch
        log.warning("  -> %r (len=%d)", known, best_len)
        if known.endswith("}"):
            return known
    return known


# =============================================================================
#  (C) BRUTE THEO THOI GIAN (timing side-channel)
# -----------------------------------------------------------------------------
#  Y tuong: so sanh chuoi kieu "sai la break ngay" -> ky tu cang dung, ham chay
#  cang lau. Chon ky tu co THOI GIAN LON NHAT (lap nhieu lan lay trung binh de
#  giam nhieu). Thuong can them do tre nhan tao trong binary moi ro ret.
# =============================================================================
def brute_by_timing(rounds=5):
    known = FLAG_PREFIX
    log.warning("[C] Brute theo thoi gian (rounds=%d)", rounds)
    for _ in range(len(known), MAX_LEN):
        best_ch, best_t = None, -1.0
        for ch in CHARSET:
            samples = []
            for _ in range(rounds):
                _out, t = attempt(known + ch)
                samples.append(t)
            samples.sort()
            med = samples[len(samples) // 2]    # trung vi -> chong nhieu tot hon trung binh
            if med > best_t:
                best_t, best_ch = med, ch
        if best_ch is None:
            break
        known += best_ch
        log.warning("  -> %r (t=%.4fs)", known, best_t)
        if known.endswith("}"):
            return known
    return known


# =============================================================================
#  (4) MAIN  -  chon ky thuat phu hop
# =============================================================================
def main():
    # Chon 1 trong cac che do (bo comment che do can dung):
    flag = brute_by_content()       # (A) thuong dung nhat
    # flag = brute_by_length()      # (B)
    # flag = brute_by_timing()      # (C)

    log.warning("KET QUA: %s", flag)


if __name__ == "__main__":
    main()
