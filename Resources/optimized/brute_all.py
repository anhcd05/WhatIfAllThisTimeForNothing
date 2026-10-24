#!/usr/bin/env python3
# =============================================================================
#  brute_all.py — Brute-force hash TỐI ƯU bằng Python (1 file lo MỌI thuật toán).
#
#  Hỗ trợ:
#   - Mọi thuật toán của hashlib: md5, sha1, sha224, sha256, sha384, sha512,
#     sha3_224/256/384/512, blake2b, blake2s, ripemd160, sm3, shake_128/256...
#   - crc32  (qua zlib — checksum, KHÔNG phải hash mật mã)
#   - ntlm   (= MD4 của mật khẩu mã hoá UTF-16LE; MD4 tự cài vì hashlib 3.x bỏ md4)
#
#  Tối ưu: hashlib gọi OpenSSL (C) + multiprocessing chạy hết số nhân + so bytes (memcmp C).
#  (Vẫn chậm hơn bản C; ntlm dùng MD4 thuần Python nên khá chậm — xem ghi chú cuối file.)
#
#  CHẠY:
#     python brute_all.py                   # dùng cấu hình mặc định bên dưới
#     python brute_all.py sha256 <hash>     # đổi thuật toán + hash qua tham số
#     python brute_all.py crc32  c760632c
#     python brute_all.py ntlm   <ntlm_hex>
# =============================================================================
import sys, time, itertools, hashlib, struct
from multiprocessing import Pool, cpu_count

# ----------------------------- CẤU HÌNH -------------------------------------
WANTED_HASH = "0abefe1fb88827bb302fcbc086a416cb7d8f3536ed2150bf5dbefceace8d2335"  # sha256("Dec0d3")
CHARSET     = "ABCDEFabcdef0123456789"
LEN         = 6
ALGO        = "sha256"   # md5,sha1,sha224,sha256,sha384,sha512,sha3_256,blake2b,ripemd160,crc32,ntlm,...
# ----------------------------------------------------------------------------

# Ghi đè nhanh qua dòng lệnh: python brute_all.py <algo> <hash>
if len(sys.argv) >= 2: ALGO = sys.argv[1]
if len(sys.argv) >= 3: WANTED_HASH = sys.argv[2]

CHARSET_B = CHARSET.encode()
TARGET    = bytes.fromhex(WANTED_HASH)


def _md4(message: bytes) -> bytes:
    """MD4 thuần Python (dùng cho NTLM, vì hashlib 3.x không còn md4)."""
    rotl = lambda x, s: ((x << s) | (x >> (32 - s))) & 0xFFFFFFFF
    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    msg = bytearray(message)
    ml = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", ml)
    for off in range(0, len(msg), 64):
        X = struct.unpack("<16I", bytes(msg[off:off + 64]))
        a, b, c, d = A, B, C, D
        F = lambda x, y, z: (x & y) | (~x & z)
        G = lambda x, y, z: (x & y) | (x & z) | (y & z)
        H = lambda x, y, z: x ^ y ^ z
        for i in (0, 4, 8, 12):          # Round 1
            a = rotl((a + F(b, c, d) + X[i])     & 0xFFFFFFFF, 3)
            d = rotl((d + F(a, b, c) + X[i + 1]) & 0xFFFFFFFF, 7)
            c = rotl((c + F(d, a, b) + X[i + 2]) & 0xFFFFFFFF, 11)
            b = rotl((b + F(c, d, a) + X[i + 3]) & 0xFFFFFFFF, 19)
        for i in (0, 1, 2, 3):           # Round 2
            a = rotl((a + G(b, c, d) + X[i]      + 0x5a827999) & 0xFFFFFFFF, 3)
            d = rotl((d + G(a, b, c) + X[i + 4]  + 0x5a827999) & 0xFFFFFFFF, 5)
            c = rotl((c + G(d, a, b) + X[i + 8]  + 0x5a827999) & 0xFFFFFFFF, 9)
            b = rotl((b + G(c, d, a) + X[i + 12] + 0x5a827999) & 0xFFFFFFFF, 13)
        for i in (0, 2, 1, 3):           # Round 3
            a = rotl((a + H(b, c, d) + X[i]      + 0x6ed9eba1) & 0xFFFFFFFF, 3)
            d = rotl((d + H(a, b, c) + X[i + 8]  + 0x6ed9eba1) & 0xFFFFFFFF, 9)
            c = rotl((c + H(d, a, b) + X[i + 4]  + 0x6ed9eba1) & 0xFFFFFFFF, 11)
            b = rotl((b + H(c, d, a) + X[i + 12] + 0x6ed9eba1) & 0xFFFFFFFF, 15)
        A = (A + a) & 0xFFFFFFFF; B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF; D = (D + d) & 0xFFFFFFFF
    return struct.pack("<4I", A, B, C, D)


def make_digest_fn():
    """Trả về hàm: bytes ứng viên -> bytes digest, theo ALGO."""
    a = ALGO.lower()
    if a == "crc32":
        import zlib
        return lambda d: (zlib.crc32(d) & 0xFFFFFFFF).to_bytes(4, "big")
    if a == "ntlm":
        return lambda d: _md4(bytes([x for ch in d for x in (ch, 0)]))  # UTF-16LE rồi MD4
    fn = getattr(hashlib, a, None)
    if fn is not None:
        fn(b"")                      # thử dùng (vd sha256)
        return lambda d: fn(d).digest()
    return lambda d: hashlib.new(a, d).digest()   # vd sm3/ripemd160 qua new()


def worker(first):
    """Thử mọi chuỗi bắt đầu bằng ký tự 'first'."""
    dig = make_digest_fn()
    prefix = bytes([first])
    tgt = TARGET
    for tail in itertools.product(CHARSET_B, repeat=LEN - 1):
        cand = prefix + bytes(tail)
        if dig(cand) == tgt:
            return cand.decode()
    return None


def main():
    try:
        make_digest_fn()(b"")        # kiểm tra thuật toán dùng được
    except Exception as e:
        print(f"[!] Thuat toan '{ALGO}' khong dung duoc: {e}")
        sys.exit(2)

    nproc = cpu_count()
    total = len(CHARSET_B) ** LEN
    print(f"[*] algo={ALGO} LEN={LEN} charset={len(CHARSET_B)}  "
          f"khong gian={total:,}  tien trinh={nproc}")

    t0 = time.time()
    found = None
    with Pool(nproc) as p:
        for res in p.imap_unordered(worker, list(CHARSET_B)):
            if res:
                found = res
                p.terminate()
                break
    dt = time.time() - t0

    print(f"FOUND: {found}" if found else "Khong tim thay.")
    print(f"Thoi gian: {dt:.2f}s  (~{total/1e6:.0f}M to hop, "
          f"{(total/dt/1e6) if dt>0 else 0:.1f} M/s)")


if __name__ == "__main__":
    main()

# -----------------------------------------------------------------------------
# GHI CHÚ:
#  - crc32: 32-bit nên dễ đụng độ — có thể ra MỘT chuỗi cùng CRC, không chắc chuỗi gốc.
#  - ntlm : MD4 thuần Python khá CHẬM. Brute NTLM thật sự nên dùng hashcat -m 1000
#           (NTLM là hash NHANH, hashcat/john trên Kali xử lý rất tốt kể cả không GPU).
# -----------------------------------------------------------------------------
