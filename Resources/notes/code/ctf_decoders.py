#!/usr/bin/env python3
"""
ctf_decoders.py - bo giai ma "dung ngay" cho cac thuat toan hay gap trong Reverse CTF.

* Thuan Python 3 (khong can thu vien ngoai), tru khi ghi chu khac.
* Moi ham duoc kiem chung bang output cua binary that (xem test_decoders.py).
* Quy uoc: bytes vao -> bytes ra. Mat ma khoi dung ECB, little-endian (nhu code C x86).
"""
import base64
import hashlib
import itertools
import string
import zlib

M32 = 0xFFFFFFFF


# ----------------------------------------------------------------------------
# 1. ENCODE
# ----------------------------------------------------------------------------
B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
B58_BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b64_decode(s, alphabet=B64_STD):
    """Base64 voi bang chu cai tuy y (dang custom alphabet rat hay gap)."""
    s = s.rstrip("=")
    acc = bits = 0
    out = bytearray()
    for ch in s:
        acc = (acc << 6) | alphabet.index(ch)
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)


def b64_encode(b, alphabet=B64_STD):
    std = base64.b64encode(b).decode()
    return std.translate(str.maketrans(B64_STD, alphabet))


def b32_decode(s):
    return base64.b32decode(s)


def b58_decode(s, alphabet=B58_BTC):
    num = 0
    for ch in s:
        num = num * 58 + alphabet.index(ch)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    lead = len(s) - len(s.lstrip(alphabet[0]))
    return b"\x00" * lead + raw


def a85_decode(s):
    return base64.a85decode(s)


# ----------------------------------------------------------------------------
# 2. PHEP TOAN DON GIAN
# ----------------------------------------------------------------------------
def rol8(x, k): return ((x << k) | (x >> (8 - k))) & 0xFF
def ror8(x, k): return ((x >> k) | (x << (8 - k))) & 0xFF
def rol32(x, k): return ((x << k) | (x >> (32 - k))) & M32
def ror32(x, k): return ((x >> k) | (x << (32 - k))) & M32
def rol64(x, k): return ((x << k) | (x >> (64 - k))) & 0xFFFFFFFFFFFFFFFF
def ror64(x, k): return ((x >> k) | (x << (64 - k))) & 0xFFFFFFFFFFFFFFFF


def rot13(s):
    import codecs
    return codecs.decode(s, "rot13")


def xor_repeat(data, key):
    """XOR voi key lap lai (key 1 byte = XOR don)."""
    if isinstance(key, int):
        key = bytes([key])
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def xor_known_plaintext(cipher, crib=b"flag{"):
    """Tim key XOR bang doan plaintext da biet (crib). Tra ve key (toi da len(crib) byte)."""
    return bytes(c ^ p for c, p in zip(cipher, crib))


def xor_single_bruteforce(cipher, must_contain=b"flag"):
    """Thu 256 key 1 byte, tra ve cac ung vien chua `must_contain`."""
    return [(k, xor_repeat(cipher, k)) for k in range(256) if must_contain in xor_repeat(cipher, k)]


def op_add(data, k): return bytes((c + k) & 0xFF for c in data)
def op_sub(data, k): return bytes((c - k) & 0xFF for c in data)
def op_not(data): return bytes(~c & 0xFF for c in data)
def op_rol8(data, k): return bytes(rol8(c, k) for c in data)
def op_ror8(data, k): return bytes(ror8(c, k) for c in data)


def mix_chain_encrypt(data):
    """c=b^(0x5A+i); c=rol3(c); c+=0x13; c^=prev; prev=c (giong ham mix_chain trong algos.c)."""
    out, prev = bytearray(), 0x42
    for i, b in enumerate(data):
        c = b ^ ((0x5A + i) & 0xFF)
        c = rol8(c, 3)
        c = (c + 0x13) & 0xFF
        c ^= prev
        prev = c
        out.append(c)
    return bytes(out)


def mix_chain_decrypt(data):
    """Dao nguoc tung buoc: xor prev -> tru 0x13 -> ror3 -> xor (0x5A+i). Day la cach dao ham 'chain'."""
    out, prev = bytearray(), 0x42
    for i, c in enumerate(data):
        t = c ^ prev
        prev = c
        t = (t - 0x13) & 0xFF
        t = ror8(t, 3)
        out.append(t ^ ((0x5A + i) & 0xFF))
    return bytes(out)


# ----------------------------------------------------------------------------
# 3. MAT MA DOI XUNG
# ----------------------------------------------------------------------------
def rc4(key, data):
    """RC4 (ma hoa va giai ma giong het nhau)."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


DELTA = 0x9E3779B9


def _u32(b): return [int.from_bytes(b[i:i + 4], "little") for i in range(0, len(b), 4)]
def _p32(v): return b"".join(x.to_bytes(4, "little") for x in v)


def tea_decrypt_block(v0, v1, k, rounds=32):
    s = (DELTA * rounds) & M32
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & M32
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & M32
        s = (s - DELTA) & M32
    return v0, v1


def tea_encrypt_block(v0, v1, k, rounds=32):
    s = 0
    for _ in range(rounds):
        s = (s + DELTA) & M32
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & M32
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & M32
    return v0, v1


def tea_decrypt(data, key4):
    w, out = _u32(data), []
    for i in range(0, len(w), 2):
        out += tea_decrypt_block(w[i], w[i + 1], key4)
    return _p32(out)


def xtea_decrypt_block(v0, v1, k, rounds=32):
    s = (DELTA * rounds) & M32
    for _ in range(rounds):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & M32
        s = (s - DELTA) & M32
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & M32
    return v0, v1


def xtea_decrypt(data, key4):
    w, out = _u32(data), []
    for i in range(0, len(w), 2):
        out += xtea_decrypt_block(w[i], w[i + 1], key4)
    return _p32(out)


def xxtea_decrypt(data, key4):
    v = _u32(data)
    n = len(v)
    rounds = 6 + 52 // n
    s = (rounds * DELTA) & M32
    y = v[0]

    def mx(y, z, s, p, e):
        return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (key4[(p & 3) ^ e] ^ z))) & M32

    for _ in range(rounds):
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - mx(y, z, s, p, e)) & M32
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - mx(y, z, s, 0, e)) & M32
        y = v[0]
        s = (s - DELTA) & M32
    return _p32(v)


# ---- AES-128 (thuan Python, tu sinh S-box) ----
def _aes_tables():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        q &= 0xFF
        x = q ^ rol8(q, 1) ^ rol8(q, 2) ^ rol8(q, 3) ^ rol8(q, 4)
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


AES_SBOX, AES_INV_SBOX = _aes_tables()


def _xt(x): return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF


def _gm(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = _xt(a)
        b >>= 1
    return p


def aes128_expand_key(key):
    rk = bytearray(key)
    rc = 1
    for i in range(16, 176, 4):
        t = list(rk[i - 4:i])
        if i % 16 == 0:
            t = [AES_SBOX[t[1]] ^ rc, AES_SBOX[t[2]], AES_SBOX[t[3]], AES_SBOX[t[0]]]
            rc = _xt(rc)
        rk += bytes(rk[i - 16 + j] ^ t[j] for j in range(4))
    return bytes(rk)


def aes128_decrypt_block(rk, blk):
    s = [blk[i] ^ rk[160 + i] for i in range(16)]
    for r in range(9, -1, -1):
        t = [0] * 16
        for c in range(4):                       # InvShiftRows + InvSubBytes
            for rr in range(4):
                t[c * 4 + rr] = AES_INV_SBOX[s[((c - rr) & 3) * 4 + rr]]
        t = [t[i] ^ rk[r * 16 + i] for i in range(16)]   # AddRoundKey
        if r > 0:                                # InvMixColumns
            s = [0] * 16
            for c in range(4):
                a0, a1, a2, a3 = t[c * 4:c * 4 + 4]
                s[c * 4 + 0] = _gm(a0, 14) ^ _gm(a1, 11) ^ _gm(a2, 13) ^ _gm(a3, 9)
                s[c * 4 + 1] = _gm(a0, 9) ^ _gm(a1, 14) ^ _gm(a2, 11) ^ _gm(a3, 13)
                s[c * 4 + 2] = _gm(a0, 13) ^ _gm(a1, 9) ^ _gm(a2, 14) ^ _gm(a3, 11)
                s[c * 4 + 3] = _gm(a0, 11) ^ _gm(a1, 13) ^ _gm(a2, 9) ^ _gm(a3, 14)
        else:
            s = t
    return bytes(s)


def aes128_ecb_decrypt(key, data):
    rk = aes128_expand_key(key)
    return b"".join(aes128_decrypt_block(rk, data[i:i + 16]) for i in range(0, len(data), 16))


# ---- ChaCha20 / Salsa20 (XOR keystream => ma hoa = giai ma) ----
def _chacha_block(key, counter, nonce):
    k = _u32(key)
    n = _u32(nonce)
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574] + k + [counter] + n
    x = list(s)

    def qr(a, b, c, d):
        x[a] = (x[a] + x[b]) & M32; x[d] = rol32(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & M32; x[b] = rol32(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & M32; x[d] = rol32(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & M32; x[b] = rol32(x[b] ^ x[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return _p32([(x[i] + s[i]) & M32 for i in range(16)])


def chacha20_xor(key, nonce12, data, counter=0):
    out = bytearray()
    for off in range(0, len(data), 64):
        ks = _chacha_block(key, counter + off // 64, nonce12)
        out += bytes(a ^ b for a, b in zip(data[off:off + 64], ks))
    return bytes(out)


def _salsa_block(key, nonce8, counter):
    k = _u32(key)
    n = _u32(nonce8)
    s = [0x61707865, k[0], k[1], k[2], k[3], 0x3320646E, n[0], n[1],
         counter & M32, counter >> 32, 0x79622D32, k[4], k[5], k[6], k[7], 0x6B206574]
    x = list(s)
    for _ in range(10):
        x[4] ^= rol32((x[0] + x[12]) & M32, 7);  x[8] ^= rol32((x[4] + x[0]) & M32, 9)
        x[12] ^= rol32((x[8] + x[4]) & M32, 13); x[0] ^= rol32((x[12] + x[8]) & M32, 18)
        x[9] ^= rol32((x[5] + x[1]) & M32, 7);   x[13] ^= rol32((x[9] + x[5]) & M32, 9)
        x[1] ^= rol32((x[13] + x[9]) & M32, 13); x[5] ^= rol32((x[1] + x[13]) & M32, 18)
        x[14] ^= rol32((x[10] + x[6]) & M32, 7); x[2] ^= rol32((x[14] + x[10]) & M32, 9)
        x[6] ^= rol32((x[2] + x[14]) & M32, 13); x[10] ^= rol32((x[6] + x[2]) & M32, 18)
        x[3] ^= rol32((x[15] + x[11]) & M32, 7); x[7] ^= rol32((x[3] + x[15]) & M32, 9)
        x[11] ^= rol32((x[7] + x[3]) & M32, 13); x[15] ^= rol32((x[11] + x[7]) & M32, 18)
        x[1] ^= rol32((x[0] + x[3]) & M32, 7);   x[2] ^= rol32((x[1] + x[0]) & M32, 9)
        x[3] ^= rol32((x[2] + x[1]) & M32, 13);  x[0] ^= rol32((x[3] + x[2]) & M32, 18)
        x[6] ^= rol32((x[5] + x[4]) & M32, 7);   x[7] ^= rol32((x[6] + x[5]) & M32, 9)
        x[4] ^= rol32((x[7] + x[6]) & M32, 13);  x[5] ^= rol32((x[4] + x[7]) & M32, 18)
        x[11] ^= rol32((x[10] + x[9]) & M32, 7); x[8] ^= rol32((x[11] + x[10]) & M32, 9)
        x[9] ^= rol32((x[8] + x[11]) & M32, 13); x[10] ^= rol32((x[9] + x[8]) & M32, 18)
        x[12] ^= rol32((x[15] + x[14]) & M32, 7); x[13] ^= rol32((x[12] + x[15]) & M32, 9)
        x[14] ^= rol32((x[13] + x[12]) & M32, 13); x[15] ^= rol32((x[14] + x[13]) & M32, 18)
    return _p32([(x[i] + s[i]) & M32 for i in range(16)])


def salsa20_xor(key, nonce8, data, counter=0):
    out = bytearray()
    for off in range(0, len(data), 64):
        ks = _salsa_block(key, nonce8, counter + off // 64)
        out += bytes(a ^ b for a, b in zip(data[off:off + 64], ks))
    return bytes(out)


# ----------------------------------------------------------------------------
# 4. HASH (khong dao nguoc duoc -> brute force / tra bang / forge)
# ----------------------------------------------------------------------------
def hash_bruteforce(target_hex, algo="md5", charset=string.ascii_lowercase + string.digits,
                    max_len=5, prefix=b"", suffix=b""):
    """Thu moi chuoi do dai 1..max_len. VD hash_bruteforce('...', 'sha256', max_len=4)."""
    target = bytes.fromhex(target_hex)
    for n in range(1, max_len + 1):
        for tup in itertools.product(charset, repeat=n):
            cand = prefix + "".join(tup).encode() + suffix
            if hashlib.new(algo, cand).digest() == target:
                return cand
    return None


def hash_wordlist(target_hex, words, algo="md5"):
    target = bytes.fromhex(target_hex)
    for w in words:
        w = w.encode() if isinstance(w, str) else w
        if hashlib.new(algo, w).digest() == target:
            return w
    return None


# CRC32: tuyen tinh -> co the "forge" 4 byte cuoi de dat CRC mong muon
def crc32(data, init=0):
    return zlib.crc32(data, init) & M32


def crc32_forge(prefix, target):
    """Tra ve 4 byte `tail` sao cho crc32(prefix + tail) == target (hoac None).

    CRC32 la anh xa affine tren GF(2): crc(prefix+tail) = L(tail) xor const, voi L tuyen tinh va
    khong suy bien tren 4 byte -> giai he 32 an 32 phuong trinh bang khu Gauss.
    """
    base = crc32(prefix + b"\x00\x00\x00\x00")
    cols = [crc32(prefix + (1 << b).to_bytes(4, "little")) ^ base for b in range(32)]
    basis = []                                   # (vector, to hop bit goc tao ra vector do)
    for b, v in enumerate(cols):
        combo = 1 << b
        for bv, bc in basis:
            if v ^ bv < v:                       # bit cao nhat cua bv dang bat trong v
                v ^= bv
                combo ^= bc
        if v:
            basis.append((v, combo))
            basis.sort(reverse=True)
    v, combo = target ^ base, 0
    for bv, bc in basis:
        if v ^ bv < v:
            v ^= bv
            combo ^= bc
    return combo.to_bytes(4, "little") if v == 0 else None

def fnv1a_32(data):
    h = 2166136261
    for c in data:
        h = ((h ^ c) * 16777619) & M32
    return h


def fnv1a_unstep(h, c):
    """Quay lui 1 buoc FNV-1a khi biet ky tu c vua nap (dung cho meet-in-the-middle)."""
    return ((h * pow(16777619, -1, 1 << 32)) & M32) ^ c


def djb2_32(data):
    h = 5381
    for c in data:
        h = (h * 33 + c) & M32
    return h


def djb2_unstep(h, c):
    return ((h - c) * pow(33, -1, 1 << 32)) & M32


def adler32(data):
    return zlib.adler32(data) & M32

