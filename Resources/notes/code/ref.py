#!/usr/bin/env python3
# Tham chieu doc lap cho algos.c: in ra dung cung dinh dang. Chay: python ref.py [input]
import sys, base64, hashlib, zlib, codecs

M = 0xFFFFFFFF
text = sys.argv[1] if len(sys.argv) > 1 else "Hello, CyberSeaGame!"
data = text.encode()[:200]
n = len(data)

def hx(b): return bytes(b).hex()
def line(tag, b): print("%s: %s" % (tag, hx(b)))

def b58(b):
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    z = 0
    while z < len(b) and b[z] == 0: z += 1
    num = int.from_bytes(b, "big")
    out = ""
    while num:
        num, r = divmod(num, 58)
        out = alpha[r] + out
    return "1" * z + out

def pad(b, bs):
    m = (len(b) + bs - 1) // bs * bs or bs
    return b + b"\0" * (m - len(b))

def u32s(b): return [int.from_bytes(b[i:i+4], "little") for i in range(0, len(b), 4)]
def p32s(v): return b"".join(x.to_bytes(4, "little") for x in v)

tk = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210]
D = 0x9E3779B9

def tea_enc(v0, v1):
    s = 0
    for _ in range(32):
        s = (s + D) & M
        v0 = (v0 + ((((v1 << 4) + tk[0]) ^ (v1 + s) ^ ((v1 >> 5) + tk[1])))) & M
        v1 = (v1 + ((((v0 << 4) + tk[2]) ^ (v0 + s) ^ ((v0 >> 5) + tk[3])))) & M
    return v0, v1
def tea_dec(v0, v1):
    s = 0xC6EF3720
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) + tk[2]) ^ (v0 + s) ^ ((v0 >> 5) + tk[3])))) & M
        v0 = (v0 - ((((v1 << 4) + tk[0]) ^ (v1 + s) ^ ((v1 >> 5) + tk[1])))) & M
        s = (s - D) & M
    return v0, v1
def xtea_enc(v0, v1):
    s = 0
    for _ in range(32):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + tk[s & 3]))) & M
        s = (s + D) & M
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + tk[(s >> 11) & 3]))) & M
    return v0, v1
def xtea_dec(v0, v1):
    s = (D * 32) & M
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + tk[(s >> 11) & 3]))) & M
        s = (s - D) & M
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + tk[s & 3]))) & M
    return v0, v1

def xxtea(v, enc=True):
    v = list(v); nn = len(v)
    def mx(y, z, s, p, e):
        return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (tk[(p & 3) ^ e] ^ z))) & M
    rounds = 6 + 52 // nn
    if enc:
        s = 0; z = v[nn - 1]
        for _ in range(rounds):
            s = (s + D) & M; e = (s >> 2) & 3
            for p in range(nn - 1):
                y = v[p + 1]; v[p] = (v[p] + mx(y, z, s, p, e)) & M; z = v[p]
            y = v[0]; v[nn - 1] = (v[nn - 1] + mx(y, z, s, nn - 1, e)) & M; z = v[nn - 1]
    else:
        s = (rounds * D) & M; y = v[0]
        for _ in range(rounds):
            e = (s >> 2) & 3
            for p in range(nn - 1, 0, -1):
                z = v[p - 1]; v[p] = (v[p] - mx(y, z, s, p, e)) & M; y = v[p]
            z = v[nn - 1]; v[0] = (v[0] - mx(y, z, s, 0, e)) & M; y = v[0]
            s = (s - D) & M
    return v

# ---------- encode ----------
print("input: %s" % text[:200])
print("base64: %s" % base64.b64encode(data).decode())
print("base64_dec: %s" % base64.b64decode(base64.b64encode(data)).decode())
print("base32: %s" % base64.b32encode(data).decode())
print("base58: %s" % b58(data))
print("ascii85: %s" % base64.a85encode(data).decode())
print("hex: %s" % data.hex())

# ---------- simple ops ----------
print("rot13: %s" % hx(codecs.encode(text[:200], "rot13").encode()))
line("xor_single_5a", [c ^ 0x5A for c in data])
line("xor_repeat_KEY", [c ^ b"KEY"[i % 3] for i, c in enumerate(data)])
line("add_7", [(c + 7) & 255 for c in data])
line("sub_7", [(c - 7) & 255 for c in data])
line("not", [~c & 255 for c in data])
line("rol8_3", [((c << 3) | (c >> 5)) & 255 for c in data])
line("ror8_3", [((c >> 3) | (c << 5)) & 255 for c in data])
x = 0x12345678
print("rol32: %08x ror32: %08x" % (((x << 8) | (x >> 24)) & M, ((x >> 8) | (x << 24)) & M))
line("reverse", data[::-1])
out = []; prev = 0x42
for i, c in enumerate(data):
    c ^= (0x5A + i) & 255
    c = ((c << 3) | (c >> 5)) & 255
    c = (c + 0x13) & 255
    c ^= prev; prev = c; out.append(c)
line("mix_chain", out)

# ---------- symmetric ----------
from Crypto.Cipher import ARC4, AES, ChaCha20, Salsa20
line("rc4_CyberSea", ARC4.new(b"CyberSea").encrypt(data))

pt = pad(data, 8)
w = u32s(pt); ct = []; ok = True
for i in range(0, len(w), 2):
    ct += list(tea_enc(w[i], w[i + 1]))
    ok &= tea_dec(ct[-2], ct[-1]) == (w[i], w[i + 1])
line("tea_ecb", p32s(ct)); print("tea_dec_ok: %d" % ok)
ct = []; ok = True
for i in range(0, len(w), 2):
    ct += list(xtea_enc(w[i], w[i + 1]))
    ok &= xtea_dec(ct[-2], ct[-1]) == (w[i], w[i + 1])
line("xtea_ecb", p32s(ct)); print("xtea_dec_ok: %d" % ok)
c = xxtea(w, True)
line("xxtea", p32s(c)); print("xxtea_dec_ok: %d" % (xxtea(c, False) == w))

pt = pad(data, 16)
line("aes128_ecb", AES.new(b"0123456789abcdef", AES.MODE_ECB).encrypt(pt)); print("aes_dec_ok: 1")

key = bytes(range(32))
line("chacha20", ChaCha20.new(key=key, nonce=bytes(range(12))).encrypt(data))
line("salsa20", Salsa20.new(key=key, nonce=bytes(range(8))).encrypt(data))

# ---------- hash ----------
line("md5", hashlib.md5(data).digest())
line("sha1", hashlib.sha1(data).digest())
line("sha256", hashlib.sha256(data).digest())
line("sha512", hashlib.sha512(data).digest())
print("crc32_table: %08x" % (zlib.crc32(data) & M))
print("crc32_bitwise: %08x" % (zlib.crc32(data) & M))
print("adler32: %08x" % (zlib.adler32(data) & M))
h = 2166136261
for c in data:
    h = ((h ^ c) * 16777619) & M
print("fnv1a: %08x" % h)
h = 5381
for c in data:
    h = (h * 33 + c) & M
print("djb2: %08x" % h)
