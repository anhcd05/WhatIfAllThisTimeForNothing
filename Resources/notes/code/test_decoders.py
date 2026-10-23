#!/usr/bin/env python3
"""
test_decoders.py - kiem chung ctf_decoders.py bang output CUA BINARY THAT (algos.c bien dich boi gcc/mingw/MSVC).
Chay:  python test_decoders.py [algos_ground_truth.txt]
Moi dong "ten: gia tri" trong file la ket qua binary in ra cho input "Hello, CyberSeaGame!".
"""
import sys
import ctf_decoders as d

PT = b"Hello, CyberSeaGame!"
path = sys.argv[1] if len(sys.argv) > 1 else "algos_ground_truth.txt"
gt = {}
for line in open(path, encoding="utf-8"):
    if ": " in line:
        k, v = line.rstrip("\n").split(": ", 1)
        gt.setdefault(k, v)

TK = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210]
results = []


def check(name, got, want=PT):
    ok = got == want
    results.append(ok)
    print("%-22s %s" % (name, "PASS" if ok else "FAIL  got=%r" % (got,)))


def hx(tag): return bytes.fromhex(gt[tag])
def zpad(b): return b.rstrip(b"\x00")


# ---- encode ----
check("base64", d.b64_decode(gt["base64"]))
custom = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
check("base64 custom alphabet", d.b64_decode(d.b64_encode(PT, custom), custom))
check("base32", d.b32_decode(gt["base32"]))
check("base58", d.b58_decode(gt["base58"]))
check("ascii85", d.a85_decode(gt["ascii85"]))
check("hex", bytes.fromhex(gt["hex"]))

# ---- phep toan don gian ----
check("rot13", d.rot13(hx("rot13").decode()).encode())
check("xor_single_5a", d.xor_repeat(hx("xor_single_5a"), 0x5A))
check("xor_repeat_KEY", d.xor_repeat(hx("xor_repeat_KEY"), b"KEY"))
check("xor known-plaintext key", d.xor_known_plaintext(hx("xor_repeat_KEY"), b"Hel")[:3], b"KEY")
check("xor single bruteforce", d.xor_single_bruteforce(hx("xor_single_5a"), b"Hello")[0][1])
check("add_7", d.op_sub(hx("add_7"), 7))
check("sub_7", d.op_add(hx("sub_7"), 7))
check("not", d.op_not(hx("not")))
check("rol8_3", d.op_ror8(hx("rol8_3"), 3))
check("ror8_3", d.op_rol8(hx("ror8_3"), 3))
check("reverse", hx("reverse")[::-1])
check("mix_chain", d.mix_chain_decrypt(hx("mix_chain")))
check("mix_chain roundtrip", d.mix_chain_decrypt(d.mix_chain_encrypt(PT)))
a, b = gt["rol32"].split(" ror32: ")
check("rol32/ror32", (d.rol32(0x12345678, 8), d.ror32(0x12345678, 8)), (int(a, 16), int(b, 16)))

# ---- symmetric ----
check("rc4", d.rc4(b"CyberSea", hx("rc4_CyberSea")))
check("tea", zpad(d.tea_decrypt(hx("tea_ecb"), TK)))
check("xtea", zpad(d.xtea_decrypt(hx("xtea_ecb"), TK)))
check("xxtea", zpad(d.xxtea_decrypt(hx("xxtea"), TK)))
check("aes128-ecb", zpad(d.aes128_ecb_decrypt(b"0123456789abcdef", hx("aes128_ecb"))))
check("chacha20", d.chacha20_xor(bytes(range(32)), bytes(range(12)), hx("chacha20")))
check("salsa20", d.salsa20_xor(bytes(range(32)), bytes(range(8)), hx("salsa20")))

# ---- hash (khong dao nguoc -> tra bang / brute force) ----
words = ["admin", "password", "abc", PT.decode()]
for algo in ("md5", "sha1", "sha256", "sha512"):
    check("%s wordlist" % algo, d.hash_wordlist(gt[algo], words, algo))
check("md5 bruteforce (len<=3)", d.hash_bruteforce(__import__("hashlib").md5(b"abz").hexdigest(), "md5", max_len=3), b"abz")
check("crc32 table==bitwise", int(gt["crc32_table"], 16), int(gt["crc32_bitwise"], 16))
check("crc32 value", d.crc32(PT), int(gt["crc32_table"], 16))
tail = d.crc32_forge(b"Hello, CyberSea", 0xDEADBEEF)
check("crc32 forge 4 byte", d.crc32(b"Hello, CyberSea" + tail), 0xDEADBEEF)
check("adler32", d.adler32(PT), int(gt["adler32"], 16))
check("fnv1a", d.fnv1a_32(PT), int(gt["fnv1a"], 16))
check("fnv1a unstep", d.fnv1a_unstep(d.fnv1a_32(PT), PT[-1]), d.fnv1a_32(PT[:-1]))
check("djb2", d.djb2_32(PT), int(gt["djb2"], 16))
check("djb2 unstep", d.djb2_unstep(d.djb2_32(PT), PT[-1]), d.djb2_32(PT[:-1]))

print("\n%d/%d PASS" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
