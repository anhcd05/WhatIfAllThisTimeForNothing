#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tmpl_decrypt.py - Template GIẢI MÃ / DECODE (Reverse / Forensics)
Cyber SEA Game 2026

MỤC ĐÍCH
    Bộ hàm mẫu để giải mã dữ liệu thường gặp trong CTF:
        - XOR: 1 byte + brute 0..255, XOR nhiều byte (key lặp), XOR known-plaintext.
        - RC4 (ARC4).
        - AES: ECB / CBC / CTR (pycryptodome) kèm xử lý IV và padding (unpad).
        - Encoding: base64 / base32 / base16(hex), ROT13 / Caesar brute.
        - Biến đổi byte: đảo byte (reverse), đổi endian theo word.

AN TOÀN
    Template CHỈ thao tác trên DỮ LIỆU/bytes. KHÔNG chạy binary lạ.

CÁCH DÙNG
    Import và gọi hàm, hoặc sửa phần `demo()` / `main()` cho đúng bài của bạn.
        python tmpl_decrypt.py          # chạy self-test (XOR + AES trên dữ liệu tự tạo)

PHỤ THUỘC (chỉ cần cho RC4/AES):
    pip install pycryptodome
"""

import sys
import base64
import binascii
import codecs
import struct

# ---------------------------------------------------------------------------
# PHẦN 1: XOR
# ---------------------------------------------------------------------------

def xor_bytes(data, key):
    """XOR `data` với `key` (lặp lại nếu key ngắn hơn data).

    key : int (1 byte, 0..255) HOẶC bytes (nhiều byte).
    XOR có tính đối xứng: cùng 1 hàm vừa mã hóa vừa giải mã.
    """
    if isinstance(key, int):
        return bytes(b ^ key for b in data)
    if not key:
        return bytes(data)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _printable_ratio(b):
    """Tỉ lệ ký tự ASCII in được (0..1) - dùng chấm điểm kết quả brute."""
    if not b:
        return 0.0
    good = sum(1 for x in b if x in b"\t\r\n" or 32 <= x < 127)
    return good / len(b)


def xor_brute_single(data, min_ratio=0.9, sample=512, show=20):
    """Brute XOR 1 byte: thử cả 256 key, in các key cho ra text in được.

    Trả về list (key, ratio, preview) sắp xếp theo độ "giống text" giảm dần.
    """
    probe = data[:sample]
    out = []
    for key in range(256):
        dec = xor_bytes(probe, key)
        r = _printable_ratio(dec)
        if r >= min_ratio:
            out.append((key, r, dec[:60].decode("latin-1", "replace")))
    out.sort(key=lambda t: t[1], reverse=True)
    for key, r, preview in out[:show]:
        print(f"    key=0x{key:02x} ratio={r:.2f} | {preview!r}")
    return out


def xor_repeating(data, key):
    """XOR với key nhiều byte lặp (repeating-key / Vigenère-XOR).

    key: bytes hoặc str (str sẽ được encode utf-8). Chỉ là alias của xor_bytes.
    """
    if isinstance(key, str):
        key = key.encode()
    return xor_bytes(data, key)


def xor_known_plaintext(cipher, known_plain, known_off=0):
    """Suy ra khóa XOR khi biết 1 đoạn plaintext (known-plaintext attack).

    key = cipher XOR plaintext tại cùng vị trí.
    - Nếu known_plain dài >= chu kỳ key: giải được toàn bộ.
    - Mẹo chọn known_plain: header file (b"\\x89PNG", b"PK\\x03\\x04"),
      tiền tố flag (b"flag{", b"CSG{"), hoặc text cố định đã biết.
    Trả về (key, plaintext_thu_giai_ca_file).
    """
    seg = cipher[known_off:known_off + len(known_plain)]
    key = bytes(c ^ p for c, p in zip(seg, known_plain))
    recovered = xor_bytes(cipher, key)   # thử dùng key này giải cả file
    print(f"    key = {key!r}  (hex {key.hex()})")
    return key, recovered


# ---------------------------------------------------------------------------
# PHẦN 2: RC4 (ARC4)
# ---------------------------------------------------------------------------

def rc4(data, key):
    """RC4 thuần Python (không cần thư viện) - vừa mã hóa vừa giải mã.

    key : bytes hoặc str. RC4 là stream cipher đối xứng.
    Dùng khi không muốn phụ thuộc pycryptodome, hoặc để hiểu thuật toán.
    """
    if isinstance(key, str):
        key = key.encode()
    # KSA - Key Scheduling Algorithm: khởi tạo hoán vị S
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    # PRGA - Pseudo-Random Generation: sinh keystream rồi XOR với data
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xff]
        out.append(byte ^ k)
    return bytes(out)


def rc4_pycrypto(data, key):
    """RC4 bằng pycryptodome (Crypto.Cipher.ARC4) - nhanh hơn với data lớn."""
    try:
        from Crypto.Cipher import ARC4
    except ImportError:
        print("[!] Chua cai pycryptodome -> dung ham rc4() thuan Python thay the.")
        return rc4(data, key)
    if isinstance(key, str):
        key = key.encode()
    return ARC4.new(key).decrypt(data)


# ---------------------------------------------------------------------------
# PHẦN 3: AES (ECB / CBC / CTR) - pycryptodome
# ---------------------------------------------------------------------------
# Nhắc lại:
#   - Key phải dài 16 / 24 / 32 byte (AES-128/192/256).
#   - ECB:  không IV. Nguy hiểm (lộ pattern) nhưng CTF hay dùng.
#   - CBC:  cần IV 16 byte. Thường IV được GHÉP vào ĐẦU ciphertext.
#   - CTR:  cần nonce/counter. Là stream, KHÔNG cần padding.
#   - PKCS7 padding: ECB/CBC thường có padding -> cần unpad sau khi giải.
# ---------------------------------------------------------------------------

def aes_decrypt(cipher, key, mode="CBC", iv=None, nonce=None, unpad_result=True):
    """Giải mã AES đa chế độ bằng pycryptodome.

    cipher : ciphertext (bytes).
    key    : bytes 16/24/32 byte.
    mode   : "ECB" | "CBC" | "CTR".
    iv     : 16 byte (bắt buộc cho CBC). Nếu None và mode=CBC, hàm sẽ lấy 16 byte
             ĐẦU của cipher làm IV (quy ước phổ biến).
    nonce  : cho CTR (thường 8 byte). Nếu None -> dùng counter 0 chuẩn.
    unpad_result : True -> bỏ PKCS7 padding (ECB/CBC). Đặt False nếu không có padding.
    Trả về plaintext (bytes).

    Yêu cầu: pip install pycryptodome
    """
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        from Crypto.Util import Counter
    except ImportError:
        print("[!] Chua cai pycryptodome. Chay: pip install pycryptodome")
        return None

    if isinstance(key, str):
        key = key.encode()

    mode = mode.upper()
    if mode == "ECB":
        c = AES.new(key, AES.MODE_ECB)
        pt = c.decrypt(cipher)
    elif mode == "CBC":
        if iv is None:
            # Quy ước: IV nằm ở 16 byte đầu ciphertext
            iv, cipher = cipher[:16], cipher[16:]
        c = AES.new(key, AES.MODE_CBC, iv)
        pt = c.decrypt(cipher)
    elif mode == "CTR":
        if nonce is not None:
            c = AES.new(key, AES.MODE_CTR, nonce=nonce)
        else:
            # Counter 128-bit bắt đầu từ 0 (hay gặp khi đề không nói rõ nonce)
            ctr = Counter.new(128, initial_value=0)
            c = AES.new(key, AES.MODE_CTR, counter=ctr)
        pt = c.decrypt(cipher)   # CTR là stream -> không padding
        return pt
    else:
        raise ValueError(f"Mode khong ho tro: {mode}")

    # Bỏ padding cho ECB/CBC (nếu có). Nếu sai key/IV -> unpad sẽ ném lỗi.
    if unpad_result:
        try:
            pt = unpad(pt, AES.block_size)  # block_size = 16
        except ValueError:
            print("[!] unpad that bai (sai key/IV hoac khong co padding PKCS7).")
    return pt


def aes_encrypt(plain, key, mode="CBC", iv=None, pad_input=True):
    """Mã hóa AES (dùng để TỰ TẠO test / kiểm chứng hàm giải mã).

    Trả về: với CBC -> iv + ciphertext (ghép IV vào đầu); ECB -> ciphertext.
    """
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    if isinstance(key, str):
        key = key.encode()
    mode = mode.upper()
    if pad_input:
        plain = pad(plain, AES.block_size)
    if mode == "ECB":
        return AES.new(key, AES.MODE_ECB).encrypt(plain)
    if mode == "CBC":
        import os
        if iv is None:
            iv = os.urandom(16)
        return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(plain)
    raise ValueError("Chi ho tro ECB/CBC cho ham encrypt demo.")


# ---------------------------------------------------------------------------
# PHẦN 4: ENCODING (base64 / base32 / hex / ROT)
# ---------------------------------------------------------------------------

def b64_decode(s, urlsafe=False):
    """Decode base64. urlsafe=True cho biến thể dùng '-' và '_'.

    Tự thêm '=' đệm nếu thiếu (lỗi 'Incorrect padding' rất hay gặp).
    """
    if isinstance(s, str):
        s = s.encode()
    s += b"=" * (-len(s) % 4)   # vá padding
    return base64.urlsafe_b64decode(s) if urlsafe else base64.b64decode(s)


def b32_decode(s):
    """Decode base32 (ký tự A-Z 2-7). Tự vá padding về bội số 8."""
    if isinstance(s, str):
        s = s.encode()
    s = s.upper()
    s += b"=" * (-len(s) % 8)
    return base64.b32decode(s)


def b16_decode(s):
    """Decode base16 = hex. Chấp nhận cả chữ hoa/thường, bỏ khoảng trắng."""
    if isinstance(s, bytes):
        s = s.decode("latin-1")
    s = "".join(s.split())
    return bytes.fromhex(s)


def rot13(s):
    """ROT13 cho text (chỉ xoay chữ cái a-z A-Z)."""
    if isinstance(s, bytes):
        s = s.decode("latin-1")
    return codecs.encode(s, "rot_13")


def caesar_brute(s):
    """Brute Caesar: in cả 26 dịch chuyển để mắt người chọn đáp án đúng.

    Trả về list (shift, text).
    """
    if isinstance(s, bytes):
        s = s.decode("latin-1")
    out = []
    for shift in range(26):
        res = []
        for ch in s:
            if "a" <= ch <= "z":
                res.append(chr((ord(ch) - 97 + shift) % 26 + 97))
            elif "A" <= ch <= "Z":
                res.append(chr((ord(ch) - 65 + shift) % 26 + 65))
            else:
                res.append(ch)
        text = "".join(res)
        out.append((shift, text))
        print(f"    shift={shift:2d}: {text}")
    return out


# ---------------------------------------------------------------------------
# PHẦN 5: BIẾN ĐỔI BYTE (reverse / endian swap)
# ---------------------------------------------------------------------------

def reverse_bytes(data):
    """Đảo ngược thứ tự toàn bộ byte (data[::-1])."""
    return data[::-1]


def swap_endian(data, word=4):
    """Đổi endian theo từng 'word' (mặc định 4 byte).

    Ví dụ word=4:  AA BB CC DD -> DD CC BB AA. Dùng khi dữ liệu lưu sai endian.
    Byte dư ở cuối (không đủ 1 word) được giữ nguyên.
    """
    out = bytearray()
    for i in range(0, len(data) - len(data) % word, word):
        out += data[i:i + word][::-1]
    out += data[len(data) - len(data) % word:]
    return bytes(out)


# ---------------------------------------------------------------------------
# DEMO / SELF-TEST
# ---------------------------------------------------------------------------

def demo():
    """Tự tạo dữ liệu rồi mã hóa -> giải mã để xác nhận các hàm chạy đúng."""
    ok = True
    secret = b"flag{cyber_sea_game_2026_demo}"

    # --- XOR repeating-key ---
    key = b"S3A"
    ct = xor_repeating(secret, key)
    assert xor_repeating(ct, key) == secret
    print(f"[OK] XOR repeating-key: {xor_repeating(ct, key)!r}")

    # --- XOR known-plaintext (biết tien to 'flag{') ---
    rkey, _ = xor_known_plaintext(ct, b"fla", 0)
    print(f"[OK] XOR known-plaintext suy ra key bat dau: {rkey!r}")

    # --- RC4 (thuan Python) ---
    rc_ct = rc4(secret, b"rc4key")
    assert rc4(rc_ct, b"rc4key") == secret
    print(f"[OK] RC4: {rc4(rc_ct, b'rc4key')!r}")

    # --- base64 / hex ---
    assert b64_decode(base64.b64encode(secret)) == secret
    assert b16_decode(secret.hex()) == secret
    print("[OK] base64 + hex round-trip")

    # --- AES (neu co pycryptodome) ---
    try:
        from Crypto.Cipher import AES  # noqa: F401
        aeskey = b"0123456789abcdef"            # 16 byte = AES-128
        # CBC: aes_encrypt ghep IV vao dau -> aes_decrypt tu tach IV
        cbc = aes_encrypt(secret, aeskey, "CBC")
        dec = aes_decrypt(cbc, aeskey, "CBC")
        assert dec == secret, dec
        print(f"[OK] AES-CBC: {dec!r}")
        # ECB
        ecb = aes_encrypt(secret, aeskey, "ECB")
        dec2 = aes_decrypt(ecb, aeskey, "ECB")
        assert dec2 == secret
        print(f"[OK] AES-ECB: {dec2!r}")
    except ImportError:
        print("[skip] AES: chua cai pycryptodome (pip install pycryptodome).")

    print("\n[==] Tat ca self-test PASS" if ok else "[!!] Co loi")


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return
    # Mặc định chạy self-test để xác nhận môi trường ok.
    demo()
    # TODO: Thay bằng lời giải bài thật của bạn, ví dụ:
    #   data = open("challenge.bin","rb").read()
    #   print(aes_decrypt(data, b"<key 16 byte>", "CBC"))        # AES-CBC (IV o dau)
    #   print(rc4(data, b"<key>"))                               # RC4
    #   xor_brute_single(data)                                   # do XOR 1 byte
    #   key,_ = xor_known_plaintext(data, b"flag{")              # XOR known-plaintext


if __name__ == "__main__":
    main()
