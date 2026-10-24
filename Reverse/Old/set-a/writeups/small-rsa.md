# small-rsa

- **Category:** Cryptography
- **File đề:** `ctf/crypto/small-rsa/text.txt` — 543 byte — MD5 `a68b95b30c5967d216c8db7b14dcafa1` — SHA-1 `6fc454c4991d92e1ac40fc5c0c7c05dc093059f2`. Chứa script sinh + ciphertext hex.

## Tóm tắt đề
Đề cho một đoạn script Python mã hóa **từng ký tự** của flag bằng RSA với module cực nhỏ, kèm ciphertext dạng hex. Mục tiêu: giải mã lấy nội dung.

Script sinh (trích nguyên văn `text.txt`):
```python
from Crypto.Util.number import getPrime
flag="FLAG*****************************"
c=""
p=getPrime(12)
q=getPrime(12)
N=p*q
E=65537
for l in flag:
    c += format(pow(ord(l), E, N), '08X')
print(c)
```
Ciphertext (hex, 352 hex = 44 block × 8 hex):
```
0015A15A001D7AEA000F663A001A1CFB00127B2D000353B800135A9B001D7AEA00212E6E0015A15A
00064786001D57D6001D7AEA00150F64001A1CFB001D7AEA001D57D60018005E0013EDF20010858D
0015A15A000823E20011654D001D57D6001D7AEA00135A9B002137060011654D0021370600150F64
0015A15A000353B8001D7AEA00213706000823E200064786001A1CFB00127B2D0017CEF80015A15A
00150F6400213706001A1CFB000823E2
```

## Phân tích (chi tiết: n/e/c RSA, khóa thật)
- **Lược đồ:** RSA textbook, mã hóa **mỗi ký tự riêng lẻ**: `c_i = m_i^E mod N` với `m_i = ord(char_i)`. Mỗi `c_i` được format thành đúng **8 chữ hex** → tách khối rất dễ. Có **44 block** ⇒ plaintext dài 44 ký tự.
- **Tham số:**
  - `E = 65537` (0x10001).
  - `p, q = getPrime(12)` → mỗi nguyên tố đúng 12 bit, nằm trong `[2048, 4095]`. Có **564 số nguyên tố < 4096** (gợi ý của đề), tức ~318k cặp — brute tức thời.
  - `N = p·q < 4096² ≈ 16.78 triệu` (≈ 2²⁴). Đây chính là lỗ hổng: **module quá nhỏ**, phân tích/brute trong tích tắc.
- **Lỗ hổng phụ (ECB per-character):** vì mã hóa từng ký tự, **block giống nhau ⇒ cùng một ký tự**. Block `0015A15A` lặp nhiều lần (ký tự xuất hiện thường xuyên nhất — ở đây là dấu cách). Về lý thuyết có thể tấn công bằng phân tích tần suất như mã thay thế đơn, nhưng brute `p,q` nhanh và chắc hơn.
- **Khóa thật (xác minh bằng phân tích tĩnh — chạy script giải trên dữ liệu, KHÔNG chạy binary đề):**
  - `p = 1429`, `q = 1531`, `N = 1429 × 1531 = 2,187,799`.
  - `λ = lcm(p-1, q-1) = lcm(1428, 1530)`; `D = E⁻¹ mod λ`.
  - Giải toàn bộ 44 block cho ra chuỗi ASCII in được 100%.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Brute-force small-modulus RSA:** thử mọi cặp nguyên tố `< 4096`, tính `D`, giải, chọn nghiệm cho toàn ký tự ASCII in được. *Vì sao:* `N ≈ 2²⁴` nên không gian khóa cực nhỏ; không cần RsaCtfTool/FactorDB, brute thuần nhanh hơn.
- **Tính khóa riêng:** `L = lcm(p-1, q-1)`; `E·D ≡ 1 (mod L)`; `m_i = c_i^D mod N`. *Vì sao:* đây là công thức giải RSA chuẩn; dùng `λ(N)` (lcm) thay vì `φ(N)` để tránh trường hợp `gcd(E, φ) ≠ 1`.
- **Điều kiện lọc nghiệm:** `N > max(block)` (bản mã phải nhỏ hơn module) và `gcd(E, L) = 1` (để `D` tồn tại). *Vì sao:* loại nhanh cặp vô nghĩa, tránh `ValueError` khi nghịch đảo.
- **Công cụ:** Python thuần (`math.lcm`, `pow(E,-1,L)` cần Python ≥ 3.8).

## Lời giải chi tiết (bước + code sạch)
```python
import math
c_hex = (
 "0015A15A001D7AEA000F663A001A1CFB00127B2D000353B800135A9B001D7AEA00212E6E0015A15A"
 "00064786001D57D6001D7AEA00150F64001A1CFB001D7AEA001D57D60018005E0013EDF20010858D"
 "0015A15A000823E20011654D001D57D6001D7AEA00135A9B002137060011654D0021370600150F64"
 "0015A15A000353B8001D7AEA00213706000823E200064786001A1CFB00127B2D0017CEF80015A15A"
 "00150F6400213706001A1CFB000823E2"
)
cs = [int(c_hex[i:i+8], 16) for i in range(0, len(c_hex), 8)]   # 44 block
E  = 65537

def primes_below(n):                 # sàng Eratosthenes
    s = [True]*n; s[0] = s[1] = False
    for i in range(2, int(n**0.5)+1):
        if s[i]:
            for j in range(i*i, n, i): s[j] = False
    return [i for i in range(n) if s[i]]

P = primes_below(4096)               # 564 số nguyên tố, đúng gợi ý đề
mx = max(cs)
for i in range(len(P)):
    for j in range(i, len(P)):
        N = P[i]*P[j]
        if N <= mx:                   # N phải lớn hơn mọi block
            continue
        L = math.lcm(P[i]-1, P[j]-1)
        if math.gcd(E, L) != 1:       # D phải tồn tại
            continue
        D = pow(E, -1, L)
        ms = [pow(x, D, N) for x in cs]
        if all(32 <= m < 127 for m in ms):      # toàn ký tự in được?
            print(P[i], P[j], N, "->", "".join(chr(m) for m in ms))
```
Output thực tế (đã chạy lại trên `text.txt`):
```
1429 1531 2187799 -> a world safe to exchange digital information
```

## Flag
```
flag{a world safe to exchange digital information}
```
(Nguồn: `SOLUTIONS_VN.md` mục A3 nêu plaintext `a world safe to exchange digital information` ✅ *tự khôi phục & đã xác minh lại tĩnh*. Đề chỉ yêu cầu "Decrypt text"; biến trong script tên `flag` nên nội dung giải mã chính là đáp án. Wrapper `flag{...}` chính thức: **nguồn không nêu rõ**, ở đây bọc giữ nguyên nội dung giải được. Lưu ý `flag="FALG****"`/`FLAG****` trong code chỉ là placeholder, KHÔNG phải tiền tố flag thật.)

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** RSA `getPrime(nhỏ)` (12-bit), mã hóa từng ký tự rồi nối hex; block cố định (8 hex) và có block lặp.
- **Quy trình:** tách block → đổi về số nguyên → brute cặp nguyên tố trong bound (`<4096`) → `D = E⁻¹ mod lcm(p-1,q-1)` → chọn `N` cho toàn ASCII in được. (Thay thế: thừa số hóa `N` trực tiếp qua FactorDB/RsaCtfTool nếu biết `N`.)
- **Bẫy:** per-character ⇒ lộ tần suất (ECB); nhớ điều kiện `gcd(E, lcm)=1` và `N > max(block)`; `pow(E,-1,L)` cần Python ≥ 3.8; đừng tin "FLAG/FALG" placeholder trong source.
- **Checklist:** split 8-hex block → brute p,q<4096 → D = E⁻¹ mod lcm → giải → lọc nghiệm ASCII.
