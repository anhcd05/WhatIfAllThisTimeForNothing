# simple-crypto

- **Category:** Cryptography
- **File đề:** `ctf/crypto/simple-crypto/VGhlIGtleSBpcyBoaWRkZW4gaW4gb25lIGluIGEgcHJpbWUgbnVtYmVy` — 32 byte — MD5 `9d78e9517a727721154638ec37a53770` — SHA-1 `4fe046d17236917113c51253b2f1a492fa7c19b8`. **Tên file chính là một chuỗi Base64**; nội dung bên trong là ciphertext.

## Tóm tắt đề
"Find the flag from the file." Tên file là Base64, decode ra gợi ý về khóa. Nội dung file (32 ký tự thường, xác minh tĩnh):
```
vjzgulmutmeuyubwekaqtmpjebiapwiy
```
Gợi ý từ đề (bản PDF nháp): mã Vigenère, "key = 1/prime number", "circulation (chu kỳ) của 1/prime", prime = **17** (có thể brute).

## Phân tích (chi tiết: khóa thật, offset)
1. **Decode tên file (Base64):**
   `VGhlIGtleSBpcyBoaWRkZW4gaW4gb25lIGluIGEgcHJpbWUgbnVtYmVy` → `The key is hidden in one in a prime number`.
   → diễn giải: "key = **ONE** in a prime number" = `1/prime`.
2. **Loại cipher:** Vigenère/Gronsfeld — Vigenère với khóa bằng **chữ số**. Keystream = các chữ số của khai triển thập phân tuần hoàn của `1/p`.
3. **Khóa với p = 17:** `1/17 = 0.0588235294117647 0588...`, chu kỳ **16 chữ số**: `0588235294117647`. Ciphertext dài 32 ⇒ khóa lặp đúng 2 chu kỳ.
4. **Phép giải:** Gronsfeld decrypt `P_i = (C_i − 97 − d_i) mod 26 + 97`, với `d_i` là chữ số khóa thứ `i`.
5. **Kết quả kiểm chứng (phân tích tĩnh):**
   - 4 ký tự đầu: `v→v (d=0)`, `j→e (d=5)`, `z→r (d=8)`, `g→y (d=8)` → **"very"** — khớp hoàn hảo 4 chữ số đầu chu kỳ `0,5,8,8` của `1/17`, tín hiệu rất mạnh khẳng định đúng hướng.
   - Nhưng từ ký tự 5 trở đi ra rác: chuỗi giải đầy đủ = `verysihskidtroxpefsirjkhvxhziqer` — không phải câu tiếng Anh rõ nghĩa.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Base64 decode tên file:** *Vì sao:* tên file nhìn rõ là Base64 (`A-Za-z0-9+/`, chia hết 4) → chứa hint về khóa.
- **Gronsfeld/Vigenère với keystream = chữ số của `1/p`:** sinh keystream bằng **chia dài** (`r=1; r*=10; digit=r//p; r%=p`). *Vì sao:* đề nêu rõ "Vigenère" + "1/prime" + "circulation"; chu kỳ `1/17` dài 16 tạo khóa lặp cho 32 ký tự.
- **Brute prime + chấm điểm tần suất tiếng Anh:** nếu p=17 chưa ra, thử mọi prime nhỏ, cả chiều cộng/trừ và biến thể Beaufort. *Vì sao:* đề gợi ý "should not be too difficult to brute force".
- **Công cụ:** Python thuần (chia dài tính `1/p`), CyberChef (From Base64, Vigenère Decode).

## Lời giải chi tiết (bước + code sạch)
```python
ct = "vjzgulmutmeuyubwekaqtmpjebiapwiy"

def recip_digits(p, n):                 # n chữ số đầu phần thập phân 1/p (chia dài)
    digs, r = [], 1
    for _ in range(n):
        r *= 10
        digs.append(r // p)
        r %= p
    return digs

def decrypt(p):
    key = recip_digits(p, len(ct))
    return "".join(chr((ord(c) - 97 - key[i]) % 26 + 97) for i, c in enumerate(ct))

print("p=17 ->", decrypt(17))
# p=17 -> verysih...  (4 ký tự đầu 'very' khớp; phần sau chưa ra câu nghĩa)
```
Khung brute dự phòng (nếu cần thử prime khác / Beaufort):
```python
for p in range(2, 4096):
    # bỏ qua số không nguyên tố ...
    for mode in ("sub", "add", "beaufort"):
        ...  # thử + chấm điểm tần suất tiếng Anh, tìm chuỗi chứa 'flag' hay câu nghĩa
```

## Flag
```
flag{...}
```
**Nguồn không nêu.** `SOLUTIONS_VN.md` (mục A2) và nháp `Simple Crypto.md` đều **không in flag cuối**: bản PDF đề bị cắt ở phần Instructions (trang trống) và không công bố flag. Áp đúng phương pháp đề mô tả (Gronsfeld, keystream = chu kỳ `1/17`) cho chuỗi `verysihskidtroxpefsirjkhvxhziqer`; cụm "very" ở đầu xác nhận đúng hướng nhưng phần sau không khớp dịch-đơn-chữ-số. Đã brute mọi nguyên tố `< 4096`, mọi điểm bắt đầu chu kỳ, 3 biến thể (cộng/trừ/Beaufort), chấm điểm tần suất chữ cái Anh — **không** ra plaintext tiếng Anh sạch. ⇒ Giá trị flag chính xác **không tái tạo được** từ dữ liệu hiện có; nhiều khả năng bản gốc dùng một biến thể cụ thể của công cụ (ví dụ chọn offset chu kỳ khác, hoặc chữ số map 0→a). Khi có bản đề đầy đủ, cập nhật nội dung trong `flag{...}`.

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** tên file/đoạn text là Base64; hint "Vigenère" + "key = 1/prime" + "circulation/recurring decimal"; ciphertext là chữ thường thuần.
- **Quy trình:** Base64-decode mọi thứ nhìn giống (tên file, chuỗi lạ) lấy hint → nhận khóa = chữ số khai triển `1/p` → sinh keystream bằng chia dài → Gronsfeld `P=(C−d) mod 26`, thử cả chiều `+`/Beaufort → nếu p gợi ý không ra, brute prime nhỏ + chấm điểm tần suất.
- **Bẫy:** quên chữ số `0` đầu chu kỳ (`1/17 = 0.0588...`) gây lệch khóa; chữ số đầu của `1/p` (p>10) thường là 0 nên kết quả brute "giống nguyên văn" ở đầu dễ gây nhầm; nhầm chiều cộng/trừ; prime lớn có chu kỳ dài hơn ciphertext (thành running key không lặp).
- **Checklist:** b64 hint → keystream = digits(1/p) → Gronsfeld P=C−d → thử chiều/Beaufort → brute prime nếu cần.
