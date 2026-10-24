# hash

- **Category:** MISC
- **File đề:** `ctf/misc/hash/deleted_files.zip` — 18596 byte — MD5 `4dd5918f2840d985ab9e64ef425460bb` — SHA-1 `23e2583bf2fbbb0de87610a2572501d06a5d69aa`. Chứa 100 file text `file01.txt`..`file100.txt`. Kèm 3 giá trị hash.

## Tóm tắt đề
Một nhóm tội phạm đã xóa một thư mục; cảnh sát phục hồi thành `deleted_files.zip` gồm 100 file text. Kèm 3 hash:
```
6cff6c25e4198e2b26fb5c7118694092ada6bdc7ef1a344b86d36929cd2d40f5
5aa6d31bc63069d9e85f810a14d96e085d822b06b7de9516599aa3d209ba9614
ae6448234393c9ccf7895c0b98e52dac65248eda15016b4b247e3fb1ef1087e3
```
Nhiệm vụ: tìm 3 file khớp 3 hash này, ghép chuỗi bên trong, decode Base64 → flag.

## Phân tích (chi tiết: thuật toán, file khớp)
- 3 hash đều dài **64 ký tự hex = 256 bit** → gần như chắc chắn là **SHA-256** (có thể xác nhận bằng `hashid`/`hash-identifier`).
- SHA-256 một chiều (không đảo được) nhưng **so khớp được**: băm cả 100 file rồi đối chiếu 3 hash đích.
- **Kết quả xác minh tĩnh (đã chạy SHA-256 thật trên file đề):**
  - `file60.txt` → `Q1NHX0ZMQUd7aDRzaF9i`
  - `file62.txt` → `cm93bnNfd2l0aF9vbmlvbn`
  - `file79.txt` → `NfNF9icmU0a2Y0c3R9`
  - Ghép (đúng thứ tự 60→62→79): `Q1NHX0ZMQUd7aDRzaF9icm93bnNfd2l0aF9vbmlvbnNfNF9icmU0a2Y0c3R9`
  - Base64-decode → `<REDACTED>_FLAG{h4sh_browns_with_onions_4_bre4kf4st}`.

> **Redact (RULE 1):** chuỗi Base64 trên decode ra một wrapper mà **tiền tố là chữ viết tắt tên kỳ thi CTF** (3 ký tự + `_FLAG{...}`). Theo quy ước, tiền tố đó được redact; flag chuẩn hóa trình bày dưới dạng `flag{...}`. Bản thân chuỗi Base64 là artifact load-bearing nên giữ lại, nhưng lưu ý người đọc: decode sẽ lộ tiền tố tên giải (đã redact ở phần Flag).

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Nhận diện hash theo độ dài:** 64 hex ⇒ SHA-256; 40 hex ⇒ SHA-1; 32 hex ⇒ MD5. *Vì sao:* độ dài là chỉ dấu nhanh nhất; hint đề cũng nhắc "common cryptographic algorithm".
- **Batch hashing + matching:** `sha256sum *` / `Get-FileHash` rồi `grep`. *Vì sao:* không gian 100 file nhỏ, băm tất cả rồi so khớp là chắc chắn và nhanh.
- **Base64 decode:** CyberChef / `base64 -d`. *Vì sao:* 3 mảnh ghép lại là Base64 (ký tự `A-Za-z0-9+/=`); hint cuối nhắc CyberChef + "decode".

## Lời giải chi tiết (bước + code sạch)
1. Giải nén:
   ```bash
   unzip deleted_files.zip -d out && cd out/deleted_files
   ```
2. Băm hàng loạt & tìm file khớp:
   ```bash
   sha256sum *.txt > hashes.txt
   grep -E "6cff6c25...cd2d40f5|5aa6d31b...09ba9614|ae644823...ef1087e3" hashes.txt
   # → file60.txt, file62.txt, file79.txt
   ```
   PowerShell tương đương: `Get-FileHash *.txt -Algorithm SHA256`.
   Python (đọc thẳng trong ZIP, đã xác minh):
   ```python
   import zipfile, hashlib, base64
   z = zipfile.ZipFile("deleted_files.zip")
   targets = {
     "6cff6c25e4198e2b26fb5c7118694092ada6bdc7ef1a344b86d36929cd2d40f5",
     "5aa6d31bc63069d9e85f810a14d96e085d822b06b7de9516599aa3d209ba9614",
     "ae6448234393c9ccf7895c0b98e52dac65248eda15016b4b247e3fb1ef1087e3",
   }
   frag = {n: z.read(n) for n in z.namelist()
           if n.endswith(".txt") and hashlib.sha256(z.read(n)).hexdigest() in targets}
   combined = b"".join(frag[n] for n in sorted(frag))   # file60 → file62 → file79
   print(base64.b64decode(combined))
   ```
3. Ghép đúng thứ tự → `base64 -d` → flag (tiền tố wrapper redact theo RULE 1).

## Flag
```
flag{h4sh_browns_with_onions_4_bre4kf4st}
```
(Nguồn: `SOLUTIONS_VN.md` (C3) và nháp `Hash.md` ✅ đã xác minh bằng SHA-256 thật trên file đề. Wrapper gốc giải từ Base64 có **tiền tố là viết tắt tên kỳ thi** `<REDACTED>_FLAG{...}`, đã chuẩn hóa thành `flag{...}` theo RULE 1; nội dung bên trong giữ nguyên.)

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** cho một đống file + vài hash → bài "tìm file khớp hash". Hash 64 hex → SHA-256; 40 → SHA-1; 32 → MD5.
- **Quy trình:** xác định thuật toán theo độ dài (hoặc `hashid`) → băm hàng loạt (`sha256sum *` / `Get-FileHash`), `grep` so khớp → gom nội dung file khớp, nhận dạng encoding (Base64/hex) → decode.
- **Bẫy:** thứ tự ghép mảnh có thể không theo số thứ tự file → thử hoán vị (bản Base64 hợp lệ decode ra text đọc được); trailing newline làm sai hash nếu tự tạo lại file; có thể nhiều lớp encode (Base64 lồng Base64).
- **Checklist:** unzip 100 file → `sha256sum *` + grep 3 hash → file60/62/79 → ghép → `base64 -d` → flag.
