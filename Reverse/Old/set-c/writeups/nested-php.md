# nested-php

- **Category:** Reverse / Misc (PHP obfuscation — "matryoshka")
- **File đề:**
  - Lớp ngoài cùng: một file PHP **~130 MB** (một lệnh `eval(hex2bin("…"))` khổng lồ).
    *Lưu ý: file lớp ngoài không có trong thư mục đề; chỉ phân tích cơ chế dựa trên mô tả + lớp
    cuối.*
  - `challenges/nested-php/final.php` — **143 byte**, md5 `6232378e53afa52faf51a5178639b984` —
    lớp trong cùng, chứa flag (và một cú lừa).

## Tóm tắt đề

Một script PHP bị làm rối kiểu **búp bê Nga (matryoshka)**: mỗi lớp khi `eval` chỉ làm đúng một
việc là **giải mã/giải nén rồi `eval` lớp tiếp theo**, lồng nhau rất nhiều tầng. Lớp trong cùng
`final.php` chứa flag — nhưng có **bẫy**: flag nằm trong **comment**, còn đoạn code thực thi bị
**cắt ngắn** nên khi chạy KHÔNG hề in flag. Phải **đọc tĩnh**, tuyệt đối không chạy PHP.

## Phân tích (chi tiết: khóa/offset/hằng số thật)

**Cơ chế từng lớp (từ vựng wrapper).** Mỗi lớp = lớp-kế-tiếp được bọc bởi một chuỗi phép biến
đổi **khả nghịch** rồi `eval`. Pattern điển hình:

```
eval(hex2bin("6261736536345f6465636f6465..."))     # hex2bin  -> chuỗi "base64_decode(..."
   -> base64_decode("aGV4MmJpbigi...")              # base64   -> chuỗi "hex2bin(..."
      -> hex2bin("677a696e666c617465...")           # hex      -> chuỗi "gzinflate(..."
         -> gzinflate(hex2bin("..."))               # raw DEFLATE -> lớp PHP kế
            -> eval(... lớp tiếp theo ...)
```

Bằng chứng "từ vựng" (giải hex bằng tay, không chạy PHP):

```python
bytes.fromhex("6261736536345f6465636f6465")  # -> b"base64_decode"
bytes.fromhex("677a696e666c617465")          # -> b"gzinflate"
bytes.fromhex("6865783262696e")              # -> b"hex2bin"
```

Mỗi hàm và hàm ngược của nó:

| Wrapper (PHP) | Tác dụng | Hàm ngược / cách bóc |
|---|---|---|
| `hex2bin("...")` | hex → bytes (2 hex = 1 byte) | `bytes.fromhex(...)` / From Hex |
| `base64_decode("...")` | base64 → bytes | `base64.b64decode(...)` / From Base64 |
| `gzinflate("...")` | giải nén **raw DEFLATE** (không header) | `zlib.decompress(data, -15)` / Raw Inflate |
| `eval("<php>")` | **chạy** chuỗi như PHP | → thay bằng `echo`/`print` để IN RA, không chạy |

Vì sao lớp ngoài tới ~130 MB: hex encode nhân đôi kích thước, base64 +~33%, nhiều tầng lồng nhau
cộng dồn nên phình rất to ở lớp ngoài cùng.

**Lớp trong cùng `final.php` (143 byte) — nội dung THẬT trên đĩa:**

```php
<?php $s='print("I have a flag!\n"); /* flag{A_Matryoshka_Obfuscated_Script} */ print("Congrats!!\n");'; $s=substr($s, 0, 27); eval($s); ?>
```

**Phân tích byte-level cú lừa `substr`:** chuỗi `$s` (sau khi PHP xử lý single-quote) là:

```
print("I have a flag!\n"); /* flag{A_Matryoshka_Obfuscated_Script} */ print("Congrats!!\n");
```

`$s = substr($s, 0, 27)` cắt còn **27 ký tự đầu** = (xác minh THẬT bằng đếm ký tự):

```
substr(0,27)   -> 'print("I have a flag!\n"); '      <-- 27 ký tự, gồm cả "; " ở cuối
phần bị cắt bỏ -> '/* flag{A_Matryoshka_Obfuscated_Script} */ print("Congrats!!\n");'
```

→ `eval($s)` chỉ chạy `print("I have a flag!\n");` nên **chỉ in "I have a flag!"** rồi dừng. Flag
thật nằm trong **comment `/* ... */`** của chuỗi gốc — đoạn này bị `substr` cắt mất, **không bao
giờ được eval/in ra**. Vì vậy phải ĐỌC chuỗi, đừng tin output khi chạy.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Bóc lớp obfuscation theo vòng lặp (unwrap loop)** — VÌ mỗi lớp có pattern cố định
  `eval(<transform>(<transform>(...)))`; nhận ra pattern thì chỉ cần đảo đúng các phép đó.
- **Vô hiệu hóa `eval` khi bóc** (thay `eval`→`echo`/`print`, hoặc giải mã thủ công) — VÌ chạy
  `eval` của mã lạ là nguy hiểm; mục tiêu chỉ là "giải mã", không "thực thi payload".
- **Các phép PHP đều khả nghịch trong Python** (`bytes.fromhex`, `base64.b64decode`,
  `zlib.decompress(x,-15)`) — VÌ cho phép bóc hoàn toàn offline, không cần PHP runtime.
- **Phân tích tĩnh thắng bẫy `substr`** — VÌ output khi chạy bị cố ý làm lệch (code bị cắt, flag
  trong comment); chỉ `grep` flag trên **source đã giải** mới ra.

## Lời giải chi tiết (bước + code/lệnh sạch, chạy lại được)

**Bóc tự động bằng Python (không chạy PHP) — dùng khi có file lớp ngoài:**

```python
import base64, zlib, re, binascii

def peel(payload: bytes) -> bytes:
    """Đảo đúng wrapper xuất hiện ở lớp hiện tại; trả nguyên trạng nếu hết wrapper."""
    s = payload.decode('latin1', 'ignore')
    m = re.search(r'gzinflate\(hex2bin\("([0-9a-fA-F]+)"\)\)', s)   # xét tổ hợp trước
    if m:
        return zlib.decompress(binascii.unhexlify(m.group(1)), -15)
    m = re.search(r'hex2bin\("([0-9a-fA-F]+)"\)', s)
    if m:
        return binascii.unhexlify(m.group(1))
    m = re.search(r'base64_decode\("([A-Za-z0-9+/=]+)"\)', s)
    if m:
        return base64.b64decode(m.group(1))
    m = re.search(r'gzinflate\("(.*?)"\)', s, re.S)
    if m:
        return zlib.decompress(m.group(1).encode('latin1'), -15)
    return payload

data = open('outer_layer.php', 'rb').read()
prev = None
while data != prev:                 # bóc đến khi không còn wrapper
    prev = data
    data = peel(data)

src = data.decode('latin1', 'ignore')
print(src)
print(re.search(r'flag\{[^}]*\}', src).group(0))   # grep flag trên SOURCE, không chạy
```

**Cách thủ công tương đương (CyberChef):** ở mỗi lớp lấy chuỗi hex/base64 ra và chạy chuỗi công
thức *From Hex → From Base64 → Raw Inflate* (đúng theo wrapper của lớp đó), lặp đến khi ra
`final.php`. Hoặc trong PHP CLI cô lập, thay `eval(` → `echo(` để **in** lớp kế thay vì chạy.

**Tới lớp cuối `final.php` — KHÔNG chạy, chỉ đọc + đếm ký tự** (xác minh bẫy `substr`):

```python
import re
raw = open('final.php', 'rb').read()
inner = re.search(r"\$s='(.*?)';", raw.decode('latin1')).group(1)
php = inner.replace('\\\\', '\\').replace("\\'", "'")   # giải escape single-quote của PHP
print('substr(0,27):', repr(php[:27]))                  # -> 'print("I have a flag!\\n"); '
print('bị cắt bỏ   :', repr(php[27:]))                  # -> chứa comment flag
print(re.search(r'flag\{[^}]*\}', php).group(0))        # -> flag{A_Matryoshka_Obfuscated_Script}
```

Flag lấy trực tiếp từ comment, không phụ thuộc vào việc chạy script.

## Flag

flag{A_Matryoshka_Obfuscated_Script}

## Gặp lại thì xử lý thế nào (playbook)

- **Nhận diện:** file PHP/JS rất lớn chỉ gồm một `eval(...)` với chuỗi hex/base64 dài; giải một
  lớp lại lộ `eval(...)` tiếp.
- **Quy trình:**
  1. **KHÔNG chạy.** Thay `eval`→`echo`/`print`, hoặc giải mã thủ công từng wrapper.
  2. Nhận diện bảng wrapper: `hex2bin` / `base64_decode` / `gzinflate` / `gzuncompress` /
     `gzdecode` / `str_rot13` / `strrev` — mỗi cái có hàm ngược trong Python/CyberChef.
  3. Lặp bóc tới khi không còn `eval` → lớp cuối.
  4. Ở lớp cuối, cảnh giác bẫy bẻ output: `substr`/biến bị ghi đè/decoy/comment. Lấy flag bằng
     **đọc source tĩnh + regex** `flag\{.*\}`, đừng tin những gì script in ra.
- **Công cụ:** CyberChef (From Hex, From Base64, Raw Inflate, ROT13); Python (`base64`, `zlib`,
  `binascii`); PHP CLI với `eval`→`echo`.
- **Bẫy hay gặp:** chạy thử rồi tưởng không có flag vì code cắt chuỗi/decoy; file quá lớn làm
  editor treo (xử lý bằng stream + regex trên bytes); dùng `gzinflate` với header sai (phải raw
  DEFLATE `zlib.decompress(x, -15)`).
- **Checklist ngắn:** đừng chạy → nhận diện wrapper → bóc vòng lặp → tới lớp cuối → đọc tĩnh +
  regex flag.
