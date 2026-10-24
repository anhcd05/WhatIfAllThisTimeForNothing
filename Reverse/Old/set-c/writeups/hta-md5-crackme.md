# hta-md5-crackme

- **Category:** Reverse / Crypto nhẹ (HTA crackme, MD5 + obfuscation)
- **File đề:** `challenges/hta-md5-crackme/crackme.hta` (116657 byte, MD5 `c327318de9a061955668cba97356b17a`), `description.txt`, `hashcat.txt` (1 hash MD5), `solve.py`

> Phân tích TĨNH tuyệt đối: `.hta` chạy bằng `mshta.exe` và có quyền hệ thống trên Windows → coi là **dữ liệu**, chỉ ĐỌC mã, KHÔNG double-click, KHÔNG chạy. Mọi logic dưới đây suy ra từ việc đọc JavaScript trong file.
>
> Lưu ý ẩn danh: file/đề gốc có chứa tên kỳ thi; trong writeup này mọi tham chiếu đó đã được thay bằng "giải"/"kỳ thi CTF". Các hằng số kỹ thuật (hash, mảng) được nêu nguyên giá trị vì không chứa tên giải.

## Tóm tắt đề
`description.txt`: bạn là giáo sư; sinh viên John quên mật khẩu đã dùng mã hóa project, nhờ khôi phục. Hint của John:
```
ko : 8-digit number
ka : 4-digit alphanumeric character
ko : 6-digit alphanumeric character   (dòng này thực chất nói về kq)

Order: 0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz
Flag format: flag{password}
```
File `.hta` là crackme JavaScript: mật khẩu nhập vào bị **tách thành 3 thành phần h1/h2/h3** theo một **mảng vị trí `nl`**, mỗi thành phần được **MD5**, rồi so với một **hash đích bị làm rối** (thay ký tự + đảo chuỗi) nhúng sẵn. Crack được 3 thành phần + tái tạo thứ tự = ra mật khẩu.

## Phân tích (chi tiết: khóa/offset/hằng số thật)

### 1. Khung HTA
Đầu file là HTML + thẻ `<HTA:APPLICATION ...>` (SINGLEINSTANCE, SHOWINTASKBAR="no"...). Toàn bộ JavaScript nằm gọn trong **một dòng rất dài (dòng 35)**; các hằng số khóa khai báo ở dòng 69–72:
```javascript
nl = [0, 6, 17, 14, 1, 18, 16, 7, 11, 13, 8, 12, 2, 3, 0, 15, 4, 0, 9, 5, 0, 0, 10, 0, 0];
ko = "58b4cb64f141e5c914640c5c8cc8e5d5";
ka = "8a1828526galf607b8257cb552b0e6c8";
kq = "z99za5c140689zc2d2a1052c8z5e4b9d";
```

### 2. Logic kiểm tra thật (trích nguyên từ `function checkPW`)
```javascript
function checkPW(pass) {
  if (pass != null && pass == "close") { window.close(); }
  var pwbody = (" " + pass).split("");       // CHÈN 1 space ở đầu => index 1-based
  var h1 = "", h2 = "", h3 = "";
  for (var i = 0; i < 24;) {
    h1 += pwbody[nl[++i]];
    h2 += pwbody[nl[++i]];
    h3 += pwbody[nl[++i]];
  }
  if ( co(m(h1.replace(/(^\s+)|(\s+$)/g, ""))) &&
       ca(m(h2.replace(/(^\s+)|(\s+$)/g, ""))) &&
       cq(m(h3.replace(/(^\s+)|(\s+$)/g, ""))) ) {
    alert("Congratulations! You got the right flag!");
  } else { alert("YOU'RE WRONG, TRY AGAIN!"); }
}
```
- `m(...)` = hàm MD5 thuần JS trong file (các hàm `fF/fG/fH/fI/rol/do_digest/...`).
- `.replace(/(^\s+)|(\s+$)/g,"")` = trim 2 đầu (loại các ô space dư).
- `co/ca/cq` so MD5 của h1/h2/h3 với hash đích đã **gỡ rối**:
```javascript
function co(o){ return o === dfgtrfd45TYHtredfgr45treRRGTEDFR( ko.replace(/4/g,'a').replace(/d/g,'3').replace(/e/g,'7') ); }
function ca(a){ return a === dfgtrfd45TYHtredfgr45treRRGTEDFR( ka.replace(/f/g,'3').replace(/l/g,'d').replace(/g/g,'9') ); }
function cq(q){ return q === dfgtrfd45TYHtredfgr45treRRGTEDFR( kq.replace(/2/g,'f').replace(/b/g,'7').replace(/z/g,'3') ); }
```
- Hàm tên dọa người `dfgtrfd45TYHtredfgr45treRRGTEDFR(s)` thực chất chỉ là **đảo chuỗi**: `s.split("").reverse().join("")`.

### 3. Gỡ rối để lấy MD5 đích THẬT
`ko/ka/kq` KHÔNG phải MD5 hợp lệ (chứa `g`, `l`, `z` ngoài tập hex) ⇒ chắc chắn đã bị substitution. Tái hiện đúng thứ tự JS làm (replace trước, rồi reverse):
```python
target_h1 = ko.replace('4','a').replace('d','3').replace('e','7')[::-1]
target_h2 = ka.replace('f','3').replace('l','d').replace('g','9')[::-1]
target_h3 = kq.replace('2','f').replace('b','7').replace('z','3')[::-1]
```
Giá trị đích (đã verify tĩnh bằng `hashlib`):
- **h1:** `53578cc8c5c0a6a19c571a1fa6bcab85`  — 8 chữ số
- **h2:** `8c6e0b255bc7528b7063da96258281a8`  — 4 ký tự alphanumeric
- **h3:** `d974e538cf501afdfc3986041c5a3993`  — 6 ký tự alphanumeric (trùng đúng nội dung `hashcat.txt`)

### 4. Giải mã mảng `nl` (bản đồ vị trí THẬT)
Vì `pwbody = " " + pass`, chỉ số là **1-based** (`pwbody[k]` = `pass[k-1]`, `nl[0]=0` trỏ vào space → bị trim). Vòng lặp chạy 8 lượt (i: 0→24, mỗi lượt `++i` 3 lần), gom theo `nl`:
```
h1 lấy nl tại vị trí [1,4,7,10,13,16,19,22] = pwbody[6,1,7,8,3,4,5,10]  -> 8 ký tự
h2 lấy nl tại vị trí [2,5,8,11,14,17,20,23] = pwbody[17,18,11,12,0,0,0,0] -> trim còn 4 ký tự
h3 lấy nl tại vị trí [3,6,9,12,15,18,21,24] = pwbody[14,16,13,2,15,9,0,0] -> trim còn 6 ký tự
```
Tức mật khẩu dài **18 ký tự** (`pwbody[1..18]`), được xé vào 3 nhóm. Đảo ngược ánh xạ này cho ta cách ráp lại mật khẩu từ h1/h2/h3 (xem bước giải).

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Đọc tĩnh HTA như dữ liệu:** `.hta` có quyền thực thi trên Windows; mở bằng editor/`strings`, KHÔNG chạy. *Vì sao:* tránh thực thi mã không tin cậy; mọi thứ cần đã nằm trong source.
- **Phát hiện "hash ngụy trang":** chuỗi 32 ký tự nhưng có ký tự ngoài `[0-9a-f]` ⇒ chắc chắn bị biến đổi. Tên hàm obfuscate (`dfgtrfd45...`) chỉ là đảo chuỗi. *Vì sao phải replace trước rồi reverse:* đúng thứ tự JS áp dụng khi so sánh, ta chỉ tái hiện để biết MD5 thật cần crack.
- **Brute-force theo không gian khóa nhỏ (dùng hint độ dài + charset):**
  - h1 = 8 **chữ số** → 10^8, Python `itertools` vét cạn vài giây.
  - h2 = 4 **alphanum (62)** → 62^4 ≈ 1.46e7, vét cạn được.
  - h3 = 6 **alphanum** → 62^6 ≈ 5.68e10, quá lớn cho Python → dùng **hashcat mask**.
  *Vì sao chia nhỏ:* MD5 một chiều; tác giả cố tình xé thành 3 phần ngắn để không gian từng phần đủ nhỏ để crack thay vì brute cả 18 ký tự.
- **Tái tạo hoán vị theo `nl`:** ánh xạ vị trí ngược để ghép ký tự 3 phần về đúng thứ tự mật khẩu.

## Lời giải chi tiết (bước + code/lệnh sạch, chạy lại được)

### Bước 1 — Crack h3 bằng hashcat (6 ký tự, charset hoa+thường+số)
```bash
hashcat -m 0 -a 3 hashcat.txt ?1?1?1?1?1?1 -1 ?u?l?d
#  -m 0 = MD5, -a 3 = mask, -1 ?u?l?d = charset gồm UPPER+lower+digit
#  => h3 = Dec0d3
```

### Bước 2 — Crack h1, h2 + ráp mật khẩu (thuần Python, CHỈ hashing, không chạy HTA)
```python
import hashlib, itertools

# MD5 đích đã GỠ RỐI từ ko/ka/kq (replace + reverse)
TARGET_H1 = "53578cc8c5c0a6a19c571a1fa6bcab85"  # 8 digits
TARGET_H2 = "8c6e0b255bc7528b7063da96258281a8"  # 4 alphanum
TARGET_H3 = "d974e538cf501afdfc3986041c5a3993"  # 6 alphanum

md5 = lambda s: hashlib.md5(s.encode()).hexdigest()

def crack(target, charset, length):
    for combo in itertools.product(charset, repeat=length):
        c = ''.join(combo)
        if md5(c) == target:
            return c

ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
h2 = crack(TARGET_H2, ALNUM, 4)        # -> fL46
h1 = crack(TARGET_H1, "0123456789", 8) # -> 20231114
h3 = "Dec0d3"                          # từ hashcat (62^6 quá lớn cho Python)
assert md5(h3) == TARGET_H3

# Ráp mật khẩu theo nghịch đảo bản đồ vị trí nl (đã suy ở phần Phân tích §4)
password = ''.join([
    h1[1], h3[3], h1[4], h1[5], h1[6], h1[0], h1[2], h1[3],
    h3[5], h1[7], h2[2], h2[3], h3[2], h3[0], h3[4], h3[1],
    h2[0], h2[1],
])
print(password)             # 001112233446cDdefL
print("flag{%s}" % password)
```

### Kết quả crack (đã kiểm chứng bằng hashlib)
- `h1 = 20231114` → MD5 = `53578cc8c5c0a6a19c571a1fa6bcab85` ✔ (giống một ngày 2023-11-14)
- `h2 = fL46`     → MD5 = `8c6e0b255bc7528b7063da96258281a8` ✔
- `h3 = Dec0d3`   → MD5 = `d974e538cf501afdfc3986041c5a3993` ✔

Ráp theo vị trí (từ `nl`):
```
pos 1: h1[1]=0   pos 2: h3[3]=0   pos 3: h1[4]=1   pos 4: h1[5]=1
pos 5: h1[6]=1   pos 6: h1[0]=2   pos 7: h1[2]=2   pos 8: h1[3]=3
pos 9: h3[5]=3   pos10: h1[7]=4   pos11: h2[2]=4   pos12: h2[3]=6
pos13: h3[2]=c   pos14: h3[0]=D   pos15: h3[4]=d   pos16: h3[1]=e
pos17: h2[0]=f   pos18: h2[1]=L
```
→ mật khẩu = `001112233446cDdefL`.

## Flag
```
flag{001112233446cDdefL}
```

## Gặp lại thì xử lý thế nào (playbook)
- **Nhận diện:** file `.hta`/`.html`/`.js` là crackme — có mảng hằng số + chuỗi ~32 ký tự (MD5) + hàm so sánh sau khi hash input người dùng; hoặc hàm tên lố (ví dụ `dfgtrfd45...`) để dọa.
- **Quy trình:**
  1. Đọc TĨNH, trích hằng số: hash đích, mảng hoán vị, bảng `replace`. (Với HTA: tuyệt đối không chạy.)
  2. Hash có ký tự ngoài `[0-9a-f]` ⇒ đã bị substitution/đảo. Hoàn tác **đúng thứ tự** mã làm: áp các `replace` rồi `reverse` (`[::-1]`). Tên hàm obfuscate thường chỉ là `split/reverse/join`.
  3. Dùng hint độ dài + charset để chọn công cụ: `itertools` cho không gian nhỏ (≤ ~10^8), **hashcat mask** (`-m 0 -a 3`, `-1 ?u?l?d`) cho không gian lớn.
  4. Đọc kỹ cách input bị tách/hoán vị (ở đây là mảng `nl` + thủ thuật chèn 1 space để index 1-based). Nghịch đảo ánh xạ để ráp mật khẩu đúng thứ tự, rồi bọc `flag{...}`.
- **Bẫy hay gặp:** (1) tưởng `ko/ka/kq` là MD5 rồi crack thẳng — sai, phải gỡ rối trước; (2) nhầm thứ tự ghép — `nl` là bản đồ vị trí, lại còn 1-based do chèn space, không đọc tuần tự; (3) charset h3 phải gồm cả hoa/thường/số (`?u?l?d`), thiếu một loại là không ra; (4) chạy thẳng `.hta` để "thử pass" — nguy hiểm và không cần thiết.
- **Công cụ:** editor/`strings` (đọc HTA), Python `hashlib`+`itertools`, `hashcat`, CyberChef (thử nhanh replace/reverse).
- **Checklist ngắn:** trích hằng số → gỡ rối (replace + reverse) → crack theo charset/độ dài → nghịch đảo hoán vị → tạo flag.
