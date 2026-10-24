# nested-encoding

- **Category:** MISC
- **File đề:** `nested-encoding/README.md` (chứa bảng dữ liệu). Không có file nhị phân.

## Tóm tắt đề

Đề cho bảng 2 cột `A | B`, yêu cầu điền hàng còn thiếu `● | ■` để ghép flag. Format: `flag{A_B}`, ví dụ `flag{au_c3lkbmV5}`.

```
A | B
au | c3lkbmV5
us | dWNudi1uY21nLWVrdmE=
gr | ZXhsaXJ3
it | emF4b3Q=
cn | am1xcnF2bw==
ca | Zmt4bXllZm9i
gb | eGF6cGF6
ru | Z2Nxdnc=
br | aHll
kr | aHF3Z2Z5dXpzZnk=
● | ■
cn | eGFlZmVqYw==
fr | bnlwZ3E=
it | Z2NsdWhp
us | bmM=
```

## Phân tích (chi tiết)

Cột A là **ccTLD** (mã quốc gia 2 chữ: `au`=Úc, `us`=Mỹ, `gr`=Hy Lạp...). Cột B trông như **Base64**. Bài chồng 2 lớp: Base64 (ngoài) + ROT/Caesar (trong), và mấu chốt "trí tuệ" là nhận ra **ngữ cảnh**.

**Lớp 1 — Base64 decode** cột B:

```
au -> sydney          (đọc được ngay, có nghĩa)
us -> ucnv-ncmg-ekva
gr -> exlirw
it -> zaxot
cn -> jmqrqvo ...
```

Chỉ `au=sydney` có nghĩa → còn một lớp ROT nữa. **Lớp 2 — ROT/Caesar** với bước **tăng dần**:

```
au -> sydney                        (2000 Sydney)
us -> salt-lake-city   // ROT-2     (2002 Salt Lake City)
gr -> athens           // ROT-4     (2004 Athens)
it -> turin            // ROT-6     (2006 Turin)
cn -> beijing          // ROT-8     (2008 Beijing)
ca -> vancouver        // ROT-10    (2010 Vancouver)
gb -> london           // ROT-12    (2012 London)
ru -> sochi            // ROT-14    (2014 Sochi)
br -> rio              // ROT-16    (2016 Rio)
kr -> pyeongchang      // ROT-18    (2018 PyeongChang)
● | ■                  // ROT-20    (2020 ???)
cn -> beijing          // ROT-22    (2022 Beijing)
fr -> paris            // ROT-24    (2024 Paris)
it -> gcluhi           // ROT-26 (=ROT0, xác nhận quy luật)
us -> la               // ROT-28    (2028 Los Angeles)
```

Đây là danh sách **thành phố đăng cai Olympic** (xen kẽ hè/đông). Bước ROT = **(năm − 2000)**. Hàng thiếu ứng với **2020 → Tokyo, Nhật → ccTLD `jp`**.

Để khớp "công thức" tạo cột B, phải **mã hóa ngược**: lấy `tokyo` → ROT20 → Base64.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **Base64 decode** cột B. *Vì sao:* tập ký tự + `=` cho thấy Base64; decode để lộ lớp trong.
2. **ROT/Caesar với bước thay đổi theo hàng.** *Vì sao:* chỉ `au` đọc được sau Base64, các hàng khác cần dịch chữ; bước dịch không cố định mà = (năm − 2000).
3. **Nhận diện ngữ cảnh (Olympic host cities).** *Vì sao:* đây là chìa khóa xác định hàng thiếu là 2020/Tokyo/`jp`.
4. **Mã hóa ngược `tokyo` → ROT20 → Base64.** *Vì sao:* cột B là *bản đã mã hóa*; phải tạo lại đúng format để điền ô `■`.

## Lời giải chi tiết (bước + code/lệnh sạch)

```python
import base64

def rot(s, n):
    out = []
    for c in s:
        if c.islower():
            out.append(chr((ord(c)-97+n) % 26 + 97))
        elif c.isupper():
            out.append(chr((ord(c)-65+n) % 26 + 65))
        else:
            out.append(c)
    return ''.join(out)

# Mã hóa ngược cho hàng 2020:
x = rot("tokyo", 20)                              # 'niesi'
b = base64.b64encode(x.encode()).decode()          # 'bmllc2k='
print("jp", "|", b)                                 # jp | bmllc2k=
```

Kết quả: `rot20("tokyo") = "niesi"`, `base64("niesi") = "bmllc2k="`. Hàng thiếu là `jp | bmllc2k=` → flag.

CyberChef: "From Base64" → "ROT13 Brute Force" để dò nhanh các hàng; khi điền ô thiếu thì làm ngược: "ROT13" (amount 20) → "To Base64".

## Flag

flag{jp_bmllc2k=}

## Gặp lại thì xử lý thế nào (playbook)

1. Cột/chuỗi giống Base64 → decode trước. Nếu ra chữ "gần giống nghĩa" nhưng lệch → nghĩ tới **ROT/Caesar lớp trong**.
2. Khi chỉ một mẫu đọc được, so sánh để tìm **bước dịch**; thử ROT1..25 (brute).
3. Tìm **quy luật** của bước dịch (theo số thứ tự, theo một con số trong dữ liệu như năm) — ở đây là năm Olympic.
4. Khai thác **ngữ cảnh** (tên quốc gia, thành phố, danh sách nổi tiếng) để điền phần thiếu.
5. Khi phải "điền ô", nhớ làm **ngược quy trình** (encode) đúng định dạng đề yêu cầu, giữ cả phần đệm `=`.
