# fullwidth-mail

- **Category:** Crypto
- **File đề:** `fullwidth-mail/README.md` (đề + chuỗi hex) và ảnh gợi ý `unhex.png`. Không có file nhị phân — toàn bộ dữ liệu nằm trong phần mô tả.

## Tóm tắt đề

Một điều tra viên (Mr. Horii) đang điều tra vụ **biển thủ** trong công ty thì nhận được email từ người gửi vô danh. Nội dung quan trọng của email bị thay bằng một "chuỗi vô nghĩa":

```
/EF/BC/B6/EF/BC/A7/EF/BD/87/EF/BD/9A/EF/BC/B8/EF/BC/90/EF/BC/B6/EF/BD/94/EF/BC/B9/EF/BD/8A/EF/BC/AE/EF/BC/96/EF/BD/85/EF/BD/8D/EF/BD/97/EF/BD/9A/EF/BD/83/EF/BD/8C/EF/BC/98/EF/BD/98/EF/BC/AE/EF/BC/B6/EF/BC/99/EF/BC/A7/EF/BD/84/EF/BC/B7/EF/BC/91/EF/BD/90/EF/BC/BA/EF/BC/B1/EF/BC/9D/EF/BC/9D
```

Định dạng flag: `flag{[A-Za-z0-9 symbols]}`. Nhiệm vụ: khôi phục thông tin ẩn trong email.

## Phân tích (chi tiết)

Chuỗi có cấu trúc rất đều: các cụm 2 ký tự hex ngăn cách bằng `/`. Đây là **dãy byte viết dưới dạng hex**.

Điểm then chốt: các byte luôn đi theo nhóm **3 byte** bắt đầu bằng `EF BC xx` hoặc `EF BD xx`. Trong UTF-8:

- Byte dẫn `1110xxxx` báo hiệu một ký tự được mã hóa bằng **3 byte** (`1110xxxx 10xxxxxx 10xxxxxx`).
- Giải mã `EF BC B6` → code point `U+FF36` = `Ｖ` (fullwidth Latin capital V).
- Giải mã `EF BC 9D` → `U+FF1D` = `＝` (fullwidth equals sign).

Vậy dãy byte này là **UTF-8 của một chuỗi ký tự fullwidth** (dải *Halfwidth and Fullwidth Forms*, `U+FF00–U+FFEF`). Fullwidth là bản ký tự rộng gấp đôi dùng trong văn bản CJK (Trung/Nhật/Hàn): mỗi ký tự ASCII có một "bản fullwidth" tương ứng.

Hai ký tự cuối là `＝＝` (fullwidth `==`) — dấu hiệu đặc trưng của **phần đệm Base64**. Tức là chuỗi fullwidth này thực chất là một **Base64 đã bị "ngụy trang" bằng cách thay từng ký tự ASCII bằng bản fullwidth**.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **Unhex** — tách chuỗi theo `/`, đổi mỗi phần tử hex thành byte. *Vì sao:* chuỗi gốc chỉ là biểu diễn hex của dãy byte thật.
2. **Decode UTF-8** — ghép byte lại và giải mã UTF-8 để ra chuỗi ký tự fullwidth. *Vì sao:* các nhóm `EF Bx xx` là mã hóa UTF-8 nhiều byte, phải decode mới ra ký tự Unicode đúng.
3. **Chuẩn hóa Unicode NFKC** — đổi ký tự fullwidth về ASCII thường (`Ｖ`→`V`, `＝`→`=`...). *Vì sao:* NFKC (Normalization Form Compatibility Composition) định nghĩa phép "gập" tương thích, trong đó fullwidth được quy về ký tự ASCII tương đương. Đây là cách sạch và chuẩn hơn tự lập bảng tra thủ công.
4. **Decode Base64** — chuỗi ASCII thu được là Base64 hợp lệ. *Vì sao:* đuôi `==` và tập ký tự `A-Za-z0-9+/` xác nhận đây là Base64.

## Lời giải chi tiết (bước + code/lệnh sạch)

```python
import base64, unicodedata

hexpath = ("/EF/BC/B6/EF/BC/A7/EF/BD/87/EF/BD/9A/EF/BC/B8/EF/BC/90/EF/BC/B6/EF/BD/94"
           "/EF/BC/B9/EF/BD/8A/EF/BC/AE/EF/BC/96/EF/BD/85/EF/BD/8D/EF/BD/97/EF/BD/9A"
           "/EF/BD/83/EF/BD/8C/EF/BC/98/EF/BD/98/EF/BC/AE/EF/BC/B6/EF/BC/99/EF/BC/A7"
           "/EF/BD/84/EF/BC/B7/EF/BC/91/EF/BD/90/EF/BC/BA/EF/BC/B1/EF/BC/9D/EF/BC/9D")

# Bước 1: unhex -> bytes
bs = bytes(int(x, 16) for x in hexpath.split('/') if x)

# Bước 2: decode UTF-8 -> chuỗi fullwidth
full = bs.decode('utf-8')          # ＶＧｇｚＸ０ＶｔＹｊＮ６ｅｍｗｚｃｌ８ｘＮＶ９ＧｄＷ１ｐＺＱ＝＝

# Bước 3: NFKC -> Base64 ASCII
b64 = unicodedata.normalize('NFKC', full)   # VGgzX0VtYjN6emwzcl8xNV9GdW1pZQ==

# Bước 4: Base64 decode
print(base64.b64decode(b64).decode())        # Th3_Emb3zzl3r_15_Fumie
```

Kết quả trung gian (đã kiểm chứng trong nguồn): Base64 = `VGgzX0VtYjN6emwzcl8xNV9GdW1pZQ==`, giải ra `Th3_Emb3zzl3r_15_Fumie` ("The Embezzler is Fumie" — kẻ biển thủ là Fumie, khớp cốt truyện tố giác tham nhũng).

Cách làm bằng CyberChef: `From Base64` không chạy được ngay trên fullwidth; phải thêm bước **Normalize Unicode (NFKC)** trước, sau đó mới `From Base64`.

## Flag

flag{Th3_Emb3zzl3r_15_Fumie}

## Gặp lại thì xử lý thế nào (playbook)

1. Thấy chuỗi hex ngăn cách bằng `/` (hoặc `\x`, `%`, dấu cách) → **unhex** trước tiên.
2. Sau unhex ra byte lạ dạng `EF Bx xx` lặp đi lặp lại → nghĩ ngay tới **UTF-8 nhiều byte** → decode UTF-8.
3. Nhìn thấy ký tự "rộng" (fullwidth) hoặc ký tự trông giống chữ/số nhưng không phải ASCII → **NFKC normalize** để gập về ASCII. (CyberChef: "Normalize Unicode".)
4. Chuỗi ASCII kết thúc bằng `=`/`==`, chỉ gồm `A-Za-z0-9+/` → **Base64 decode**.
5. Nguyên tắc chung: fullwidth Unicode là một "lớp ngụy trang" rất phổ biến cho Base64/text; đừng cố brute mật mã toán học khi đây chỉ là chồng encoding.
6. Cạm bẫy: dán thẳng fullwidth vào bộ decode Base64 → báo lỗi "invalid character"; luôn normalize trước. Đừng nhầm `EF BB BF` (BOM UTF-8) với ký tự fullwidth.
