# lsb-blue

- **Category:** Steganography
- **File đề:** `ctf/stego/lsb-blue/lsb_blue.png` — 84.583 byte — MD5 `eaf5a024a28ad4d58f22d5c073e22244`. Ảnh người cầm cờ tông **xanh dương**.

## Tóm tắt đề
Flag được nhúng trong ảnh dưới dạng file `flag.txt` bằng **OpenStego**, nhưng cần **passphrase**. Passphrase lại được giấu bằng **LSB** trong chính ảnh. Hai lớp: (1) lấy passphrase từ LSB kênh Blue; (2) dùng passphrase đó OpenStego Extract ra `flag.txt`.

## Phân tích (chi tiết: kênh/bit/chuỗi thật)
**Trinh sát (xác minh thật bằng `strings`):** ảnh có chunk tEXt:
```
tEXtDescription   This image contains the passphrase for OpenStego.
```
→ xác nhận công cụ là **OpenStego** và còn một passphrase ẩn phải tìm trước.
- Tông ảnh **xanh dương** → gợi ý dữ liệu LSB nằm ở **kênh Blue**. Mỗi pixel 3 kênh R/G/B, mỗi kênh 8 bit; thay bit thấp nhất (bit 0) gần như không đổi màu thị giác.
- Hai lớp khác nhau: **LSB bit0 kênh Blue → passphrase**; **OpenStego (LSB + password riêng) → flag.txt**.

Passphrase thu được: **`B@NGK0K`**.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **ExifTool/strings đọc metadata:** VÌ SAO: tEXt nêu rõ OpenStego + có passphrase ẩn → định hướng đúng 2 lớp.
- **LSB extraction bit0 kênh Blue (StegOnline/zsteg):** VÌ SAO: màu chủ đạo ám chỉ kênh chứa dữ liệu; chọn sai kênh/bit → ra rác.
- **OpenStego "Extract Data" + passphrase:** VÌ SAO: flag.txt được nhúng bằng OpenStego, không phải LSB thô → cần đúng tool + passphrase vừa tìm.

## Lời giải chi tiết (bước + lệnh sạch)
1. Đọc metadata:
   ```bash
   exiftool lsb_blue.png
   # Description: This image contains the passphrase for OpenStego.
   ```
2. Trích passphrase từ LSB bit0 kênh Blue:
   - StegOnline: upload → *Extract Files/Data* → chọn **Least Significant Bit (bit 0)** kênh **Blue**.
   - Hoặc: `zsteg -a lsb_blue.png` / `zsteg lsb_blue.png -E b1,b,lsb,xy`.
   - Kết quả: **`B@NGK0K`**.
3. OpenStego Extract Data:
   ```bash
   openstego extract -sf lsb_blue.png -p "B@NGK0K" -xd ./out
   ```
4. Đọc `out/flag.txt` → flag.

## Flag
flag{A_picture_is_worth_@_thousand_words}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** ảnh PNG tông màu đơn (xanh/đỏ/vàng) → ám chỉ kênh LSB; Exif/Description nhắc tên tool (OpenStego).
- **Quy trình:** (1) `exiftool`/`strings` lấy gợi ý + tên tool; (2) thử LSB theo kênh được gợi ý → lấy passphrase/chuỗi; (3) nếu tool là OpenStego/steghide → extract bằng passphrase vừa tìm.
- **Công cụ:** exiftool, StegOnline, zsteg, OpenStego.
- **Bẫy:** nhầm 2 lớp (LSB cho passphrase, OpenStego cho flag.txt); chọn sai kênh/bit; passphrase có ký tự đặc biệt (`@`, số `0`) → gõ chính xác.
