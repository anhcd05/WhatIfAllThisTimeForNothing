# lsb-to-qr

- **Category:** Steganography (nguồn ghi "Forensics")
- **File đề:** `ctf/stego/lsb-to-qr/lsb_qr_o65537.png` — 184.748 byte — MD5 `3b6d22ff90408e8caf12f20f8e97f95c`. Ảnh **480×270** (xác minh IHDR: width `0x01E0`=480, height `0x010E`=270, color type 02 = RGB). Hậu tố `o65537` gợi ý **offset pixel** để bắt đầu đọc LSB.

## Tóm tắt đề
Trích thông điệp ẩn trong ảnh. Trích **LSB** (bắt đầu từ offset 65537 pixel) rồi decode ASCII → thấy một đoạn bọc giữa `<LINE>` và `<PLAIN>`. Chuỗi bên trong là **632 bit nhị phân**. Tên bài "LINE to PLAIN" = biến chuỗi **một hàng (line)** thành mặt phẳng **(plane)** 2D: `632 = 25×25 + 7` (7 bit cuối là padding). Ma trận 25×25 là một **mã QR version 2**; quét QR để lấy thông điệp.

## Phân tích (chi tiết: offset/độ dài/ma trận thật)
- `o65537`: số pixel offset bắt đầu đọc LSB. 65537 = `0x10001` (số Fermat quen thuộc), ở đây dùng như offset để dễ giải.
- LSB cho ra text có cấu trúc `<LINE> ...632 bit... <PLAIN>`.
- `632 − 7 = 625 = 25²` → reshape thành ma trận **25×25** (đọc theo hàng). Bit 1 = ô đen, bit 0 = ô trắng (thử đảo nếu quét trượt).
- Chuỗi 632 bit (giữa `<LINE>`/`<PLAIN>`):
```
1111111011001010001111111100000100001100010100000110111010111000110010111011011
1010111001000010111011011101000111000001011101100000101010100110100000111111110
1010101010111111100000000111011011000000000101011111010010111101101011101000101
1100011000001111110111001111011100111110010100100101010101110111001011001110010
1111000100000110010011010111101111100100100100110000100010101100100001011011001
0001111011010101011001111111100000000011011111100011101111111101101001110101111
1100000101101110010001011010111010000000101111100111011101011011110010110100101
1101001111011100111101100000101100100110001000011111110001100111011110110000000
```

## Kỹ thuật áp dụng (+ VÌ SAO)
- **LSB extraction + offset 65537:** VÌ SAO: hậu tố tên file cho offset; đọc đúng điểm bắt đầu mới ra marker `<LINE>...<PLAIN>` sạch.
- **Reshape 1D → 2D (625 = 25²):** VÌ SAO: tên bài + độ dài ≈ số chính phương là tín hiệu QR; 25×25 = QR version 2.
- **Dựng QR + quiet zone, quét bằng OpenCV:** VÌ SAO: reader cần viền trắng (quiet zone) + ảnh đủ lớn mới nhận finder pattern.

## Lời giải chi tiết (bước + code sạch, đã chạy thật trên dữ liệu)
```python
import numpy as np, cv2
bits = ("1111111011001010001111111100000100001100010100000110111010111000110010111011011"
        "1010111001000010111011011101000111000001011101100000101010100110100000111111110"
        "1010101010111111100000000111011011000000000101011111010010111101101011101000101"
        "1100011000001111110111001111011100111110010100100101010101110111001011001110010"
        "1111000100000110010011010111101111100100100100110000100010101100100001011011001"
        "0001111011010101011001111111100000000011011111100011101111111101101001110101111"
        "1100000101101110010001011010111010000000101111100111011101011011110010110100101"
        "1101001111011100111101100000101100100110001000011111110001100111011110110000000")
side, scale, qz = 25, 10, 4
mat = np.array([[0 if bits[r*side+c]=='1' else 255 for c in range(side)]   # 1 = đen
                for r in range(side)], dtype=np.uint8)
big = np.kron(mat, np.ones((scale, scale), np.uint8))
canvas = np.full(((side+2*qz)*scale, (side+2*qz)*scale), 255, np.uint8)     # thêm quiet zone
canvas[qz*scale:qz*scale+big.shape[0], qz*scale:qz*scale+big.shape[1]] = big
data, *_ = cv2.QRCodeDetector().detectAndDecode(canvas)
print(data)        # -> now you see me!!
```
Kết quả quét QR: **`now you see me!!`**.

## Flag
flag{now you see me!!}

> Nội dung mã QR là `now you see me!!` — chính là message cần nộp. Đề không dùng wrapper `flag{}` cứng; `SOLUTIONS_VN.md` ghi flag ≈ `flag{now you see me!!}`. Giá trị QR đã tự khôi phục/xác minh (nguồn gốc không in nội dung QR).

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** LSB ra một dãy bit dài (không phải text) → nghĩ reshape 2D (bitmap/QR); độ dài ≈ n² (441=21², 625=25², 729=27²); tên bài gợi ý "line → plane/matrix/reshape".
- **Quy trình:** (1) trích LSB (chú ý offset nếu tên file/hint cho biết), decode ASCII tìm marker; (2) đếm độ dài, trừ padding, kiểm tra số chính phương; (3) reshape ma trận, map 1→đen/0→trắng (thử cả 2 chiều); (4) thêm quiet zone, quét QR (nếu trượt: transpose, đảo màu, scale lớn hơn).
- **Công cụ:** zsteg/script LSB, numpy, OpenCV `QRCodeDetector`, zbar, điện thoại.
- **Bẫy:** quên quiet zone; đảo nhầm bit (1=trắng); padding không chắc ở cuối → kiểm tra finder pattern (3 góc) để xác định hướng đọc.
