# png-ihdr

- **Category:** Steganography
- **File đề:** `ctf/stego/png-ihdr/png_ihdr.png` — 20.982 byte — MD5 `644b3891cd58d5e59444368405740e38`. Ảnh người cầm cờ **vàng**; chiều cao ảnh bị sửa sai → flag ở đáy bị cắt.

## Tóm tắt đề
Flag được **viết trong ảnh** nhưng **chiều cao** đã bị sửa sai trong chunk IHDR nên phần chứa flag bị cắt. Nhiệm vụ: khôi phục chiều cao đúng bằng cách **sửa binary PNG (IHDR)** rồi **tính lại CRC32**. Chiều cao gốc được giấu bằng **LSB**.

## Phân tích (chi tiết: offset/giá trị/CRC thật)
**Cấu trúc PNG:** chữ ký `89 50 4E 47 0D 0A 1A 0A` + các chunk `length(4)+type(4)+data+CRC(4)`. CRC32 tính trên `type+data`.

**Dump 50 byte đầu (xác minh thật bằng `xxd`):**
```
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452   .PNG........IHDR
00000010: 0000 027c 0000 022b 0806 0000 0075 6644   ...|...+.....ufD
00000020: 1900 ...                                  ..
```
Giải mã IHDR:
- offset `0x10`: **width = `00 00 02 7C` = 636**
- offset `0x14`: **height = `00 00 02 2B` = 555**
- offset `0x18`: bit depth `08`, color type `06` (RGBA)
- offset `0x1D`: **CRC IHDR lưu trong file = `75 66 44 19` = `0x75664419`**

**Dữ liệu LSB (kênh Red + Green vì màu vàng = R+G):** trích LSB bit0 → chuỗi `"The original height is 580 pixel"`. Vậy phải đổi height 555 → **580** (`0x244`).

Sửa 4 byte height tại offset `0x14`: `00 00 02 2B` → `00 00 02 44`. Việc này làm **sai CRC** → PNG báo hỏng → phải tính lại CRC IHDR.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **LSB extraction bit0 kênh R+G:** VÌ SAO: tông vàng ám chỉ Red+Green; chuỗi LSB cho biết chiều cao gốc chính xác (580), tránh đoán.
- **Hex edit chunk IHDR:** VÌ SAO: height nằm cố định tại offset `0x14` (big-endian 4 byte); sửa trực tiếp là nhanh nhất.
- **Tính lại CRC32 (`zlib.crc32`):** VÌ SAO: CRC tính trên `type+data`; không sửa CRC thì nhiều viewer từ chối mở.

## Lời giải chi tiết (bước + code sạch, đã kiểm chứng zlib.crc32)
1. Đọc kích thước + kiểm tra toàn vẹn:
   ```bash
   exiftool png_ihdr.png      # Image Size: 636 x 555
   pngcheck -v png_ihdr.png   # báo CRC/kích thước
   ```
2. Trích LSB kênh Red+Green (StegOnline/zsteg) → `The original height is 580 pixel`.
3. Sửa height + tính lại CRC bằng Python:
   ```python
   import zlib, struct
   d = bytearray(open("png_ihdr.png","rb").read())
   struct.pack_into(">I", d, 20, 580)              # ghi height=580 tại offset 0x14 (20)
   crc = zlib.crc32(d[12:29]) & 0xffffffff         # CRC trên type+data = d[12:29]
   struct.pack_into(">I", d, 29, crc)              # ghi CRC mới tại offset 0x1D (29)
   open("png_ihdr_fixed.png","wb").write(d)
   print(format(crc,"08x"))                        # -> 8cc4f996
   ```
4. Mở `png_ihdr_fixed.png` → đủ chiều cao 580 → flag ở đáy ảnh.

> Đã xác minh: CRC gốc `0x75664419` (đọc trực tiếp từ file), CRC sau khi đổi height=580 là `0x8cc4f996` — khớp `pngcheck` trong nguồn.

## Flag
flag{Broaden_your_horizons_to_find_the_FLAG!35}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** ảnh PNG "cụt" ở đáy/đỉnh, hoặc đề nói "dimensions altered / original height"; `pngcheck` báo lỗi CRC ở IHDR.
- **Quy trình:** (1) đọc kích thước hiện tại; (2) nếu có LSB (màu ám chỉ kênh) → trích lấy kích thước gốc; (3) sửa 4 byte height (hoặc width) trong IHDR; (4) tính lại CRC32 và ghi đè 4 byte CRC.
- **Công cụ:** xxd/HxD, exiftool, pngcheck, Python zlib.
- **Bẫy:** quên tính lại CRC → ảnh vẫn hỏng; nhầm byte width (đứng trước) vs height; phải dùng **big-endian** (580 → `00 00 02 44`); tăng height không đủ vẫn không lộ flag → dùng đúng giá trị LSB.
