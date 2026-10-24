# lsb-half

- **Category:** Steganography
- **File đề:** `ctf/stego/lsb-half/hidden.pdf` — 26.423 byte — MD5 `24069fa3fcd5a9cea169eae0201d88e7`. Tên `.pdf` nhưng thực chất là **PNG** bị đặt sai đuôi.

## Tóm tắt đề
Cho file tên `hidden.pdf` nhưng "ẩn bên dưới" là ảnh. Bước đầu: nhận ra file thật là PNG → đọc như ảnh. Sau đó phân tích pixel: vùng bút dạ (marker) đỏ che chữ đen có sắc độ **hơi khác nhau** → dữ liệu giấu trong LSB; dùng kỹ thuật **LSB Half** để lộ flag.

## Phân tích (chi tiết: magic/kỹ thuật thật)
**Kiểm tra magic (xác minh thật bằng `xxd`):**
```
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452   .PNG........IHDR
```
→ `89 50 4E 47 0D 0A 1A 0A` = **chữ ký PNG**. Đuôi `.pdf` chỉ để đánh lừa; đuôi file không quyết định định dạng (magic number mới quyết định).

- Trong ảnh có chữ đen bị **bút đỏ bôi che**; sắc đỏ ở các vùng **hơi khác nhau** → pixel đã bị sửa để giấu dữ liệu (redaction giả — dữ liệu vẫn còn trong pixel).
- Kỹ thuật trích: **LSB Half** (StegOnline) — một chế độ đọc bit thấp để tách phần dữ liệu ẩn khỏi màu "trang trí". Có thể thay bằng xem bit-plane thấp kênh Red trong StegSolve/aperisolve.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Kiểm magic number (`file`/`xxd | head`):** VÌ SAO: phát hiện PNG giả `.pdf`; tin đuôi file là bẫy kinh điển.
- **Convert/đọc đúng PNG (ImageMagick):** VÌ SAO: trình xem PDF sẽ báo lỗi; cần đọc như ảnh để phân tích pixel.
- **StegOnline "LSB Half" (hoặc bit-plane thấp kênh Red):** VÌ SAO: "màu marker hơi khác" = dữ liệu nhúng LSB; chỉ nhìn mắt vùng che đỏ sẽ không thấy chữ.

## Lời giải chi tiết (bước + lệnh sạch)
1. Xác định định dạng thật:
   ```bash
   file hidden.pdf
   xxd hidden.pdf | head        # 89 50 4E 47 0D 0A 1A 0A -> PNG
   ```
2. Đọc đúng dạng PNG:
   ```bash
   convert hidden.pdf marker.png      # hoặc: cp hidden.pdf marker.png
   ```
3. Quan sát ảnh: chữ đen bị bút đỏ che, sắc đỏ chỗ khác nhau → pixel đã sửa.
4. Phân tích LSB:
   - StegOnline: upload `marker.png` → chọn chế độ **"LSB Half"** → nội dung ẩn (text dưới marker) hiện ra, chứa flag.
   - (Tùy chọn) StegSolve/aperisolve: xem bit-plane thấp kênh Red.

## Flag
flag{M4rker_f4iled}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** file không mở được đúng đuôi → luôn kiểm tra magic number; hint "màu hơi khác", "bôi che", "đừng tin mắt" → nghĩ tới LSB/bit-plane.
- **Quy trình:** (1) `file` + hex header xác định định dạng thật, sửa đuôi/convert; (2) mở ảnh, xem vùng che/màu bất thường; (3) duyệt bit-plane thấp từng kênh (StegOnline "LSB Half", StegSolve, aperisolve, zsteg).
- **Công cụ:** file/xxd, ImageMagick, StegOnline, StegSolve, aperisolve, zsteg.
- **Bẫy:** tin vào đuôi file; "LSB Half" ≠ "LSB bit0 full" → thử nhiều chế độ hiển thị bit; chỉ nhìn mắt vùng đỏ.
