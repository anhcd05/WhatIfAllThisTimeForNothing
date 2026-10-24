# captcha-ocr

- **Category:** Web
- **File đề:** target `10.3.204.204`. Repo kèm `captcha-ocr/captcha.py` (2664 bytes, Python 2 — script giải) + README rỗng. Phải giải CAPTCHA **đúng 1000/1000 lần liên tiếp** để server trả flag.

## Tóm tắt đề

Server ra CAPTCHA ảnh text; phải trả lời đúng 1000 lần liên tiếp mới nhận flag. Giải pháp: **tự động hóa OCR** đọc ảnh CAPTCHA, **hiệu chỉnh các lỗi OCR có hệ thống**, và loại bỏ các ảnh dễ sai để giữ chuỗi đúng không đứt.

## Phân tích (chi tiết)

**Nền tảng.** CAPTCHA yếu (ảnh text rõ) có thể bẻ bằng OCR tự động. Script `captcha.py` dùng **`gocr`** (OCR mã nguồn mở) đọc ảnh `/image`, hiệu chỉnh ký tự dễ nhầm, rồi POST đáp án tới `/challenge`. Vì cần 1000 lần đúng liên tiếp, độ chính xác phải rất cao → phải "sửa" lỗi OCR thường gặp.

Đọc `captcha.py`, luồng xử lý:
1. Lặp 1000 lần; mỗi lần GET `/image`, lưu `tmp.png`.
2. `gocr -l 0 -i tmp.png > result.txt` → đọc kết quả OCR.
3. Hiệu chỉnh: bỏ space, `_`→`Q`, `f`→`F`; nếu có `O`/`0` thì **bỏ ảnh, lấy ảnh khác** (vì gocr hay sai cặp này → tránh đoán sai làm đứt chuỗi).
4. POST `captcha` tới `/challenge`, đọc điểm `<h2>x/1000</h2>`; nếu `1000/1000` → in flag; nếu `0/1000` → mở ảnh cho người kiểm tra và thoát.

Mấu chốt: **tự động + sửa lỗi OCR có hệ thống** — tác giả quan sát các cặp gocr hay nhầm rồi hard-code quy tắc thay thế, đồng thời **loại** các ảnh mà OCR dễ sai (chứa O/0). Nhờ đó đạt 1000/1000.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **OCR tự động (`gocr`)** — VÌ CAPTCHA tập ký tự giới hạn, ảnh rõ → máy đọc được, không cần người.
- **Hiệu chỉnh ký tự + loại ảnh dễ sai** — VÌ 1000/1000 liên tiếp đòi độ chính xác gần tuyệt đối; sửa lỗi quen (`_`→`Q`, `f`→`F`) và bỏ ảnh có `O`/`0` giữ chuỗi không đứt.
- **Giữ phiên hợp lệ (cookie/CSRF FuelPHP)** — VÌ server dùng FuelPHP; thiếu `fuel_csrf_token`/`fuelcid` sẽ bị từ chối.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

```
1) Lấy session hợp lệ (cookie fuel_csrf_token, fuelcid từ trình duyệt/Burp) — ứng dụng FuelPHP.
2) Cập nhật cookie/CSRF mới vào captcha.py (giá trị trong repo đã hết hạn).
3) Chạy script (cần Python 2 + gocr + requests):
   python2 captcha.py
   Vòng lặp: GET /image -> gocr -l 0 -i tmp.png -> hiệu chỉnh (_->Q, f->F; bỏ ảnh có O/0)
             -> POST /challenge với đáp án -> đọc <h2>x/1000</h2>
4) Khi đạt 1000/1000, server in flag trong response.
```

Lưu ý: script là **Python 2** (`print "..."`). Có thể port sang Python 3 và thay `gocr` bằng `tesseract` + tiền xử lý ảnh (nhị phân hóa, khử nhiễu bằng OpenCV) để chính xác hơn.

## Flag

```
flag{...}
```

**Nguồn không nêu** — flag chỉ xuất hiện runtime khi đạt 1000/1000 trên server; `README.md` rỗng và `SOLUTIONS_VN.md` không ghi flag. Bài học: CAPTCHA yếu bị OCR tự động bẻ.

## Gặp lại thì xử lý thế nào (playbook)

1. CAPTCHA ảnh rõ + yêu cầu nhiều lần đúng ⇒ tự động hóa OCR, không giải tay.
2. Quan sát các cặp ký tự OCR hay nhầm → hard-code quy tắc sửa; loại bỏ ảnh dễ sai để giữ streak.
3. Giữ đúng phiên/CSRF (FuelPHP: `fuel_csrf_token`, `fuelcid`); token hết hạn phải lấy mới.
4. `gocr` kém thì dùng `tesseract` + tiền xử lý OpenCV (threshold, denoise, resize).
5. Nếu bị rate-limit, thêm delay giữa request.
