# qr-shares

- **Category:** Crypto / Stego / Web (visual secret sharing → QR → S3 SSE-C)
- **File đề:** `challenges/qr-shares/index.html` (15.751 byte, md5 `a37b52803a0676fef598729f46fedbc3`), `description.txt`. Kèm `extract_decode.py` (script giải tham khảo). Phân tích tĩnh; không fetch internet.

## Tóm tắt đề

`description.txt` dẫn dắt về AES và "một file HTML bí ẩn nhiều lớp mã hoá". File `index.html` vẽ một **bảng 4 ô**, mỗi ô là một **ảnh PNG nhúng base64** (`data:image/png;base64,...`) trông như **QR bị nhiễu**. Trang còn có link **`fetch.php`** ("Go to Download Page"). Phải gộp 4 ảnh share → khôi phục QR → ra URL S3 → vượt **SSE-C** qua proxy `fetch.php` để đọc file `.txt` chứa flag.

## Phân tích (chi tiết: khóa/offset/hằng số thật)

**1) Cấu trúc HTML (xác nhận tĩnh).** Phần khung (bỏ các blob base64):
```html
<title>What is this?</title>
<style>
  table { border-collapse: collapse; }
  td    { width:100px; height:100px; }
  .bg1,.bg2,.bg3,.bg4 { width:100px; height:100px; background-size: cover; }
  .bg1 { background-image: url("data:image/png;base64,<...>") }
  .bg2 { ... }  .bg3 { ... }  .bg4 { ... }
</style>
<a href="fetch.php" ...>Go to Download Page</a>
<table ...><tr>
  <td><div class="bg1"></div></td> ... <td><div class="bg4"></div></td>
</tr></table>
```
Đếm được chính xác:
- `grep -o "data:image" index.html | wc -l` → **4** ảnh nhúng.
- 4 lớp CSS `.bg1 .bg2 .bg3 .bg4` (mỗi ô một ảnh, mỗi ô 100×100).
- **1** tham chiếu `fetch.php` (link tải, chính là proxy).

Mỗi `data:image/png;base64,...` giải ra một PNG xám **100×100 nhìn như QR đầy hạt nhiễu** → không ô nào quét được riêng lẻ. Đây là **visual secret sharing / QR multi-share**: QR thật bị tách thành 4 share nhiễu, chỉ gộp đúng mới hiện QR.

**2) Vì sao phải gộp.** Mỗi share đơn lẻ không mang đủ thông tin (nhiễu che module QR). Vì không biết trước phép gộp đúng, cách chắc ăn là **brute nhiều biến thể** rồi để OpenCV tự quét.

**3) Kết quả QR (từ lần chạy gốc).** Biến thể `var_14.png` giải ra URL object S3:
```
https://<redacted-bucket>.s3.us-east-2.amazonaws.com/ltnytc9p84wy8pcw8y4tc.txt
```
(Tên bucket chứa tên kỳ thi CTF nên đã REDACT thành `<redacted-bucket>`; đường dẫn object `ltnytc9p84wy8pcw8y4tc.txt` giữ nguyên.)

**4) Rào SSE-C.** GET thẳng URL thất bại vì object lưu bằng **SSE-C** (Server-Side Encryption with Customer-provided key, AES-256):
```
InvalidRequest: The object was stored using a form of Server Side Encryption.
The correct parameters must be provided to retrieve the object.
```
SSE-C bắt buộc gửi lại khóa AES-256 qua header `x-amz-server-side-encryption-customer-{algorithm,key,key-MD5}`; GET trần không có khóa nên bị từ chối.

**5) Lối đi hợp lệ = proxy `fetch.php`.** Link "Go to Download Page" trỏ `fetch.php` — endpoint server-side đã **cầm sẵn khóa SSE-C đúng**, gọi S3 hộ và trả nội dung đã giải mã. Đây là cơ chế bypass SSE-C mà đề thiết kế để lấy `.txt` chứa flag.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Trích ảnh base64 từ data-URI:** regex `data:image/...;base64,(...)` → decode ra PNG. VÌ SAO: ảnh nằm inline trong HTML, không có file rời.
- **Image combination để khôi phục QR:** gộp pixel-wise 4 share bằng **median / min / max / XOR bit / std / tổng chênh lệch**, kèm median filter, threshold, invert, upscale NEAREST 1.5×/2×/3×. VÌ SAO nhiều phép: không biết trước luật tách share, brute rộng rồi để detector lọc giúp.
- **Tự quét QR bằng `cv2.QRCodeDetector`:** `detectAndDecode()` chạy trên mọi biến thể. VÌ SAO: tự động hoá, tránh soi mắt từng ảnh.
- **Hiểu SSE-C + proxy:** VÌ SAO then chốt: không có khóa thì không GET được; `fetch.php` là chỗ duy nhất cầm khóa → mấu chốt bài là tìm proxy, không phải "bẻ" AES.

## Lời giải chi tiết (bước + code/lệnh sạch, chạy lại được)

```python
# Bước 1 — trích 4 ảnh base64 từ index.html
import re, base64
from pathlib import Path

html = Path("index.html").read_text(encoding="utf-8")
pat  = re.compile(r"data:image/[^;]+;base64,([A-Za-z0-9+/=]+)")
for i, m in enumerate(pat.findall(html), 1):
    Path(f"img{i}.png").write_bytes(base64.b64decode(m))   # img1.png..img4.png
```

```python
# Bước 2 — sinh biến thể khử nhiễu + gộp 4 ảnh (trích từ extract_decode.py)
import numpy as np
from PIL import Image, ImageOps, ImageFilter

imgs = [Image.open(f"img{i}.png").convert("L") for i in range(1, 5)]
arrs = [np.array(im, np.uint8) for im in imgs]
stack = np.stack(arrs, 0)

variants = []
for im in imgs:                                  # per-image
    v = im.filter(ImageFilter.MedianFilter(3))
    variants += [v, ImageOps.invert(v), v.point(lambda x: 255 if x > 128 else 0)]
variants += [Image.fromarray(np.median(stack,0).astype(np.uint8)),  # cross-image
             Image.fromarray(np.max(stack,0)),
             Image.fromarray(np.min(stack,0)),
             Image.fromarray(np.bitwise_xor.reduce(stack,0))]
# + std/diff chuẩn hoá 0..255, rồi upscale NEAREST 1.5x/2x/3x mỗi biến thể
```

```python
# Bước 3 — quét QR tự động trên mọi biến thể
import cv2
det = cv2.QRCodeDetector()
for v in variants:                                # v -> lưu .png hoặc convert ndarray
    img = cv2.cvtColor(np.array(v.convert("RGB")), cv2.COLOR_RGB2BGR)
    data, _, _ = det.detectAndDecode(img)
    if data:
        print("DECODED:", data)                   # -> URL S3 .../ltnytc9p84wy8pcw8y4tc.txt
        break
```

```bash
# Chạy pipeline sẵn có của đề:
uv run extract_decode.py
#   Found 4 embedded images
#   Saved: img1.png, img2.png, img3.png, img4.png
#   DECODED from var_14.png: https://<redacted-bucket>.s3.us-east-2.amazonaws.com/ltnytc9p84wy8pcw8y4tc.txt
```

```
# Bước 4 — lấy nội dung object (object dùng SSE-C):
#   - GET trực tiếp -> InvalidRequest (thiếu khóa khách).
#   - Đi qua proxy fetch.php (link "Go to Download Page"): server tự gắn header
#     x-amz-server-side-encryption-customer-{algorithm,key,key-MD5} và trả .txt chứa flag.
```

## Flag

```
flag{...}
```

(Nguồn không nêu — flag host trên S3 đã gỡ. Writeup gốc chỉ xác nhận tới: 4 share → gộp → QR → URL S3 → cần `fetch.php` vượt SSE-C → đọc `.txt`. Không thể lấy lại chuỗi flag cuối bằng phân tích tĩnh hiện có.)

## Gặp lại thì xử lý thế nào (playbook)

- **Dấu hiệu nhận diện:** HTML/tài nguyên nhúng **nhiều ảnh base64 cùng cỡ** "gần giống QR nhưng đầy nhiễu" → nghĩ ngay **visual secret sharing / QR multi-share**. Mô tả nhắc AES thường chỉ là flavor.
- **Quy trình:**
  1. `grep data:image...;base64,` trích hết ảnh nhúng, decode ra file.
  2. Gộp pixel-wise nhiều phép (XOR/AND/OR/min/max/median/diff/std) + threshold/invert/upscale; quét mỗi biến thể bằng OpenCV `QRCodeDetector` (hoặc `zbarimg`).
  3. QR thường trỏ URL (S3/pastebin...). Thử GET.
  4. Nếu GET lỗi **SSE/InvalidRequest/cần tham số đặc biệt** → tìm **proxy/endpoint khác cùng site** (vd `fetch.php`) được giao nhiệm vụ lấy object hộ (đã cầm sẵn khóa).
- **Bẫy hay gặp:** cố quét từng ảnh lẻ (không ra); quên invert/threshold; GET thẳng S3 rồi tưởng URL sai (thực ra dính SSE-C); bỏ qua link phụ `fetch.php` — chính là chìa khoá bypass.
- **Checklist:** trích ảnh? gộp pixel? quét QR? ra URL? GET lỗi SSE? → tìm proxy nội bộ cầm khóa.
