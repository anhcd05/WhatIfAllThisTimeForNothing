# nested-archives

- **Category:** OSINT
- **File đề:** `ctf/osint/nested-archives.zip` — 3.073.886 byte — MD5 `850eb0bebed17952186d92c9351f7245`. Chuỗi ZIP lồng nhau (xác minh thật: lớp ngoài không mã hóa, chứa `Pase2/Phase3.zip` + `Pase2/README.txt`), mỗi lớp trong cần một mật khẩu tìm bằng OSINT.

## Tóm tắt đề
File nén lồng nhiều lớp; mỗi lớp khóa bằng mật khẩu khác nhau, mỗi mật khẩu là đáp án một câu đố OSINT về Nhật Bản (ghi trong `README.txt` từng lớp). Giải lần lượt 3 lớp tới `flag.zip`; bên trong là `flag.lnk` không mở trực tiếp được → đọc URL trong shortcut → tra **Wayback Machine** → **Base64-decode** nội dung `flag.txt`.

## Phân tích (chi tiết: 3 mật khẩu + lớp cuối)
**Lớp 1 — "Name-City/Town/Village":** nơi sinh & lớn lên của nhân vật trên **tờ 10.000 yên mới nhất** của Nhật (phát hành 2024) = **Eiichi Shibusawa** ("cha đẻ của chủ nghĩa tư bản Nhật Bản"), sinh & lớn lên tại **Fukaya City**, tỉnh Saitama.
→ **Mật khẩu 1: `Fukaya-City`**
- Lưu ý: ZIP mã hóa **AES-256** → Windows Explorer không mở được (báo "sai mật khẩu" dù đúng) → dùng **7-Zip**.

**Lớp 2 — "SHoPing-LOCATION" (giữ nguyên hoa/thường theo thương hiệu):** đọc `README.txt` lớp 2 — tên cơ sở thương mại trong tòa trụ sở của một hãng (JR Shinjuku Miraina Tower) = khu mua sắm **NEWoMan** (Shinjuku).
→ **Mật khẩu 2: `NEWoMan-SHINJUKU`**

**Lớp 3 — "Land-Mark":** `README.txt` lớp 3 hỏi landmark **ở trung tâm của 4 địa điểm**. Trong thư mục có 4 ảnh, mỗi ảnh nhúng **GPS EXIF**:
- Point1 `35.693348, 139.727006` (gần Ichigaya Garrison)
- Point2 `35.640860, 139.757273` (gần Rainbow Bridge)
- Point3 `35.660016, 139.701081` (gần Shibuya Station)
- Point4 `35.664450, 139.804633` (gần BMW Kiba-SC)
- Chấm 4 toạ độ lên bản đồ → trung tâm là **Tokyo Tower**.
→ **Mật khẩu 3: `Tokyo-Tower`**

**Lớp cuối — flag.lnk + Wayback:** giải nén `flag.zip` ra `flag.lnk` (shortcut chết link). Đọc URL target trong `.lnk`, tra Wayback Machine; bản lưu trữ dạng:
```
https://web.archive.org/web/20240930060737/https://<redacted-ctf-repo>.s3.ap-southeast-1.amazonaws.com/OSINT0/flag.txt
```
Nội dung `flag.txt` là **Base64** → decode (CyberChef From Base64) ra flag.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **OSINT tri thức phổ thông (tiền giấy, trụ sở, landmark):** VÌ SAO: các câu "common knowledge" xác minh nhanh, dùng làm mật khẩu; giữ đúng format hoa/thường + dấu `-`.
- **7-Zip cho ZIP AES-256:** VÌ SAO: bộ giải nén tích hợp Windows không hỗ trợ AES-256 → báo lỗi sai dù mật khẩu đúng.
- **EXIF GPS + bản đồ (exiftool):** VÌ SAO: mật khẩu là tên hình học (trung tâm) của tập toạ độ.
- **Wayback Machine:** VÌ SAO: tài nguyên `.lnk` trỏ tới đã bị gỡ; bản lưu trữ còn giữ `flag.txt`.

## Lời giải chi tiết (bước + lệnh sạch)
1. `7z x nested-archives.zip` → đọc `README.txt`, nhập **`Fukaya-City`** cho lớp 2.
2. Giải lớp 2 → đọc `README.txt` → nhập **`NEWoMan-SHINJUKU`** cho lớp 3.
3. Giải lớp 3 → `exiftool *.jpg` lấy 4 GPS → chấm Google Maps → trung tâm = Tokyo Tower → nhập **`Tokyo-Tower`**.
4. Giải `flag.zip` → `flag.lnk`. Lấy URL target:
   ```bash
   strings flag.lnk        # hoặc đọc thuộc tính shortcut / lnkinfo
   ```
5. Tra URL trên Wayback Machine → tải `flag.txt` → `base64 -d` (hoặc CyberChef From Base64) → flag.

## Flag
flag{...}

> **Nguồn không nêu.** Lời giải gốc dừng ở bước "decode Base64 bằng CyberChef" mà **không in giá trị flag cuối** (nội dung `flag.txt` nằm trên Wayback, không có trong repo). Quy trình đã đủ để tự tái tạo. Ba mật khẩu đã xác định chắc: `Fukaya-City`, `NEWoMan-SHINJUKU`, `Tokyo-Tower`.

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** file nén lồng nhiều lớp, mỗi `README.txt` nêu một câu đố OSINT làm mật khẩu; ảnh kèm EXIF; shortcut `.lnk` chết link.
- **Quy trình:** giải từng lớp → đọc README biết câu hỏi tiếp → tra OSINT → nhập mật khẩu đúng format. Lớp ảnh: `exiftool` lấy GPS, chấm bản đồ. `.lnk` chết: lấy target URL rồi tra Wayback/urlscan. Lớp cuối thường còn 1 lớp Base64.
- **Công cụ:** 7-Zip, exiftool, Google Maps, Wayback Machine, CyberChef.
- **Bẫy:** ZIP AES-256 phải dùng 7-Zip; format mật khẩu phải khớp y hệt (hoa/thường thương hiệu, dấu `-`); đừng cố mở `.lnk`, hãy đọc target; nội dung cuối còn Base64.
