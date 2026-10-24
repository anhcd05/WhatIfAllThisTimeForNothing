# fuzzy-match

- **Category:** Forensic
- **File đề:** `fuzzy-match/Fuzzy_8648...exe` (102391 bytes; md5 thật `2f43c14cad2db191775275104f06896d`; **tên file là sha256**) và `fuzzy-match/Fuzzy_b863...zip` (1233549 bytes). ⚠️ README trong repo **rỗng** — không có lời giải sẵn; nội dung dưới đây là phân tích tĩnh/định hướng theo SOLUTIONS_VN.md.

## Tóm tắt đề

Repo không kèm mô tả. Tên bài "Fuzzy" gần như chắc chắn ám chỉ **fuzzy hashing** — kỹ thuật đo *độ tương đồng* giữa các file, khác hẳn md5/sha (so khớp **chính xác**).

## Phân tích (chi tiết)

**Fuzzy hashing** (ví dụ **ssdeep** — Context Triggered Piecewise Hashing, hoặc **TLSH**) sinh ra một "chữ ký" sao cho hai file *gần giống nhau* có hash *gần giống nhau*, cho ra **điểm tương đồng 0–100**. Dùng để phát hiện biến thể malware, file bị sửa nhẹ, tài liệu gần trùng — những trường hợp mà md5/sha hoàn toàn vô dụng (chỉ cần khác 1 byte là hash khác hẳn).

Bố cục đề (một `.exe` + một `.zip` lớn ~1.2MB) gợi ý: file zip chứa **nhiều biến thể** của chương trình/file, và nhiệm vụ là tìm file **đồng dạng nhất** với mẫu (hoặc tìm cặp gần giống nhau). File đồng dạng đó chính là đáp án hoặc chứa flag.

Vì README rỗng, không có bằng chứng để khẳng định flag; chỉ nêu hướng xử lý tĩnh.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **`ssdeep` so khớp mờ.** *Vì sao:* bài tên "Fuzzy" → fuzzy hashing là công cụ đúng để xếp hạng độ giống giữa nhiều file.
2. **Giải nén zip vào thư mục cách ly.** *Vì sao:* file là mẫu không tin cậy; mở trong thư mục riêng, không chạy.
3. **`file`/`strings` trên từng file.** *Vì sao:* xác định loại và soi chuỗi flag/gợi ý nếu có.

## Lời giải chi tiết (bước + code/lệnh sạch)

```bash
mkdir fuzzy_extract && cd fuzzy_extract
unzip ../Fuzzy_b863*.zip                 # giải nén vào thư mục riêng

# Tính fuzzy hash cho tất cả rồi tìm cặp/file giống nhau nhất:
ssdeep -r . > hashes.txt
ssdeep -d -r .                           # in các cặp file tương đồng + điểm
# hoặc so từng file với mẫu .exe:
ssdeep -m hashes.txt ../Fuzzy_8648*.exe

# soi từng ứng viên:
file *; strings -n 6 <file_dong_dang> | grep -i flag
```

File có điểm tương đồng cao nhất là ứng viên chứa đáp án; đọc nội dung/so sánh để trích flag.

## Flag

flag{...}  *(nguồn không nêu — README repo rỗng, SOLUTIONS_VN.md không ghi flag cho bài này; cần có file để chạy `ssdeep` và xác định.)*

## Gặp lại thì xử lý thế nào (playbook)

1. Tên bài/đề nhắc "fuzzy", "similar", "gần giống" → dùng **fuzzy hashing** (`ssdeep`, `tlsh`, `sdhash`), không dùng md5/sha.
2. Giải nén tập file → `ssdeep -d -r .` để xếp cặp tương đồng, hoặc `-m` so với mẫu.
3. File giống nhất thường là biến thể "sạch/đúng" → so byte (`cmp`, `vbindiff`) với mẫu để tìm phần khác biệt (nơi giấu flag).
4. Luôn thao tác trong thư mục cách ly; không chạy `.exe` lạ — chỉ `strings`/VM nếu cần.
