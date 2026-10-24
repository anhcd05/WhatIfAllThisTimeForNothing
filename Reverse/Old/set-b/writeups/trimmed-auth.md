# trimmed-auth

- **Category:** MISC
- **File đề:** không còn trong repo. ⚠️ README trong repo **rỗng** — không có lời giải sẵn; nội dung dưới đây là định hướng theo SOLUTIONS_VN.md.

## Tóm tắt đề

Repo không kèm mô tả. Tên bài gốc "Trim Auth" gợi ý lỗ hổng **so khớp xác thực sau khi trim/chuẩn hóa chuỗi**: token hoặc username bị `trim()` khoảng trắng (hoặc cắt độ dài) khiến hai giá trị *khác nhau* bị coi là *bằng nhau*, dẫn tới bypass đăng nhập.

## Phân tích (chi tiết)

"Trim" trong ngữ cảnh auth thường dẫn tới một trong các lớp lỗi sau:

- **Trim rồi so sánh:** server làm `if (trim(input) == stored)` hoặc chuẩn hóa (lowercase, bỏ khoảng trắng, NFKC) **trước** khi so sánh. Kẻ tấn công thêm khoảng trắng đầu/cuối, ký tự zero-width, hoặc biến thể Unicode để qua được kiểm tra "trùng khớp" dù giá trị gốc khác.
- **Cắt độ dài (truncation):** CSDL cột `VARCHAR(n)` cắt bớt chuỗi khi lưu; `admin` + nhiều khoảng trắng + ký tự thừa bị cắt về `admin` → tạo tài khoản trùng/chiếm quyền (SQL truncation attack kinh điển).
- **Chuẩn hóa Unicode:** `ＡＤＭＩＮ` (fullwidth) hoặc `Admın` (dotless i) sau NFKC/lowercase hóa thành `admin`.
- **Null byte / newline trim** làm phần sau bị bỏ, khiến so sánh lệch.

Flag nhiều khả năng lấy được sau khi **bypass đăng nhập** vào tài khoản đặc quyền (admin) nhờ một trong các lỗi trên.

Vì README rỗng và không có file/endpoint, không thể khẳng định flag.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **Thử khoảng trắng/ký tự vô hình quanh input.** *Vì sao:* nếu server trim trước khi so, `"admin "`/`" admin"`/`"ad\tmin"` có thể qua được.
2. **SQL truncation attack.** *Vì sao:* nếu cột bị giới hạn độ dài, `admin` + padding tạo bản sao chiếm quyền.
3. **Biến thể Unicode (fullwidth, homoglyph, NFKC).** *Vì sao:* chuẩn hóa có thể gập chúng về chuỗi admin.
4. **Phân tích tĩnh source nếu có.** *Vì sao:* tìm chỗ gọi `trim`/`normalize`/`substr` trước phép so sánh để xác định vector chính xác.

## Lời giải chi tiết (bước + code/lệnh sạch)

```bash
# (định hướng — cần endpoint/source thật)

# 1) Nếu có source: tìm chỗ trim/normalize trước khi so sánh
grep -rniE 'trim\(|strip\(|normalize|toLowerCase|substr|VARCHAR' .

# 2) Thử padding khoảng trắng / ký tự vô hình:
curl -d 'user=admin%20&pass=...'        http://TARGET/login     # trailing space
curl -d 'user=%20admin&pass=...'        http://TARGET/login     # leading space
# zero-width: user=admin%E2%80%8B

# 3) SQL truncation: đăng ký 'admin' + nhiều khoảng trắng + 'x'
#    nếu cột VARCHAR cắt -> tạo trùng 'admin'

# 4) Unicode: user=%EF%BD%81%EF%BD%84%EF%BD%8D%EF%BD%89%EF%BD%8E  (ＡＤＭＩＮ fullwidth)
```

## Flag

flag{...}  *(nguồn không nêu — README repo rỗng, không có file/endpoint; SOLUTIONS_VN.md không ghi flag cho bài này.)*

## Gặp lại thì xử lý thế nào (playbook)

1. Thấy "trim/normalize auth" → nghi **chuẩn hóa-trước-khi-so-sánh** tạo ra va chạm giá trị.
2. Thử lần lượt: khoảng trắng đầu/cuối, tab/newline, zero-width (`​`), fullwidth/homoglyph, hoa-thường.
3. Nếu có đăng ký tài khoản → thử **SQL truncation** (padding để trùng tên admin sau khi bị cắt).
4. Có source → `grep` các hàm `trim/strip/normalize/substr/lower` ngay trước `==`/`strcmp`/truy vấn DB.
5. Mục tiêu là chiếm tài khoản đặc quyền để lộ flag; kiểm cả so sánh **loose** (`==` vs `===`) đi kèm.
