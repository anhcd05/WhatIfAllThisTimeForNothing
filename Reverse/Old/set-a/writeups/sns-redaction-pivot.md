# sns-redaction-pivot

- **Category:** OSINT (nguồn ghi MISC/OSINT)
- **File đề:** không có file — điều tra tài khoản X (Twitter) `@Mark54666780228`. Flag format: `flag{mail:Skype_username:domain}` (mọi chữ trong ngoặc là chữ thường).

## Tóm tắt đề
Tài khoản X `@Mark54666780228` bị nghi dính líu lừa đảo tiền mã hóa. Nhiệm vụ: điều tra để tìm người đứng sau, ghép 3 thành phần: (1) email liên kết tài khoản; (2) username Skype gắn email đó; (3) domain website người này quảng bá.

## Phân tích (chi tiết: 3 bước pivot thật)
1. **Tweet → Dropbox → PDF.** Lướt tweet của tài khoản → gặp một tweet chứa **link Dropbox** → tải **PDF**. PDF có các khối **bị bôi đen (blackout)** che thông tin.
2. **Bỏ che bằng đổi định dạng.** Khối "bôi đen" chỉ là hình chữ nhật đen **đè lên** chữ (không flatten, không xóa text layer bên dưới). Chuyển **PDF → PowerPoint** (ví dụ Adobe online) → di chuyển/xóa ô đen → lộ **email: `hiropi1991tanapon@gmail.com`**.
3. **Email → Skype.** Tra email bằng công cụ OSINT (EPIEOS / PredictaSearch / Vedbex email2skype) → Skype username: **`enj0y555crypt0`**.
4. **Pivot alias → YouTube → domain.** Lấy alias đặc trưng `hiropi1991tanapon` (từ email) tìm trên nền tảng khác. Một tweet cho biết chủ muốn mở kênh YouTube → tìm ra `https://www.youtube.com/@hiropi1991tanapon`; đọc kỹ **mô tả kênh** thấy domain quảng bá: **`h00r@y-g00d-j0b.com`**.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Redaction defeat (PDF → PPTX/SVG):** VÌ SAO: che bằng hình đè không xóa text layer → đổi định dạng linh hoạt là lộ chữ bên dưới. Đây là lỗi bảo mật kinh điển — đừng tin "đã che".
- **Email-to-Skype OSINT (EPIEOS/Vedbex/PredictaSearch):** VÌ SAO: email Microsoft/Skype thường ánh xạ tới hồ sơ Skype công khai.
- **Alias pivoting:** VÌ SAO: người dùng hay tái sử dụng một alias độc nhất (`hiropi1991tanapon`) trên nhiều nền tảng → lần ra tài khoản khác cùng chủ (YouTube) chứa domain.

## Lời giải chi tiết (bước)
1. Đọc hết timeline/bio/media/link của `@Mark54666780228`, lần ra tweet có link Dropbox → tải PDF.
2. Với PDF có vùng che: thử copy text, hoặc chuyển PDF→PPTX/DOCX/SVG (`pdftotext`/Adobe online) → kéo/xóa khối đen → lộ `hiropi1991tanapon@gmail.com`.
3. Tra email bằng EPIEOS (hoặc holehe/Vedbex email2skype) → Skype `enj0y555crypt0`.
4. Lấy alias `hiropi1991tanapon` pivot sang YouTube (Sherlock/WhatsMyName để quét) → đọc description kênh → domain `h00r@y-g00d-j0b.com`.
5. Ghép (toàn chữ thường theo format).

## Flag
flag{hiropi1991tanapon@gmail.com:enj0y555crypt0:h00r@y-g00d-j0b.com}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** đề cho một handle mạng xã hội + nhiều mảnh thông tin cá nhân (email/Skype/domain); hint "khối bị bôi đen" và "alias ngộ nghĩnh".
- **Quy trình:** (1) đọc hết timeline/bio/media/link, lần file đính kèm (Dropbox/Drive); (2) PDF có vùng che → copy text / PDF→PPTX/SVG / `pdftotext` để bóc; (3) có email → EPIEOS/holehe/email2skype tìm dịch vụ liên kết; (4) lấy alias độc nhất pivot sang YouTube/GitHub, đọc bio/description lấy domain.
- **Công cụ:** X/Twitter, Adobe PDF↔PPTX, EPIEOS, PredictaSearch, Vedbex, holehe, Sherlock/WhatsMyName.
- **Bẫy:** redaction "đen" thường không an toàn → luôn thử bóc; đừng dừng ở email, phải pivot tiếp bằng alias; domain nằm trong **mô tả kênh** YouTube chứ không ở tweet.
