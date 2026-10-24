# command-injection-find

- **Category:** Web (OS Command Injection)
- **File đề:** Đề online, không có file kèm. Mục tiêu: một web server nhận **hostname** và trả về kết quả lệnh `dig` (đóng gói `tar.gz`). *(Chú thích: PDF gốc tham chiếu tên nền tảng/giải — lược bỏ theo quy tắc trung tính.)*

## Tóm tắt đề
Web server nhận một hostname, chạy `dig <hostname>` phía server rồi trả kết quả (nén tar.gz). Trong server có giấu file chứa flag. Nhiệm vụ: khai thác chức năng resolve này để đọc flag.

Đặc tính bộ lọc đầu vào do đề nêu:
- Server **xóa toàn bộ phần input sau chuỗi `";| "`** (để chặn command injection).
- **Nhưng** server **bỏ qua ký tự `|`** nếu input có chứa **từ khóa `find`**.
- File flag tên **`4n5w3r.ini`**, nằm đâu đó dưới **`/etc`**.

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
Server ghép hostname người dùng vào lệnh shell dạng `dig <hostname>` rồi thực thi → đây là **OS Command Injection** qua tham số hostname.

Bộ lọc có **lỗ hổng logic**: nó cắt bỏ mọi thứ sau `";| "` để ngăn pipe/`;`, **nhưng nếu input chứa từ `find`** thì ký tự `|` được cho qua (không bị dùng làm điểm cắt). Đây là kiểu blacklist yếu có **ngoại lệ (allow-list keyword)** — rất dễ bypass: chỉ cần nhét `find` vào payload là `|` sống sót, từ đó nối thêm lệnh bằng pipe.

Kế hoạch khai thác (khóa thật):
- Giữ một hostname hợp lệ ở đầu để `dig` không chết sớm.
- Nối `| find /etc ... | xargs grep flag` — vừa chứa từ khóa `find` (qua filter), vừa liệt kê file dưới `/etc` rồi `grep` ra dòng flag.
- File đích cụ thể: `/etc/.../4n5w3r.ini`.

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **OS Command Injection** qua tham số hostname (input ghép vào lệnh `dig`).
- **Bypass filter bằng keyword miễn trừ:** filter cắt sau `";| "` nhưng miễn trừ khi có `find` → chủ ý dùng `find` để `|` không bị loại.
- **VÌ SAO nhận ra:** đề mô tả thẳng cơ chế lọc và cho sẵn mẫu payload — dấu hiệu kinh điển của command injection kèm một blacklist yếu có ngoại lệ keyword.
- **Công cụ:** trình duyệt / `curl`.

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. **Xác nhận** input hostname được đưa vào lệnh shell (`dig <hostname>`): thử một hostname hợp lệ, thấy kết quả `dig`.

2. **Dựng payload chứa `find`** để `|` sống sót, nối chuỗi lệnh đọc flag. Mẫu theo đề (thay "directory" bằng `/etc`):
   ```
   example.com | find /etc -type f | xargs grep flag
   ```
   Hoặc trỏ thẳng file đích (nhanh hơn, ít nhiễu):
   ```
   example.com | find /etc -name 4n5w3r.ini | xargs grep flag
   ```
   (`example.com` chỉ là một hostname resolve được để lệnh `dig` gốc không lỗi.)

3. **Gửi payload** vào ô hostname. Do có `find`, ký tự `|` được giữ lại → chuỗi pipe thực thi → `grep` trả dòng chứa `flag` từ `/etc/.../4n5w3r.ini`.

4. **Đọc kết quả** (nằm trong text/tar.gz server trả về) → flag.

Ví dụ bằng `curl` (tham số/endpoint tùy form thực tế):
```bash
curl -G 'http://<target>/' \
  --data-urlencode 'host=example.com | find /etc -name 4n5w3r.ini | xargs grep flag'
```

## Flag
flag{...}

*(Nguồn không nêu: PDF/`SOLUTIONS_VN.md` bài #34 ghi flag nằm trong `4n5w3r.ini` dưới `/etc` nhưng chỉ hiện trên server, không in nội dung. Flag thật có wrapper `flag{...}`.)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện command injection:** input đi vào một lệnh hệ thống (ping/dig/nslookup/convert/zip...). Thử ký tự nối lệnh: `;`, `|`, `||`, `&&`, `$(...)`, backtick, `%0a` (newline).
- **Khi có blacklist filter:** đọc kỹ quy tắc lọc, tìm **ngoại lệ/allow keyword** (ở đây: cho qua `|` khi có `find`). Filter cắt theo chuỗi cố định thường vỡ khi: chèn keyword miễn trừ, thêm space/escape, đổi thứ tự, dùng newline, dùng biến thể lệnh khác.
- **Đọc file khi không có output trực tiếp:** pipe sang `grep`/`xargs grep` theo mẫu flag (`grep -r flag /etc`), hoặc `find / -name '*flag*'`.
- **Công cụ:** curl/Burp Repeater để fuzz ký tự nối; blind command injection (time-based `sleep`, OOB qua DNS/HTTP) nếu không có output.
- **Bẫy:** filter cắt sau chuỗi cụ thể → đặt phần nguy hiểm trước điểm cắt hoặc kích hoạt ngoại lệ; URL-encode (`|`=`%7C`, space=`%20`); cần hostname hợp lệ ở đầu để lệnh gốc không chết sớm.
- **Checklist:** [ ] input vào lệnh shell? [ ] thử ký tự nối lệnh [ ] đọc kỹ ngoại lệ filter [ ] dùng keyword miễn trừ (`find`) [ ] pipe sang `grep flag` trên `/etc` [ ] đọc kết quả.
