# waf-bypass

- **Category:** Web
- **File đề:** không có trong repo (`README.md` rỗng, không file đề). Tên bài gốc "WAF". Đây là bài Web điểm cao nhất của set (250đ).

## Tóm tắt đề

Bài Web 250đ. Repo **không có lời giải và không có file đề**. Tên "WAF" (Web Application Firewall) chỉ rõ đây là bài **bypass WAF** để khai thác một lỗ hổng (SQLi/XSS/RCE) vốn bị firewall chặn. Phần dưới là kiến thức nền + playbook các kỹ thuật bypass.

## Phân tích (chi tiết)

WAF chặn request dựa trên chữ ký/pattern (từ khóa SQL, thẻ `<script>`, ký tự nguy hiểm...). Mục tiêu: biến payload khai thác thành dạng WAF không nhận ra nhưng backend vẫn hiểu.

Các kỹ thuật bypass thường dùng:
- **Đổi hoa/thường** — `SeLeCt`, `UnIoN` (nếu WAF match phân biệt hoa thường).
- **Chèn comment** — `UN/**/ION SE/**/LECT`, `/*!50000UNION*/` (inline comment của MySQL).
- **Encoding** — URL-encode, double URL-encode, Unicode, hex (`0x...`), ký tự `%00`.
- **Tách/thay từ khóa** — dùng hàm/toán tử tương đương: `||` thay `OR`, `/**/` thay space, `%09`/`%0a` (tab/newline) thay space.
- **HTTP Parameter Pollution (HPP)** — gửi nhiều tham số cùng tên để backend/WAF hiểu khác nhau.
- **Thay đổi Content-Type / method** — chuyển GET↔POST, dùng JSON body nếu WAF chỉ soi query string.

Vì không có file đề, không thể xác nhận flag.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Xác định lỗ hổng gốc trước (SQLi/XSS/RCE)** — VÌ phải biết đang bypass để khai thác gì thì mới chọn payload nền.
- **Dò điểm WAF chặn** — VÌ cần biết WAF lọc từ khóa nào / ở tầng nào (query, body, header) để chọn kỹ thuật né đúng.
- **Biến đổi payload (comment/encoding/case/whitespace)** — VÌ đổi biểu diễn giữ nguyên ngữ nghĩa backend nhưng phá pattern của WAF.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

Khi có đề:

```bash
# 1) Xác định lỗ hổng gốc và điểm WAF chặn:
#    gửi payload "sạch" (SELECT/ <script>/ ; id) xem bị chặn (403/418) ở đâu.

# 2) Thử lần lượt các biến thể bypass (ví dụ SQLi):
#    - case:        uNiOn sElEcT
#    - comment:     union/**/select   |   /*!50000union*/ /*!50000select*/
#    - whitespace:  union%09select  (tab)   |   union%0aselect (newline)
#    - encoding:    %2555nion (double URL-enc)  |   0x61646d696e (hex literal)
#    - equivalent:  ' || '1'='1   thay cho  ' OR '1'='1

# 3) XSS bị chặn <script>:
#    <img src=x onerror=alert(1)>  |  <svg/onload=alert(1)>  |  dùng event handler + encoding

# 4) RCE bị chặn khoảng trắng/từ khóa:
#    cat${IFS}flag   |   c''at flag   |   /???/??t /f??g

# 5) Chuyển tầng: đưa payload sang POST body / JSON nếu WAF chỉ soi query string (HPP, method swap).
```

## Flag

```
flag{...}
```

**Nguồn không nêu** — `README.md` rỗng, không có file đề; `SOLUTIONS_VN.md` chỉ ghi định hướng, không có flag.

## Gặp lại thì xử lý thế nào (playbook)

1. Xác định lỗ hổng nền (SQLi/XSS/RCE) và dạng response khi bị WAF chặn (403/418/empty).
2. Tìm từ khóa/ký tự nào kích hoạt chặn và ở tầng nào (query/body/header/cookie).
3. Lần lượt áp: đổi case, chèn comment inline, đổi whitespace (`/**/`, `%09`, `%0a`), encoding (URL/double/hex/unicode), hàm tương đương.
4. Thử chuyển tầng request (GET↔POST, JSON, HPP) và chèn ký tự null/overlong.
5. Công cụ hỗ trợ: Burp Intruder (fuzz bypass), `sqlmap --tamper=...` với tamper script phù hợp.
