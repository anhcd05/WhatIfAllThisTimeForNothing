# loose-comparison

- **Category:** Web
- **File đề:** không có trong repo (`README.md` rỗng, không file đề). Tên bài gốc "operand mistake".

## Tóm tắt đề

Bài Web 200đ. Repo **không có lời giải và không có file đề**. Tên "operand mistake" ("dùng sai toán tử") gần như chắc chắn trỏ tới lỗi **loose comparison / type juggling** (PHP/JS): dùng `==` thay vì `===`. Phần dưới là kiến thức nền + playbook.

## Phân tích (chi tiết)

"Dùng sai toán tử" thường là:
- `==` thay vì `===` → **loose comparison / type juggling** (PHP, JS).
- `|` thay `||`, `&` thay `&&`.
- So sánh **magic hash**: chuỗi dạng `0e<chỉ_số>` được PHP coi là số `0` trong `==`, nên hai hash `0e...` khác nhau vẫn "bằng nhau".

Các điểm khai thác kinh điển trong loose comparison (PHP `==`):
- `"0e123" == "0e456"` → true (cả hai bị ép thành `0.0`). Dùng để bypass so sánh hash MD5/SHA1 nếu hash bắt đầu bằng `0e` và phần còn lại toàn số.
- `0 == "abc"` → true trong PHP cũ (< 8). Gửi `0` để khớp một chuỗi.
- `"1abc" == 1` → true (chuỗi bị ép số).
- Mảng vs chuỗi với `strcmp`: `strcmp([], "x")` trả NULL → `NULL == 0` true.

Vì không có file đề, không thể xác nhận flag.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Type juggling bằng input `0e...`** — VÌ nếu so sánh hash bằng `==`, hai "magic hash" `0e[0-9]+` đều thành 0.0 → bypass.
- **Gửi `0`/chuỗi ép số** — VÌ `==` ép kiểu, `0 == "non-numeric"` hoặc `"1abc" == 1` cho true không mong đợi.
- **Array/`strcmp` bypass** — VÌ `strcmp(array, string)` trả NULL → `NULL == 0` true, vượt qua kiểm tra.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

Khi có đề (ví dụ form so sánh token/password bằng `==`):

```bash
# 1) Nếu so sánh hash kiểu $input == $stored và $stored là magic hash '0e...':
#    gửi một chuỗi mà md5/sha1 của nó bắt đầu '0e' + toàn số (magic hash đã biết), hoặc:
curl -d 'password=0e215962017' http://<target>/login   # nếu server so sánh lỏng

# 2) Mảng bypass strcmp:
curl -d 'password[]=x' http://<target>/login

# 3) Ép kiểu số:
curl -d 'token=0' http://<target>/verify
```

## Flag

```
flag{...}
```

**Nguồn không nêu** — `README.md` rỗng, không có file đề; `SOLUTIONS_VN.md` chỉ ghi định hướng, không có flag.

## Gặp lại thì xử lý thế nào (playbook)

1. Thấy so sánh bằng `==` (PHP/JS) ⇒ nghĩ ngay type juggling.
2. So sánh hash ⇒ thử magic hash `0e...` (ví dụ `md5("240610708")` = `0e462...`).
3. So sánh chuỗi bằng `strcmp` ⇒ thử gửi mảng (`param[]=x`).
4. Ép kiểu: thử `0`, `"0e1"`, `true`, `"1abc"` tùy ngữ cảnh.
5. Bài học: dùng `===` / `hash_equals()` / so sánh constant-time.
