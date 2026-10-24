# jwt-none-auth

- **Category:** Web
- **File đề:** target `10.3.204.202:10080` (ứng dụng quản lý người dùng). Repo kèm README + nhiều ảnh (register/login/token/jwt-sign/flag).

## Tóm tắt đề

Luồng: đăng ký → đăng nhập → server trả **JWT**; truy cập trang chính bị **401 Unauthorized**. Token không có chữ ký và chứa trường `auth`. Khai thác lỗ hổng **JWT `alg:none` / không kiểm tra chữ ký** để nâng quyền và lấy flag.

## Phân tích (chi tiết)

**Nền tảng JWT.** Token gồm 3 phần `base64url(header).base64url(payload).signature`. `header` khai báo thuật toán ký, ví dụ `{"alg":"HS256","typ":"JWT"}`. Chữ ký bảo đảm payload không bị sửa.

**Lỗ hổng `alg:none`:** nếu server chấp nhận token có `"alg":"none"` (hoặc **không kiểm tra chữ ký**), kẻ tấn công tự chế payload (ví dụ nâng quyền `auth=1`) mà **không cần khóa bí mật**. Ở bài này, token "không có chữ ký và không có thuật toán" → server tin payload mù quáng.

Trinh sát:
- Đăng ký + đăng nhập → bắt token (ảnh `token.png`): payload chứa trường `auth` (ví dụ `auth=0`), và token **không có phần chữ ký**.
- Truy cập `/users` → **401** (ảnh `users-req.png`): cần quyền cao hơn.

Vì token không ký/không alg, chỉ cần sửa `auth` từ 0→1 là có quyền admin. Dùng CyberChef (JWT) hoặc tự base64url-encode payload mới rồi ghép lại (không chữ ký).

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Giải mã base64url payload** — VÌ cần thấy trường `auth` để biết đổi gì.
- **Sửa payload + ghép JWT không chữ ký** — VÌ server không kiểm tra chữ ký; `auth:1` cho quyền admin mà không cần secret.
- **Gửi token qua header Authorization** — VÌ endpoint `/users` bị gác bằng token; thay token nâng quyền là lấy được dữ liệu + flag.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

```
1) Giải mã payload JWT hiện tại (base64url) -> thấy {"auth":0,...}
2) Sửa thành {"auth":1,...}, base64url-encode lại.
3) Ghép token mới: <header_b64>.<payload_b64_sửa>.    (phần chữ ký để trống/none như token gốc)
   -> dùng https://gchq.github.io/CyberChef/ (JWT) cho nhanh.
4) Gửi token mới rồi gọi /users:
   curl -H "Authorization: <token_mới>" http://10.3.204.202:10080/users
   -> server trả toàn bộ dữ liệu user kèm flag.
```

Giải nghĩa flag:

```python
import base64
# phần trong {} là base64url của một câu
print(base64.urlsafe_b64decode("SXMgdGhlIGNvcnJlY3QgYW5zd2VyISBDb25ncmF0cyE" + "=="))
# -> b'Is the correct answer! Congrats!'
```

## Flag

```
flag{SXMgdGhlIGNvcnJlY3QgYW5zd2VyISBDb25ncmF0cyE}
```

Phần trong `{}` giải Base64 ra "Is the correct answer! Congrats!". Thông điệp: quản lý người dùng "broken" vì JWT không được ký / không kiểm tra `alg`.

## Gặp lại thì xử lý thế nào (playbook)

1. Nhận JWT (3 phần ngăn bởi `.`) ⇒ decode header/payload, kiểm tra `alg` và xem có chữ ký không.
2. Thử `alg:none` / token không chữ ký: sửa `auth`/`role`/`admin` rồi gửi lại.
3. Biến thể khác: **confusion RS256→HS256** (ký HMAC bằng public key), **khóa HS256 yếu** (brute bằng `jwt_tool`/hashcat).
4. Giữ các trường khác hợp lệ (exp, user id) kẻo bị từ chối.
5. Công cụ: `jwt_tool`, CyberChef JWT, Burp.
