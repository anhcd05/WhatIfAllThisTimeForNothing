# mail-zip

- **Category:** Network (Email trong pcap + ZIP có mật khẩu)
- **File đề:** `ctf/network/mail-zip/mail_zip.pcapng` — 301,076 byte — MD5 `bdcb5bd60105b1f4b17a57b9797262e6` — SHA-1 `ae8d1c5c12a56bfd4fa554ea2484debdb24b0d66`. *(Có file offline trong repo set-a.)*

## Tóm tắt đề
Tìm flag trong một file ZIP bảo vệ bằng mật khẩu, được đính kèm trong **email** bắt được trong pcap. "Mail-Zip / PPAP" là mô hình gửi mail kiểu Nhật: gửi file ZIP khóa password ở mail thứ nhất, rồi gửi password ở mail thứ hai (Password-protected ZIP, Password, Angou-ka Protocol).

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
Trong pcap có **2 email** (SMTP/POP3/IMAP). Một email chứa **file ZIP** (đính kèm, mã hóa Base64 trong phần MIME `Content-Transfer-Encoding: base64`), email còn lại chứa **mật khẩu** (cũng Base64). Chỉ cần tái tạo cả hai rồi giải nén là ra flag.

Dữ liệu thật trích từ pcap:
- **ZIP (Base64)** — bắt đầu bằng magic `UEsDBB...` (decode ra `50 4B 03 04` = `PK\x03\x04`), chứa entry `flag.txt`:
  ```
  UEsDBBQAAQAAAOuZRFlGOHPQMQAAACUAAAAIAAAAZmxhZy50eHT2+yc57qBmi+PdWx2XLc7s
  pd3y29tedp5FaSiXbp9+3xqjG2i0vQBakJ4dTLtGPDPSUEsBAj8AFAABAAAA65lEWUY4c9Ax
  AAAAJQAAAAgAJAAAAAAAAAAgAAAAAAAAAGZsYWcudHh0CgAgAAAAAAABABgAHnBBUUYW2wEA
  AAAAAAAAAAAAAAAAAAAAUEsFBgAAAAABAAEAWgAAAFcAAAAAAA==
  ```
- **Password (Base64):** `cEI2QEZ3a1U2SFhodzdVZVp4QGVOTCN6`
  → decode ra mật khẩu thật: **`pB6@FwkU6HXhw7UeZx@eNL#z`**

ZIP dùng **ZipCrypto cổ điển** → `zipfile` chuẩn của Python mở được với `pwd` (nếu AES-256 thì cần `pyzipper`/`7z`).

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **Tái dựng email từ pcap:** Wireshark `File → Export Objects → IMF`, hoặc Follow TCP Stream các phiên SMTP/POP/IMAP.
- **Base64 decode** cả ZIP lẫn mật khẩu.
- **Giải nén ZipCrypto** với password.
- **VÌ SAO nhận ra:** file đính kèm trong email luôn ở dạng MIME Base64; mật khẩu cũng Base64 để tránh lỗi hiển thị. Hai email liên quan (một mang ZIP, một mang password) = đúng mô hình PPAP. Phải decode đúng cả hai rồi mới ghép được.

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. Mở `mail_zip.pcapng`, tách 2 email (Export Objects → IMF hoặc Follow TCP Stream). Lấy khối Base64 của attachment ZIP và chuỗi Base64 của mật khẩu.
2. Tái tạo ZIP + mật khẩu rồi giải nén (đã chạy thật, cho ra flag):
   ```python
   import base64, io, zipfile
   zip_b64 = (
     "UEsDBBQAAQAAAOuZRFlGOHPQMQAAACUAAAAIAAAAZmxhZy50eHT2+yc57qBmi+PdWx2XLc7s"
     "pd3y29tedp5FaSiXbp9+3xqjG2i0vQBakJ4dTLtGPDPSUEsBAj8AFAABAAAA65lEWUY4c9Ax"
     "AAAAJQAAAAgAJAAAAAAAAAAgAAAAAAAAAGZsYWcudHh0CgAgAAAAAAABABgAHnBBUUYW2wEA"
     "AAAAAAAAAAAAAAAAAAAAUEsFBgAAAAABAAEAWgAAAFcAAAAAAA==")
   z = base64.b64decode(zip_b64)
   assert z[:4] == b"PK\x03\x04"                   # verify magic
   pw = base64.b64decode("cEI2QEZ3a1U2SFhodzdVZVp4QGVOTCN6")   # b'pB6@FwkU6HXhw7UeZx@eNL#z'
   zf = zipfile.ZipFile(io.BytesIO(z))
   print(zf.read("flag.txt", pwd=pw).decode('latin1'))
   ```
   Hoặc dòng lệnh:
   ```bash
   # ghi base64 zip ra file flag.zip rồi:
   echo 'cEI2QEZ3a1U2SFhodzdVZVp4QGVOTCN6' | base64 -d     # -> pB6@FwkU6HXhw7UeZx@eNL#z
   unzip -P 'pB6@FwkU6HXhw7UeZx@eNL#z' flag.zip
   ```
3. Nội dung `flag.txt` chính là flag (leet trộn ký hiệu).

## Flag
flag{!7 w4$ 34$y j06 w4$n'7 !7??}

*(Nguồn canonical `SOLUTIONS_VN.md` — bài #13; ✅ đã tự khôi phục & xác minh. Mật khẩu ZIP đã giải: `pB6@FwkU6HXhw7UeZx@eNL#z`. Leet: "it was easy job wasn't it??")*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** pcap có SMTP/POP3/IMAP; mail có attachment `Content-Transfer-Encoding: base64`; có 2 mail liên quan (một mang ZIP, một mang password) ⇒ mô hình PPAP.
- **Quy trình:**
  1. Export/Follow stream lấy nội dung mail.
  2. Tách Base64 của attachment và của password, decode cả hai.
  3. Kiểm magic `PK\x03\x04`.
  4. Giải nén với password.
- **Công cụ:** Wireshark (Export Objects → IMF, Follow Stream), `base64`, `unzip`/`7z`, Python `zipfile`, CyberChef.
- **Bẫy:** mật khẩu cũng bị Base64 — đừng dùng nguyên chuỗi `cEI2...` làm password (phải decode). ZIP AES-256 thì `unzip`/Explorer không mở được, cần `7z`/`pyzipper` (bài này là ZipCrypto nên `zipfile` chuẩn OK). Ký tự xuống dòng thừa khi copy Base64 từ Wireshark làm hỏng decode — nối liền trước khi decode.
- **Checklist:** [ ] lấy 2 mail [ ] decode ZIP base64 [ ] decode password base64 [ ] verify PK magic [ ] unzip bằng pw [ ] đọc flag.
