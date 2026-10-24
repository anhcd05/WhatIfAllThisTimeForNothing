# tls-capture

- **Category:** Forensics — giải mã phiên TLS từ bản bắt gói (pcap) bằng khoá riêng của server.
- **File đề:** `D5-tls-capture/64ef3b043d56cbbb8f873cfa96cd3e4e.zip`
  - Kích thước: **1 827 616 byte**, MD5 `64ef3b043d56cbbb8f873cfa96cd3e4e` (= tên file)
  - SHA1: `e9c09e7f22df1dc86e36d044b5722bdca2c83461`
  - **Nội dung zip:** một bản sao cây `/etc` của server CentOS, gồm:
    - `etc/httpd/conf/httpd.conf`, `etc/httpd/conf.d/ssl.conf` (cấu hình Apache)
    - `etc/pki/tls/certs/server.crt`, `server.csr`, **`server.key`** (chứng chỉ + **khoá riêng**)
    - `etc/pki/tls/certs/localhost.crt`, `etc/pki/tls/private/localhost.key`
    - NSS DB: `etc/pki/nssdb/{cert8.db,cert9.db,key3.db,key4.db,secmod.db}`
    - **`unlock.pcapng`** (~7 380 byte) — bản bắt gói

## Tóm tắt đề
Đề cung cấp cấu hình server, chứng chỉ/khoá TLS và một bản ghi lưu lượng. Flag nằm trong một phản hồi HTTP đã bị mã hoá bằng HTTPS; phải **giải mã** lưu lượng mới đọc được. Phân tích hoàn toàn **tĩnh** (đọc file, đọc gói), không chạy gì.

## Phân tích (chi tiết)
**Vì sao TLS khó đọc.** TLS/HTTPS mã hoá nội dung HTTP nên trong pcap chỉ thấy byte rối. Muốn đọc phải giải mã, tức cần khôi phục *session key*.

**Hai kiểu trao khoá (key exchange) — điểm mấu chốt của bài:**
- **RSA key exchange (kRSA):** client sinh *pre-master secret*, **mã hoá bằng khoá công khai của server**, gửi đi; server dùng **private key** giải ra pre-master → cả hai tính session key. ⇒ **Ai có private key của server thì giải mã được toàn bộ phiên** (kể cả bắt từ trước). KHÔNG có forward secrecy.
- **ECDHE (Diffie-Hellman trên đường cong elliptic):** session key sinh qua trao đổi tạm thời, **không** truyền trực tiếp; khoá ephemeral bị vứt sau phiên. Có *forward secrecy*: lộ private key sau này cũng **không** giải mã được phiên cũ — khi đó phải có `SSLKEYLOGFILE`.

**Kiểm chứng trong đề (lý do gốc rễ).** File `ssl.conf` ép:
```apache
<VirtualHost _default_:443>
  SSLProtocol all -SSLv2
  SSLCipherSuite kRSA                         # <-- CHỈ cho dùng trao khoá RSA
  SSLCertificateFile    /etc/pki/tls/certs/server.crt
  SSLCertificateKeyFile /etc/pki/tls/certs/server.key
</VirtualHost>
```
`SSLCipherSuite kRSA` buộc server **chỉ** dùng bộ mã trao khoá RSA ⇒ không có forward secrecy ⇒ nạp `server.key` vào Wireshark là giải mã được. Đây là lý do gốc rễ khiến bài giải được (nhiều mô tả phổ biến không nêu dòng này).

Thông tin `server.crt` (xem bằng `openssl x509 -in server.crt -text`):
- Subject/Issuer: `C=XX, L=Default City, O=Default Company Ltd` (self-signed, cert mặc định).
- Hiệu lực: 13/12/2018 → 10/12/2028.
- `server.key`: **RSA PRIVATE KEY, 2048-bit** (`-----BEGIN RSA PRIVATE KEY-----`).

**Quan sát pcap.** Mở `unlock.pcapng` trong Wireshark → *Statistics → Protocol Hierarchy*: có cả HTTP (rõ) và TLS (mã hoá). *Follow HTTP Stream* kênh HTTP (cổng 80):
```
GET /flag.txt HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Host: 192.168.1.111
HTTP/1.1 302 Found
Server: Apache/2.2.15 (CentOS)
Location: https://192.168.1.111/flag.txt
```
Client `wget` xin `/flag.txt` qua HTTP, server **302 chuyển hướng** sang **HTTPS**. Flag nằm ở phiên HTTPS — không xuất hiện dạng chữ trong `strings` vì đã mã hoá.

## Kỹ thuật áp dụng (CVE cụ thể nếu có + VÌ SAO)
- **Không có CVE.** Bài khai thác một *cấu hình yếu* (RSA key exchange + lộ private key), không phải lỗ hổng phần mềm.
- **Giải mã TLS trong Wireshark bằng RSA private key của server.**
  - VÌ SAO khả thi: đề cho sẵn `server.key` + `server.crt` + pcap có TLS, và `ssl.conf` ép `kRSA`. Với kRSA, pre-master secret được *mã hoá bằng public key* và gửi trong gói ClientKeyExchange; có private key là giải ngược ra pre-master → tính session key → giải mã toàn bộ phiên.
  - **Bắt tay TLS 1.2 kRSA (từng gói):** (1) ClientHello gửi `client_random`; (2) ServerHello chọn bộ `TLS_RSA_WITH_...`, gửi `server_random`; (3) Certificate gửi `server.crt` (public key); (4) **ClientKeyExchange** — client mã hoá pre-master bằng public key, gửi đi (mắt xích vàng); (5) hai bên tính master secret = PRF(pre_master, client_random, server_random) → session key; (6) dữ liệu ứng dụng mã hoá đối xứng. Nạp `server.key` → Wireshark giải gói (4) lấy pre_master, kết hợp hai random (nằm trong gói Hello không mã hoá) → tính session key → lộ `HTTP/1.1 200 OK ... flag{...}`.
  - VÌ SAO ECDHE thì KHÔNG: bước (4) không truyền pre-master; hai bên tự tính chung secret qua Diffie-Hellman, secret không bao giờ lên dây, khoá ephemeral bị vứt → có private key cũng vô dụng (forward secrecy). Đề cố tình đặt `kRSA` để loại ECDHE.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)
1. **Giải nén & khảo sát:**
   ```bash
   unzip -l 64ef3b043d56cbbb8f873cfa96cd3e4e.zip
   find etc | grep -iE 'key|crt'
   # → server.key, server.crt, localhost.key, key3.db, key4.db ...
   ```
2. **Xem cert (tuỳ chọn):** `openssl x509 -in etc/pki/tls/certs/server.crt -text -noout`.
3. **Mở `unlock.pcapng` trong Wireshark**, lọc `http` → thấy `GET /flag.txt` bị 302 sang HTTPS.
4. **Nạp private key:** *Edit → Preferences → Protocols → TLS → RSA keys list → +*, thêm:

   | Trường | Giá trị |
   |--------|---------|
   | IP address | `192.168.1.111` |
   | Port | `443` |
   | Protocol | `http` |
   | Key File | `etc/pki/tls/certs/server.key` |
   | Password | (để trống) |
5. Wireshark giải pre-master trong gói ClientKeyExchange → tính session key → giải mã phiên. **Follow HTTP Stream** phiên HTTPS:
   ```
   GET /flag.txt HTTP/1.1
   Host: 192.168.1.111
   ...
   HTTP/1.1 200 OK
   Server: Apache/2.2.15 (CentOS)
   Content-Type: text/plain; charset=UTF-8
   Content-Length: 39

   flag{cf8236571e9dd3bcaf44b188bba4f15d}
   ```
6. **Tương đương dòng lệnh (tshark):**
   ```bash
   tshark -r unlock.pcapng \
     -o "tls.keys_list:192.168.1.111,443,http,etc/pki/tls/certs/server.key" \
     -z follow,http,...
   ```

## Flag
flag{cf8236571e9dd3bcaf44b188bba4f15d}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** đề cho pcap CÙNG với `*.key`/`*.crt` hoặc file `sslkeylog`; trong pcap có TLS và một redirect HTTP→HTTPS.
- **Quy trình:**
  1. Liệt kê kho, `grep -iE 'key|crt'` để tìm private key / keylog.
  2. Mở pcap, lọc `tls`/`http`; xem ServerHello để biết cipher (kRSA hay ECDHE).
  3. Có **RSA private key** + server dùng key-exchange RSA → *Protocols → TLS → RSA keys list*.
  4. Có **SSLKEYLOGFILE** (phiên ECDHE/forward secrecy) → nạp vào *(Pre)-Master-Secret log filename*.
  5. Follow HTTP/TLS stream để đọc body đã giải mã.
- **Công cụ:** Wireshark, `tshark`, `openssl x509`, `unzip`.
- **Bẫy:**
  - Nếu cipher là **ECDHE**, private key RSA **không** giải mã được — bắt buộc phải có keylog file. Kiểm tra cipher trong ServerHello trước khi loay hoay với key.
  - Phải nhập đúng IP/port server (`192.168.1.111:443`); nhập sai Wireshark không áp key.
  - Dùng đúng `server.key` (vhost 443), không phải `localhost.key`.
  - Các file NSS `key3.db`/`key4.db` là **mồi nhử** (keystore của client NSS/Firefox), không liên quan — đừng mất thời gian mở bằng `certutil`/`pk12util`.
  - Flag chỉ xuất hiện trong luồng HTTPS đã giải mã, không phải luồng HTTP plaintext (vốn chỉ là redirect).
- **Checklist ngắn:** tìm key → xác định kiểu key-exchange → nạp đúng loại (RSA key hay keylog) → follow stream.
