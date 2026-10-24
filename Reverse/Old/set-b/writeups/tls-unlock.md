# tls-unlock

- **Category:** Network
- **File đề:** `tls-unlock/64ef3b043d56cbbb8f873cfa96cd3e4e.zip` (1870603 bytes, md5 nhúng tên `64ef3b043d56cbbb8f873cfa96cd3e4e`, git blob sha1 `711ca6edb450fa772e2ff2970aeefbe39d189383`). Trong zip: `unlock.pcapng` (bản ghi gói tin) và `server.key` (khóa riêng RSA của server). (Bài dán nhãn Binary nhưng bản chất là Network/TLS forensics.)

## Tóm tắt đề

Một bản ghi gói tin có luồng HTTPS trong đó client đọc `flag.txt`, nhưng nội dung bị mã hóa TLS. Đề cho kèm **private key RSA của server** (`server.key`). Nhiệm vụ: giải mã TLS để đọc flag.

## Phân tích (chi tiết)

**Nền tảng TLS.** TLS/HTTPS bảo vệ dữ liệu bằng mã hóa đối xứng (AES...) với một *khóa phiên*. Hai bên thống nhất khóa phiên qua **handshake**.

Handshake TLS 1.2 với **RSA key exchange**:
1. **ClientHello** — gửi `client_random` + danh sách cipher suite.
2. **ServerHello** — chọn cipher suite, gửi `server_random`.
3. **Certificate** — server gửi chứng chỉ chứa public key RSA.
4. **ClientKeyExchange** — client sinh **pre-master secret** (48 byte), **mã hóa bằng public key** server rồi gửi. Chỉ ai có **private key** mới giải ra pre-master.
5. Hai bên dẫn xuất **master secret** = PRF(pre-master, "master secret", client_random+server_random) → sinh khóa đối xứng + MAC → ChangeCipherSpec/Finished.

**Mấu chốt bài này:** với RSA kx, mọi bí mật phiên phái sinh từ pre-master, mà pre-master được mã hóa bằng public key. Có **private key** ⇒ giải ngược pre-master ⇒ tính master secret ⇒ **giải mã mọi gói**. Wireshark tự động hóa khi ta nạp `server.key`.

**Vì sao đôi khi KHÔNG giải được — Forward Secrecy:** nếu handshake dùng **(EC)DHE** (Diffie–Hellman tạm thời), khóa phiên dựa trên số bí mật *tạm thời*, không mã hóa bằng RSA key → có private key cũng vô dụng. Khi đó chỉ giải được nếu có `SSLKEYLOGFILE`. Việc đề **cho server.key** là dấu hiệu phiên dùng **RSA kx** (cipher suite kiểu `TLS_RSA_WITH_AES_...`).

Trinh sát:

```bash
unzip 64ef3b043d56cbbb8f873cfa96cd3e4e.zip
openssl rsa -in server.key -noout -text | head   # xác nhận RSA private key hợp lệ (PEM)
```

Mở `unlock.pcapng` trong Wireshark: có GET đọc `flag.txt` qua HTTP (cổng 80), nhưng server trả **301/302 redirect sang HTTPS** → request thật nằm trong phiên TLS đã mã hóa. Kiểm tra cipher suite trong ServerHello: nếu `TLS_RSA_WITH_*` ⇒ nạp key giải được.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **TLS decryption bằng RSA private key trong Wireshark** — VÌ phiên dùng RSA kx (không forward secrecy) + lộ private key = giải ngược pre-master → giải mã toàn bộ Application Data.
- **Kiểm tra cipher suite trước** — VÌ nếu là ECDHE/DHE thì private key vô dụng, phải cần SSLKEYLOGFILE; xác nhận RSA kx mới chắc giải được.
- **Follow TLS/HTTP Stream** — VÌ sau khi giải mã, cần đọc đúng response của `GET /flag.txt`.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

**Bước 1 — Giải nén & xác nhận key.**

```bash
unzip 64ef3b043d56cbbb8f873cfa96cd3e4e.zip
openssl rsa -in server.key -noout -text | head
```

**Bước 2 — Nạp key vào Wireshark.**

```
Edit > Preferences > Protocols > TLS > RSA keys list (bản mới: tab "Decryption"):
   IP Address = <IP server> , Port = 443 , Protocol = http , Key File = server.key
Apply -> các gói Application Data TLS được giải mã.
```

**Bước 3 — Đọc flag.** Chuột phải một gói của phiên → `Follow > TLS Stream` (hoặc `HTTP Stream`) → đọc phản hồi `GET /flag.txt`.

Hoặc dòng lệnh:

```bash
tshark -r unlock.pcapng -o "tls.keys_list:<ip>,443,http,server.key" -Y "http" -O http
```

## Flag

```
flag{cf8236571e9dd3bcaf44b188bba4f15d}
```

"unlock" = mở khóa phiên TLS nhờ private key. Bài học: RSA key exchange (không forward secrecy) + lộ private key = toàn bộ traffic bị giải mã.

## Gặp lại thì xử lý thế nào (playbook)

1. Có pcap HTTPS + file `.key`/`.pem` ⇒ thử giải mã TLS bằng private key.
2. Luôn xem cipher suite trong ServerHello: `TLS_RSA_WITH_*` → private key đủ; `*_ECDHE_*`/`*_DHE_*` → cần `SSLKEYLOGFILE`, private key vô dụng.
3. Khai đúng IP/port/protocol khi nạp key; thiếu ClientKeyExchange trong capture thì giải mã thất bại.
4. pcapng mở trực tiếp, không cần chuyển pcap; `tshark -o tls.keys_list` làm được từ CLI.
5. Sau khi giải mã dùng Follow Stream hoặc `File > Export Objects > HTTP` để rút file truyền.
