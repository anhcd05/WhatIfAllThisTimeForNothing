# mirai-protocol-vectors

- **Category:** Network Forensics (Mirai C2 protocol — parse lệnh DDoS)
- **File đề:** Không có pcap — phải **chủ động kết nối** tới C2 server `mirai-c2.<REDACTED>:23` và nói đúng giao thức Mirai để nhận lệnh tấn công. *(Chú thích: hostname C2 gốc chứa chuỗi gợi tên giải/nhà tài trợ — đã (REDACTED); domain mục tiêu mẫu dùng placeholder trung tính `example-ctf.net`.)*

## Tóm tắt đề
Tiếp nối phần `mirai-scan-filter`. Lần này phải **hiểu và nói được giao thức Mirai** để lấy một lệnh DDoS từ C2, tìm lệnh nhắm vào `10.192.0.10`. Flag: `flag{<type number>:<target port>:<attack duration>}`. Ví dụ "UDP flood 30s port 80" ⇒ `flag{0:80:30}`.

> Cảnh báo trong đề: C2 có lỗ hổng buffer overflow nhưng **đây không phải bài PWN** — đừng tấn công làm sập server (sẽ hỏng cả môi trường thi).

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
Để nhận lệnh, bot phải "đăng nhập" và duy trì heartbeat đúng giao thức Mirai:
- **Login:** `00 00 00 01 <1 byte độ dài botid> <botid>`
- **Ping (keep-alive):** `00 00` — không trả pong sẽ bị C2 ngắt.

**Cấu trúc lệnh tấn công** (sau khi gỡ các byte ping `00 00` ở đầu nếu có):
| Offset | Kích thước | Ý nghĩa |
|---|---|---|
| 0 | 2 byte | Packet length |
| 2 | 4 byte | **Attack duration** |
| 6 | 1 byte | **Attack type** |
| 7 | 1 byte | Number of targets |
| 8 | 5 byte × n | Mỗi target: 4 byte IP + 1 byte prefix/mask |
| sau targets | 1 byte | Number of flags |
| tiếp | biến độ dài | Mỗi flag: type (1B) + size (1B) + data (port nằm trong flag `dport`) |

C2 trả về **nhiều lệnh**. Cứ mỗi ~3 phút nhận **hai** lệnh (với `oolong-tea.example-ctf.net` phân giải thành `10.192.0.10`):
1. **HTTP flood 40s** tới port 8080 của `oolong-tea.ddns.net` — nhắm host qua header `Host:`, **không** thực sự quá tải server đích.
2. **DNS query flood 60s** hỏi `oolong-tea.example-ctf.net` tới các resolver gồm `192.168.0.1, 172.16.0.1, 127.0.0.1` và **`10.192.0.10`** — lệnh này **thực sự** quá tải server đích.

**Bẫy quan trọng (khóa thật):** nếu chỉ nhìn IP sẽ chọn nhầm. Phải đọc source Mirai để biết HTTP flood chọn mục tiêu qua header Host (không khẳng định nhắm đúng server), còn **DNS flood (attack type 2)** mới cố ý nhắm `10.192.0.10`. Vậy đáp án là DNS flood: **type = 2, target port = 53, duration = 60**.

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **Python socket + hexdump:** tự viết client giả làm bot Mirai, gửi login + ping, nhận dữ liệu, loại các byte pong `00 00` đầu khối rồi parse theo cấu trúc trên.
- **Đọc source Mirai** để map `attack type` ↔ vector ↔ cách chọn target (HTTP dùng header Host; DNS flood nhắm resolver trực tiếp).
- **VÌ SAO nhận ra:** port DNS = 53; duration lấy từ 4 byte offset 2; type là 1 byte offset 6. Chỉ lệnh DNS flood mới trực tiếp nhắm `10.192.0.10` nên nó là đáp án — không được chọn lệnh theo IP thuần.

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. Viết client duy trì heartbeat và dump lệnh:
   ```python
   import socket, time, hexdump

   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.connect(('mirai-c2.<REDACTED>', 23))
   s.send(b'\x00\x00\x00\x01'); time.sleep(1)   # Hello
   s.send(b'\x03abc');          time.sleep(1)   # login: botid length=3, botid="abc"

   while True:
       s.send(b'\x00\x00'); time.sleep(5)       # ping (keep-alive)
       packet = s.recv(1024)
       while packet[:2] == b'\x00\x00':          # bỏ các pong đầu khối
           packet = packet[2:]
       if packet:
           print(hexdump.dump(packet))
           print([chr(b) for b in packet if chr(b).isprintable()])
   ```
2. Chờ tới khi nhận các lệnh (mỗi ~3 phút có 2 lệnh). Parse theo offset:
   - `duration = int.from_bytes(packet[2:6], 'big')`
   - `atype    = packet[6]`
   - `ntargets = packet[7]`
   - targets: 5 byte mỗi target từ offset 8
   - đọc danh sách flag để lấy port (`dport`).
3. Hai lệnh nhận được:
   1. HTTP flood 40s → port 8080, host `oolong-tea.ddns.net` (qua header Host) — **không** phải mục tiêu thật.
   2. **DNS query flood 60s** truy vấn `oolong-tea.example-ctf.net` tới resolver gồm `10.192.0.10` — lệnh thực sự quá tải server đích.
4. Lệnh DNS flood: **type = 2, target port = 53, duration = 60** ⇒ ghép flag.

## Flag
flag{2:53:60}

*(Nguồn canonical `SOLUTIONS_VN.md` — bài #15; flag đã nêu trong writeup đề. type=2 (DNS), port=53, duration=60s.)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** phải "nói chuyện" với C2 Mirai (login `00 00 00 01`, ping `00 00`); dữ liệu nhận là binary length-prefixed; nhiều lệnh lặp theo chu kỳ.
- **Quy trình:**
  1. Giữ kết nối sống bằng ping/pong (không pong = bị kick).
  2. Gỡ các byte `00 00` (pong) ở đầu trước khi parse.
  3. Parse: len(2)|duration(4)|type(1)|#targets(1)|targets(5·n)|#flags(1)|flags...
  4. Xác định **vector nào thực sự nhắm IP mục tiêu** — DNS flood nhắm resolver trực tiếp; HTTP flood nhắm host qua header.
- **Công cụ:** Python socket, `hexdump`, source Mirai (`jgamblin/Mirai-Source-Code`) để map type ↔ port ↔ cách chọn target.
- **Bẫy:** (1) KHÔNG khai thác buffer overflow của C2 — sẽ sập môi trường. (2) Đừng chọn lệnh theo IP thuần: HTTP flood "ngụy trang" cùng host nhưng không quá tải server đích. (3) Nhớ shave 2 byte đầu khi message mở đầu `00 00`.
- **Checklist:** [ ] login + ping/pong [ ] strip pong [ ] parse theo offset [ ] phân biệt vector thật [ ] lấy type/port/duration.
