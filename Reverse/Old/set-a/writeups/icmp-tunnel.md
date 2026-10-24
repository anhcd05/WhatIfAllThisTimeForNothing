# icmp-tunnel

- **Category:** Network (ICMP Covert Channel)
- **File đề:** `ctf/network/icmp-tunnel/icmp_tunnel.pcapng` — 117,276 byte — MD5 `6ce980bad96497a8ec2a1108609de0c7` — SHA-1 `5f98ad9ea578d1d0f2ca14374e2d2e4528a6a837`. *(Có file offline trong repo set-a.)*

## Tóm tắt đề
Phân tích pcap để tìm flag. Như tên gợi ý, đây là một kênh **C2 / exfiltration ẩn trong ICMP** (ICMP tunneling): payload gói ICMP chứa dữ liệu khác thường so với ping bình thường, được mã hóa **Base64**.

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
Lọc `icmp`. Có hai host trao đổi:
- Phía ra lệnh: gửi **lệnh** trong ICMP echo **request** (type 8).
- Phía nạn nhân/agent: gửi **output** trong ICMP echo **reply** (type 0).

Thống kê: **1476 gói ICMP** = **8 echo request** (lệnh) + **1468 echo reply** (kết quả). Payload request decode base64 ra danh sách lệnh:
```
whoami
ipconfig
dir c:\tmp\
cat flag.txt
type c:\tmp\*
find /C "flag" c:\tmp\*
attrib c:\tmp\*
```

**Chi tiết tinh tế (khóa thật):**
- Phía reply **stream từng byte** (1 ký tự base64/gói). Dấu `.` — **không thuộc bảng Base64** — được dùng làm **ký tự phân tách (delimiter)** báo kết thúc một khối phản hồi.
- Trong mỗi "đoạn" có thể có **nhiều chuỗi Base64 nối nhau** (lệnh encode riêng, kết quả encode riêng); `base64.b64decode` **dừng ở dấu `=` padding**, nên phải tách theo các "run" base64 (regex `[A-Za-z0-9+/]+={0,2}`) rồi decode từng run — nếu decode cả đoạn một lần sẽ bị **cụt**.
- Lệnh `cat flag.txt` thất bại (`No such file or directory`); `dir` liệt kê `flag.txt` 36 byte; chính output lệnh **`type c:\tmp\*`** (hoặc `find /C "flag"`) in ra nội dung flag.

Offset ICMP: EtherType IPv4 `0x0800` tại offset 12 của khung Ethernet; IHL = `(pkt[14] & 0x0f)*4`; protocol byte ở `pkt[14+9]` (==1 là ICMP); header ICMP 8 byte, payload bắt đầu sau đó; type ICMP ở byte đầu header ICMP (0 = reply, 8 = request).

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **Nhận diện ICMP covert channel/tunneling**: payload echo là chuỗi in được (Base64) thay vì đệm `abcd...`/`0x00`.
- **Tách 2 chiều theo IP + decode Base64 theo run.**
- **VÌ SAO phân biệt 2 hướng:** request mang nguyên khối Base64 (1 lệnh/gói), còn reply bị chia 1 byte/gói nên phải tái lắp theo delimiter `.`; decode nhầm cả stream sẽ hỏng.
- **Công cụ:** Wireshark (filter `icmp`, xem Data), parser `struct` tự viết hoặc scapy/tshark, CyberChef (From Base64).

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. Lọc `icmp`, xác định 2 host và payload Base64 bất thường.
2. Parse pcapng + bóc tách theo run base64 (đã chạy thật, cho ra flag):
   ```python
   import struct, base64, re
   data = open("icmp_tunnel.pcapng", "rb").read()
   off, reps = 0, []
   while off + 8 <= len(data):
       bt = struct.unpack_from('<I', data, off)[0]
       bl = struct.unpack_from('<I', data, off + 4)[0]
       if bl < 12 or off + bl > len(data):
           break
       body = data[off + 8: off + bl - 4]
       if bt == 0x00000006:                                   # EPB
           cl = struct.unpack_from('<I', body, 12)[0]
           pkt = body[20:20 + cl]
           if len(pkt) >= 14 and struct.unpack_from('>H', pkt, 12)[0] == 0x0800:  # IPv4
               ihl = (pkt[14] & 0x0f) * 4
               if pkt[14 + 9] == 1:                           # proto 1 = ICMP
                   ic = pkt[14 + ihl:]
                   if len(ic) >= 8 and ic[0] == 0:            # type 0 = echo reply
                       reps.append(ic[8:].rstrip(b'\x00'))
       off += bl
   chars = b"".join(reps)
   for seg in chars.split(b'.'):                              # '.' = delimiter
       for m in re.finditer(rb'[A-Za-z0-9+/]+={0,2}', seg):   # từng run base64
           try:
               print(base64.b64decode(m.group()).decode('latin1'), end="")
           except Exception:
               pass
       print()
   ```
   Output lệnh `type c:\tmp\*` chứa: `flag{IC3B3RG_IS_JUS7_TH3_T1P}`.
3. Phương án scapy (đọc request → lệnh; gom reply theo `.`):
   ```python
   from scapy.all import rdpcap, IP, Raw
   from base64 import b64decode as b64d
   pkt = rdpcap("icmp_tunnel.pcapng")
   # request (src = phía ra lệnh): b64d cả khối -> lệnh
   # reply  (src = agent): gom từng byte, gặp b"." thì b64d buffer
   ```

## Flag
flag{IC3B3RG_IS_JUS7_TH3_T1P}

*(Nguồn canonical `SOLUTIONS_VN.md` — bài #12; ✅ đã tự khôi phục & xác minh trên file pcap offline. Ý nghĩa: "iceberg is just the tip".)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** ICMP echo request/reply có payload là chuỗi in được (Base64/hex) thay vì đệm `0x00`/`abcd...`; hai host trao đổi ICMP liên tục; kích thước payload bất thường hoặc nhỏ đều đặn (1 byte) ⇒ ICMP tunneling.
- **Quy trình:**
  1. `icmp` filter, chia theo hướng (src request vs src reply).
  2. Thử decode payload (Base64/hex). Nếu reply bị chia nhỏ, tìm **delimiter** (ký tự ngoài bảng mã, như `.`) để tái lắp.
  3. Decode theo **run** (không decode cả stream một lần — sẽ cụt tại `=`).
- **Công cụ:** Wireshark, scapy/tshark, CyberChef.
- **Bẫy:** đừng decode cả đoạn (reply stream 1 byte/gói + padding `=` giữa chuỗi); phân biệt rõ 2 chiều theo IP; lệnh `cat` trên Windows có thể lỗi (nhiễu) — flag thật ở output `type`/`find`.
- **Checklist:** [ ] lọc icmp [ ] tách 2 host [ ] decode base64 request→lệnh [ ] gom byte reply theo `.` [ ] decode từng run [ ] lấy flag.
