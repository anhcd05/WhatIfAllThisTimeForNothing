# mirai-scan-filter

- **Category:** Network Forensics (Botnet C2 Discovery)
- **File đề:** PCAP chụp từ một host nhiễm mã độc Mirai (biến thể dùng giao thức Mirai gốc). *(Chú thích: pcap chỉ có trên môi trường thi; phân tích dựa trên nội dung được trích trong nguồn.)*

## Tóm tắt đề
Cho một PCAP chụp từ máy nhiễm Mirai. Nhiệm vụ: tìm **gói đầu tiên liên quan tới máy chủ C&C (Command & Control)**. Định dạng flag: `flag{<IP>:<port>:<TCP sequence number ở hex big-endian, bỏ "0x">}`. Ví dụ C&C `10.192.0.18:3333`, seq đầu `0xbeef1337` ⇒ `flag{10.192.0.18:3333:beef1337}`.

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
Lưu lượng C&C bị chôn vùi trong "cơn lũ" gói **scan** của Mirai. Chữ ký quyết định (từ source code `jgamblin/Mirai-Source-Code`):

> Mỗi gói **scan SYN** của Mirai có **TCP sequence number bằng chính địa chỉ IP đích** của gói đó.

Mirai làm vậy để nhận lại SYN/ACK mà không cần lưu trạng thái (**stateless scanning**) — nó "nhúng" IP đích vào seq. Do đó, **lọc bỏ** mọi gói mà **4 byte TCP sequence number == 4 byte địa chỉ IP đích**; phần còn lại (seq ≠ dst IP) là lưu lượng bất thường, trong đó có bắt tay với C&C.

Offset thô:
- 4 byte địa chỉ IP đích: offset **16** của IP header.
- 4 byte TCP sequence number: offset **4** của **TCP** header (dùng giá trị **tuyệt đối** `tcp.seq_raw`, không phải relative seq của Wireshark).

Khóa thật (kết quả): C&C = **`143.93.131.169:23`** (port 23 = telnet, điển hình Mirai); TCP seq của gói đầu tiên = **`0x75240531`** (big-endian byte `75 24 05 31`).

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **Wireshark/tshark** so sánh trường thô để loại gói scan.
- **OSINT mã độc:** đọc source Mirai để biết đặc tính "seq == dst IP" — đúng tinh thần "to the future direction": dùng open-source intelligence cho forensics.
- **VÌ SAO nhận ra:** đặc tính `seq == dst IP` là **chữ ký duy nhất** tách scan khỏi traffic thật mà không cần biết trước IP C&C. Giải pháp phụ: gói SYN scan Mirai dài đúng **54 byte** (`frame.len != 54` khoanh vùng gói lạ, nhưng không tổng quát).

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. Mở PCAP. Tắt relative seq: Edit → Preferences → Protocols → TCP → **bỏ** "Relative sequence numbers" (hoặc dùng trường `tcp.seq_raw`).
2. Lọc giữ gói có seq ≠ IP đích (loại scan):
   ```
   tcp.flags.syn==1 && tcp.seq_raw != ip.dst_host
   ```
   (hoặc giải pháp phụ: `frame.len != 54`).
3. Trong số gói còn lại, tìm **gói đầu tiên** của bắt tay tới một host cố định → C&C **143.93.131.169:23**, seq gói đầu = **0x75240531**.
4. Ghép template: `<IP>:<port>:<seq hex>` = `143.93.131.169:23:75240531`.

Với tshark (lọc rồi lấy seq_raw của gói C&C đầu tiên):
```bash
tshark -r mirai.pcap -o tcp.relative_sequence_numbers:FALSE \
  -Y 'tcp.flags.syn==1 && tcp.seq_raw != ip.dst_host' \
  -T fields -e frame.number -e ip.dst -e tcp.dstport -e tcp.seq_raw
# đổi seq thập phân -> hex big-endian: printf '%08x\n' <seq_raw>
```

## Flag
flag{143.93.131.169:23:75240531}

*(Nguồn canonical `SOLUTIONS_VN.md` — bài #14; flag đã nêu trong writeup đề.)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** pcap đầy gói SYN rải rác tới vô số IP, port 23/2323 (telnet) — chữ ký Mirai scan. Nếu `tcp.seq_raw == ip.dst` trên hàng loạt gói ⇒ chắc chắn Mirai scanning.
- **Quy trình:**
  1. Tắt relative seq (dùng `tcp.seq_raw`).
  2. Loại gói scan: `tcp.seq_raw == ip.dst_host` là scan → bỏ.
  3. Phần còn lại: tìm bắt tay TCP đầu tiên tới host cố định (C&C). Port Mirai thường 23.
  4. Đọc seq gói đầu, đổi sang hex big-endian.
- **Công cụ:** Wireshark/tshark, source Mirai (`jgamblin/Mirai-Source-Code`).
- **Bẫy:** đừng dùng seq "relative" của Wireshark — phải tuyệt đối (`seq_raw`). Lọc theo 54 byte không tổng quát. Offset: seq ở TCP header offset 4, dst IP ở IP header offset 16.
- **Checklist:** [ ] tắt relative seq [ ] loại gói seq==dstIP [ ] tìm gói C&C đầu tiên [ ] lấy IP:port [ ] seq → hex big-endian.
