# blind-sqli

- **Category:** Network (Time-based Blind SQLi trong pcap)
- **File đề:** `ctf/network/blind-sqli/blind_sqli.pcapng` — 9,481,856 byte — MD5 `ed58400deff379ce127641fa99851e09` — SHA-1 `8b342368f6800130f98de7b5601c241bfef7977f`. *(Có file offline trong repo set-a.)*

## Tóm tắt đề
Phân tích pcap để tìm flag. Traffic chứa **rất nhiều POST tới `join.php`** kèm response **302 Found** và các truy cập `thanks.html`. Thực chất đây là log của một cuộc tấn công **time-based blind SQL injection** trích flag từng ký tự.

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
Mở pcap, xem Statistics → HTTP, thấy khối lượng lớn POST tới `/set-a/join.php` trả `302` redirect sang `thanks.html`. Form có 2 field `nickname` và `email`. Trong nhiều request, `nickname` chứa payload SQLi time-based (url-encoded), ví dụ giải mã:
```sql
test",(select sleep(IF(ascii(substr((select flag from flag),1,1)) = 32,5,0))));--
```
Ý nghĩa: lấy ký tự thứ `POS` của cột `flag` trong bảng `flag`, so mã ASCII với một giá trị thử `VAL`. Nếu đúng → `SLEEP(5)` → server trả lời chậm ~5s; sai → trả lời ngay.

**Chi tiết quyết định (đọc kỹ):** có **3705 request** như vậy. Kẻ tấn công quét **đầy đủ** mọi `VAL` từ 32..126 cho *mỗi* vị trí → **không thể** chỉ lấy "VAL lớn nhất" (luôn ra `~` = 126). **Bắt buộc dùng timing**: khi một request là TRUE, server ngủ 5s → **request kế tiếp bị trễ ~5s**. Vậy với mỗi vị trí, request mà *khoảng cách thời gian đến request kế* ≥ ~4s chính là request TRUE → `VAL` của nó là ký tự flag.

pcapng lưu timestamp trong **Enhanced Packet Block (EPB, block type `0x00000006`)**: 4 byte timestamp-high + 4 byte timestamp-low (đơn vị microsecond, tùy resolution), caplen ở offset 12 của body, dữ liệu gói bắt đầu offset 20.

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **Phân tích side-channel thời gian** trên pcap: ghép request↔độ trễ để suy nhánh TRUE.
- **VÌ SAO nhận ra:** đây là blind SQLi nên nội dung flag **không bao giờ** nằm trực tiếp trong traffic; chỉ suy ra qua thời gian. Ngưỡng 5s (`SLEEP(5)`) tách bạch TRUE (ngủ) với FALSE (phản hồi tức thì). Payload có `sleep(`, `IF(`, `ascii(substr(` là chữ ký time-based.
- **Công cụ:** parser pcapng tự viết (Python `struct`), hoặc `scapy`/`tshark` đọc timestamp.

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. Mở pcap, xác nhận mẫu `join.php` / 302 / `thanks.html` (Statistics → HTTP, Follow HTTP Stream một vài POST).
2. Parse trực tiếp pcapng, bắt `POS` và `VAL` trong payload, ghép theo timestamp (đã chạy thật, cho ra flag):
   ```python
   import struct, re
   data = open("blind_sqli.pcapng", "rb").read()
   pat = re.compile(rb'substr%28%28select\+flag\+from\+flag%29%2C(\d+)%2C1%29%29\+%3D\+(\d+)')
   off, events = 0, []                      # events = (timestamp_us, pos, val)
   while off + 8 <= len(data):
       btype = struct.unpack_from('<I', data, off)[0]
       blen  = struct.unpack_from('<I', data, off + 4)[0]
       if blen < 12 or off + blen > len(data):
           break
       body = data[off + 8: off + blen - 4]
       if btype == 0x00000006:              # Enhanced Packet Block
           th, tl = struct.unpack_from('<II', body, 4)
           ts = (th << 32) | tl
           caplen = struct.unpack_from('<I', body, 12)[0]
           pkt = body[20:20 + caplen]
           m = pat.search(pkt)
           if m:
               events.append((ts, int(m.group(1)), int(m.group(2))))
       off += blen
   events.sort()
   res = {}
   for i in range(len(events) - 1):
       ts, pos, val = events[i]
       if (events[i + 1][0] - ts) * 1e-6 >= 4.0:   # request này gây ngủ ~5s
           res[pos] = val
   print("".join(chr(res[p]) for p in sorted(res)))
   ```
   Output: `flag{https://youtu.be/wE11GYxsE7M` (vị trí 1..38). Ký tự cuối `}` (vị trí 39) là request cuối cùng, không có "request kế" để đo → bổ sung thủ công.
3. Phương án scapy: ghép request↔response theo cổng nguồn TCP / `tcp.stream`, lọc độ trễ > 5s, đọc `VAL` trong payload → `chr(VAL)`.

## Flag
flag{https://youtu.be/wE11GYxsE7M}

*(Nguồn canonical `SOLUTIONS_VN.md` — bài #11; ✅ đã tự khôi phục & xác minh từ timing của 3705 gói trên chính file pcap offline.)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** rất nhiều request gần giống nhau tới cùng endpoint, chỉ khác một tham số; payload có `sleep(`, `IF(`, `ascii(substr(`, `benchmark(`; response có 2 nhóm thời gian đáp ứng (nhanh vs ~5s) ⇒ time-based blind SQLi.
- **Quy trình:**
  1. Xác nhận mẫu qua HTTP statistics / Follow Stream.
  2. Trích (timestamp, payload) request và (timestamp) response; ghép theo cổng nguồn TCP / `tcp.stream`.
  3. Tính độ trễ, đặt ngưỡng ~ thời gian `sleep` (ở đây 5s, dùng ~4s cho an toàn).
  4. Giải mã (POS, VAL) từ payload, ghép lại.
- **Sai lầm phổ biến:** lấy "VAL lớn nhất/cuối cùng" → ra `~~~~` vì kẻ tấn công quét hết dải. **Bắt buộc dùng timing.**
- **Công cụ:** Wireshark (statistics, follow stream), parser `struct` tự viết, scapy/pyshark/tshark.
- **Bẫy:** ghép đúng cặp req-resp (nếu không timestamp lệch); payload URL-encoded (phải `unquote`); ký tự cuối có thể thiếu "request kế" → bổ sung tay.
- **Checklist:** [ ] nhận mẫu time-based [ ] xác định ngưỡng sleep [ ] ghép req/resp theo stream [ ] tính delay [ ] parse POS/ASCII [ ] ghép ký tự.
