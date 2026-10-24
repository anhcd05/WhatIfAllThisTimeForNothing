# wifi-capture

- **Category:** Network
- **File đề:** `wifi-capture/2c222708abc1c8406992bbb1e6004615.zip` (527704 bytes, md5 nhúng tên `2c222708abc1c8406992bbb1e6004615`, git blob sha1 `509896c75eb17456ac4448d769821e4060af42f4`). Giải nén ra file capture 802.11 (`.pcapng`/`.cap`).

## Tóm tắt đề

Một bản ghi gói tin Wi-Fi (802.11) **bị mã hóa WPA/WPA2**. Mục tiêu: tìm **IP server** mà client yêu cầu. Muốn đọc nội dung (IP/HTTP) phải bẻ mật khẩu Wi-Fi rồi giải mã capture.

## Phân tích (chi tiết)

**Nền tảng 802.11 + WPA.** Gói Wi-Fi ở lớp vô tuyến bị mã hóa WPA/WPA2; nội dung lớp IP/HTTP không đọc được nếu chưa có mật khẩu AP. Quy trình:
1. **Bắt 4-way handshake (EAPOL)** — có handshake mới brute được mật khẩu bằng wordlist.
2. **`aircrack-ng`** dùng wordlist dò mật khẩu từ handshake.
3. **`airdecap-ng`** dùng mật khẩu giải mã toàn bộ capture thành pcap thường.
4. Mở Wireshark đọc lớp IP/HTTP như bình thường.

Khái niệm: **ESSID** = tên mạng Wi-Fi; **BSSID** = MAC của AP.

Trinh sát:

```bash
unzip 2c222708abc1c8406992bbb1e6004615.zip   # ra file .pcapng/.cap 802.11
# Mở Wireshark: toàn frame 802.11 (Radiotap/Dot11), dữ liệu mã hóa.
```

Dữ liệu mã hóa nên không đọc IP ngay. Chỉ có **1 ESSID** trong file ⇒ đó là mạng mục tiêu. Có handshake EAPOL ⇒ brute được mật khẩu. Mật khẩu tìm ra: `pass1234` (yếu, wordlist như rockyou là đủ).

## Kỹ thuật áp dụng (+ VÌ SAO)

- **`aircrack-ng` brute mật khẩu từ handshake** — VÌ WPA không thể giải nếu không có khóa; handshake EAPOL cho phép brute offline bằng wordlist.
- **`airdecap-ng` giải mã capture** — VÌ sau khi có mật khẩu, cần biến traffic 802.11 mã hóa thành pcap IP đọc được.
- **Lọc HTTP + Follow TCP Stream** — VÌ mục tiêu là IP server client yêu cầu; theo stream sẽ thấy IP đích.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

```bash
# (nếu cần) chuyển pcapng -> cap:
tshark -F pcap -r WLANcapture.pcapng -w WLANcapture.cap   # hoặc Wireshark 'Save As'

# Bước 1: bẻ mật khẩu WPA từ handshake:
aircrack-ng -w wordlist.txt WLANcapture.cap
#   -> KEY FOUND! [ pass1234 ]   (ESSID duy nhất trong file)

# Bước 2: giải mã toàn bộ capture:
airdecap-ng -e <ESSID> -p pass1234 WLANcapture.cap
#   -> tạo WLANcapture-dec.cap (đã giải mã)

# Bước 3: mở WLANcapture-dec.cap trong Wireshark, lọc http / Follow TCP Stream,
#   xem client request tới server nào -> IP đích = 192.168.11.202
```

Cách khác: nhập thẳng khóa WPA vào Wireshark (`Preferences > IEEE 802.11 > Decryption keys`, dạng `wpa-pwd: pass1234:ESSID`) thay cho `airdecap`.

## Flag

```
flag{192.168.11.202}
```

IP server mà client yêu cầu (lấy được sau khi giải mã WPA).

## Gặp lại thì xử lý thế nào (playbook)

1. Capture toàn frame 802.11 mã hóa ⇒ cần mật khẩu WPA; tìm 4-way handshake EAPOL.
2. `aircrack-ng -w <wordlist>` để brute; mật khẩu yếu thì rockyou là đủ.
3. Giải mã bằng `airdecap-ng -e <ESSID> -p <pass>`, hoặc nhập `wpa-pwd:pass:ESSID` trong Wireshark.
4. Sau giải mã, lọc `http`/`dns`, Follow Stream để lấy IP/đối tượng cần.
5. Thiếu handshake EAPOL ⇒ không brute được; kiểm tra bằng `Statistics` hoặc filter `eapol`.
