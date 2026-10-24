# ftp-capture

- **Category:** Forensics — khôi phục file truyền qua FTP trong bản bắt gói.
- **File đề:** `D8-ftp-capture/capture_8688e1a1263c414450b12985e0d5620b.pcapng`
  - Kích thước: **12 040 byte**, MD5 `8688e1a1263c414450b12985e0d5620b` (= tên file)
  - SHA1: `069549649cb3e41bcaba9a2c6f5a62cf4b6b2bb1`

## Tóm tắt đề
Cho một file bắt gói, phần lớn là lưu lượng FTP. Trong phiên FTP có truyền một file zip chứa flag (đã đặt mật khẩu) và một file ghi chú chứa mật khẩu. Phải khôi phục cả hai file từ pcap, giải nén và đọc flag. Phân tích **tĩnh** (đọc gói, carve file), không chạy gì nguy hiểm.

## Phân tích (chi tiết)
**Nền tảng FTP:**
- **FTP không mã hoá:** mọi thứ — username, password, lệnh, nội dung file — đều đi **chữ rõ (cleartext)**. Ai bắt gói là đọc được tất cả. Đây chính là thông điệp của bài (và của flag).
- **Hai kênh:** *control* (thường cổng 21) mang lệnh (`USER`, `PASS`, `LIST`, `RETR` tải file, `STOR` gửi file, `TYPE` ASCII/binary); *data* mang nội dung file/kết quả LIST, mở riêng cho mỗi lần truyền.
- **Active mode & lệnh `PORT`:** client bảo server kết nối data về `PORT h1,h2,h3,h4,p1,p2`, trong đó IP = `h1.h2.h3.h4` và **cổng data = p1×256 + p2**. Biết công thức này để lần đúng luồng TCP chứa file.

**Trinh sát:**
```bash
# Wireshark -> Statistics -> Protocol Hierarchy: gần như toàn bộ là FTP + FTP-DATA
strings capture_8688e1a1263c414450b12985e0d5620b.pcapng | grep -iE 'USER|PASS|RETR|PORT|LIST|passmemo|FLAG'
```

**Follow TCP Stream kênh control** cho nguyên văn:
```
220 Microsoft FTP Service
USER ftpuser
PASS Pass#ftp18                 <- mật khẩu lộ cleartext
230 User logged in.
PORT 192,168,11,242,78,73       -> cổng data = 78*256+73 = 20041
200 PORT command successful.
LIST
  12-18-18  03:09PM      4709 FLAG.zip
  12-17-18  05:53PM        49 passmemo.txt
TYPE I                          <- chuyển sang binary
PORT 192,168,11,242,78,74       -> cổng data = 20042
RETR FLAG.zip                   <- tải FLAG.zip (4709 byte)
PORT 192,168,11,242,78,77       -> cổng data = 20045
RETR passmemo.txt               <- tải passmemo.txt (49 byte)
```

**Giải mã các lệnh PORT → cổng data (để biết luồng TCP nào mang file nào):**

| Lệnh PORT | p1,p2 | Tính | Cổng data | Dùng cho |
|-----------|-------|------|-----------|----------|
| `PORT 192,168,11,242,78,73` | 78,73 | 78×256+73 | **20041** | `LIST` |
| `PORT 192,168,11,242,78,74` | 78,74 | 78×256+74 | **20042** | `RETR FLAG.zip` |
| `PORT 192,168,11,242,78,77` | 78,77 | 78×256+77 | **20045** | `RETR passmemo.txt` |

**Nội dung `passmemo.txt`** (lấy từ luồng data 20045):
```
FLAG.zip   Do_you_use_FTP?
```
⇒ **mật khẩu của FLAG.zip là `Do_you_use_FTP?`**. Trong `strings` cũng thấy mảnh `PK` (chữ ký zip) và tên `FLAG.GIF` (file bên trong zip).

Đây là active mode (có lệnh `PORT`), không phải passive (`PASV`) — mỗi lần truyền mở một cổng data mới, nên mỗi file nằm ở một luồng TCP riêng.

## Kỹ thuật áp dụng (CVE cụ thể nếu có + VÌ SAO)
- **Không có CVE.** Bài forensics: carve file từ pcap + giải nén zip có mật khẩu.
- **Carve file từ pcap FTP (FTP-DATA stream).**
  - VÌ SAO: FTP truyền file dưới dạng byte thô trên kết nối data; `RETR FLAG.zip` / `RETR passmemo.txt` cho biết chính xác tên và luồng cần khôi phục (xác định qua cổng data từ lệnh `PORT`). Có thể export thủ công từng TCP stream, hoặc `binwalk` tự nhận chữ ký (zip `PK\x03\x04`, GIF `GIF8`) và tách — nhanh hơn.
- **Giải nén zip có mật khẩu bằng mật khẩu lấy từ file ghi chú** (`passmemo.txt` truyền *cùng kênh* với file — sai lầm kép: lộ cả khoá lẫn dữ liệu).

## Lời giải chi tiết (bước + code/lệnh/payload sạch)
1. Mở pcap, Follow TCP Stream kênh control → lấy tên file (`FLAG.zip`, `passmemo.txt`), mật khẩu đăng nhập, và các lệnh `PORT` để tính cổng data.
2. **Lấy mật khẩu zip:** đọc luồng data 20045 (`passmemo.txt`) → `Do_you_use_FTP?`.
3. **Cách nhanh — binwalk carve thẳng từ pcap:**
   ```bash
   binwalk -e capture_8688e1a1263c414450b12985e0d5620b.pcapng
   # Tạo thư mục _capture_...pcapng.extracted/ chứa file zip (vd 10BE.zip) + FLAG.GIF
   ```
4. **Giải nén zip bằng mật khẩu đã biết:**
   ```bash
   cd _capture_8688e1a1263c414450b12985e0d5620b.pcapng.extracted/
   unzip 10BE.zip
   # [10BE.zip] FLAG.GIF password:  -> nhập: Do_you_use_FTP?
   #   inflating: FLAG.GIF
   ```
   Nhớ quote mật khẩu khi truyền qua shell vì có ký tự đặc biệt (`?`, `#`): `unzip -P 'Do_you_use_FTP?' 10BE.zip`.
5. Mở `FLAG.GIF` → ảnh hiển thị flag.

**Cách thủ công (không binwalk):** trong Wireshark đặt filter `tcp.port == 20042`, *Follow TCP Stream → Show data as Raw → Save as* `FLAG.zip`; làm tương tự với cổng 20045 cho `passmemo.txt`; rồi `unzip FLAG.zip` với mật khẩu `Do_you_use_FTP?`. (Hoặc *File → Export Objects → FTP-DATA*.)

## Flag
flag{It's_dangerous_to_use_FTP}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** pcap nhiều FTP; thấy lệnh `RETR <file>`/`STOR <file>`; có file nén kèm file ghi chú/mật khẩu.
- **Quy trình:**
  1. Follow FTP control: lấy `USER`/`PASS`, danh sách `RETR`/`STOR`, lệnh `PORT`/`PASV` (xác định kết nối data).
  2. Với mỗi file: Follow TCP stream kết nối data → Save as raw, HOẶC `binwalk -e` để tự carve.
  3. Đọc file ghi chú lấy mật khẩu zip.
  4. Giải nén zip; không có mật khẩu thì brute bằng `fcrackzip`/`john`.
- **Công cụ:** Wireshark (Follow TCP Stream / Export Objects), `binwalk`, `foremost`, `tshark`, `NetworkMiner`, `unzip`, `fcrackzip`.
- **Bẫy:**
  - FTP control và data là HAI kết nối khác nhau; file nằm ở data (cổng do `PORT`/`PASV`), không ở stream control.
  - Tên file sau khi binwalk tách có thể là offset (`10BE.zip`) chứ không phải `FLAG.zip` — vẫn là file đó.
  - Khi export raw, cắt đúng ranh giới file (binwalk nhận magic header giúp tránh lệch byte).
  - Mật khẩu có ký tự đặc biệt (`?`, `#`) — nhớ quote khi truyền qua shell.
- **Checklist ngắn:** đọc FTP control → carve file data (binwalk/follow stream theo cổng) → lấy mật khẩu từ ghi chú → unzip → mở ảnh/flag.
