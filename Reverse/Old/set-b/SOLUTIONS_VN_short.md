# Tuyển tập challenge — Set B — Lời giải chi tiết (Tiếng Việt)

> Bản tổng hợp & viết lại lời giải cho bộ challenge **Set B** (bản ngắn gọn).

## Tổng quan

**Set B** là một tuyển tập challenge CTF thể thức **Jeopardy** (nhiều bài độc lập, chia theo category).

Các category: **Binary, OS (Reverse/OS), Web, Forensic, Network, MISC, Crypto**.

> Ghi chú về repo: đây là repo *writeup*, nhiều bài trình bày bằng ảnh chụp màn hình (PNG) kèm README.
> Một số thư mục có `README.md` **rỗng** (0 byte) → repo không kèm lời giải cho bài đó; những bài này được
> phân tích tĩnh ở mức có thể. **Không bài nào được chạy/execute binary** — chỉ phân tích tĩnh.

## Bảng challenge

| # | Tên | Category | Điểm | Độ khó | Flag |
|---|-----|----------|------|--------|------|
| 1 | reversed-name | MISC | 20 | Dễ | `flag{RLO_Disrupt_U}` |
| 2 | layered-pdf | MISC | 20 | Dễ | `flag{dog_monkey_grandpa}` |
| 3 | fake-extension | MISC | 30 | Dễ | `flag{DoNotTrustTheApparentExtension}` |
| 4 | nested-encoding | MISC | 50 | Dễ-TB | `flag{jp_bmllc2k=}` |
| 5 | twin-files | MISC | 100 | TB | `flag{File0623_79054025255fb1a26e4bc422aef54eb4}` |
| 6 | libssh-bypass | MISC | 100 | TB | *(không có trong repo)* — CVE-2018-10993 |
| 7 | hidden-message | MISC | 150 | ? | *(README rỗng — repo không có lời giải)* |
| 8 | trimmed-auth | MISC | 150 | ? | *(README rỗng — repo không có lời giải)* |
| 9 | number-canvas | Crypto | 50 | TB | `flag{PLUCK}` |
| 10 | fullwidth-mail | Crypto | 50 | Dễ-TB | `flag{Th3_Emb3zzl3r_15_Fumie}` |
| 11 | layered-powershell | Crypto | 200 | TB | `flag{Fileless_Malware_Often_Uses_ShellScript}` |
| 12 | intro-binary | Binary | 50 | Dễ | *(README rỗng — repo không có lời giải)* |
| 13 | long-delay | Binary | 100 | Dễ-TB | `flag{s133p1ng_f0r3st}` |
| 14 | debugger-gift | Binary | 100 | TB | `flag{TEST_EASY_IS_DEBUGGER_PRESENT!!}` |
| 15 | managed-branch | Binary | 120 | TB | `flag{dotN3T_pr0gr4m_de6ugg1ng_1s_e4sy}` |
| 16 | tls-unlock | Binary | 150 | TB | `flag{cf8236571e9dd3bcaf44b188bba4f15d}` |
| 17 | path-lookup | OS | 60 | ? | *(README rỗng — repo không có lời giải)* |
| 18 | session-record | OS | 70 | ? | *(README rỗng — repo không có lời giải)* |
| 19 | missing-library | OS | 110 | TB | `flag{specify_the_library}` |
| 20 | calculator | OS | 180 | ? | *(README rỗng — repo không có lời giải)* |
| 21 | fuzzy-match | Forensic | 50 | ? | *(README rỗng — repo không có lời giải)* |
| 22 | broken-zip-header | Forensic | 60 | TB | *(writeup dở dang — chưa có flag)* |
| 23 | startup-artifact | Forensic | 80 | ? | *(README rỗng — repo không có lời giải)* |
| 24 | notes-artifact | Forensic | 120 | ? | *(README rỗng — repo không có lời giải)* |
| 25 | pdf-images | Forensic | 120 | ? | *(README rỗng — repo không có lời giải)* |
| 26 | intact-capture | Network | 80 | ? | *(README rỗng — repo không có lời giải)* |
| 27 | wifi-capture | Network | 150 | TB | `flag{192.168.11.202}` |
| 28 | jwt-none-auth | Web | 150 | TB | `flag{SXMgdGhlIGNvcnJlY3QgYW5zd2VyISBDb25ncmF0cyE}` |
| 29 | router-firmware-upload | Web | 150 | TB | `flag{94550b955569733446ebf2105ed54e9c22276d912befab7a4c}` |
| 30 | struts-tomcat-rce | Web | 150 | TB | *(không có trong repo)* — Struts2/Tomcat RCE |
| 31 | captcha-ocr | Web | 200 | TB | *(không có trong repo — có script giải)* |
| 32 | loose-comparison | Web | 200 | ? | *(README rỗng — repo không có lời giải)* |
| 33 | waf-bypass | Web | 250 | ? | *(README rỗng — repo không có lời giải)* |

---

## 1. reversed-name — `flag{RLO_Disrupt_U}`

**Đề:** chạy `7904ba4cdb3b1cb4c6a9f767c9ef065c.exe` trên Windows, nó tạo ra nhiều file 0 byte với tên kỳ lạ.

**Phân tích:** Tên file dùng ký tự Unicode **RLO (U+202E, Right-to-Left Override)** để đảo chiều hiển thị
phần sau nó. Mỗi file có đoạn `?_` (thực ra là ký tự ẩn + RLO). Ký tự *đứng ngay trước* `?_` theo thứ tự thời
gian (`dir /O:D`) ghép lại thành flag. Ví dụ `...abcde?_...` → ký tự sau "e" là "f".

**Flag:** `flag{RLO_Disrupt_U}`

## 2. layered-pdf — `flag{dog_monkey_grandpa}`

**Đề:** một file PDF, flag bị che bằng khối đen. (File đề bị mất trong repo.)

**Phân tích & lời giải:** flag gồm 3 phần ở 3 nơi khác nhau:
- Phần 1: là **ảnh** đè lên text → chuột phải "Save image as" để lộ `flag{dog_...}`.
- Phần 2: là **text thật** nằm dưới khối đen → bôi đen + copy ra `..._monkey_...`.
- Phần 3: nằm trong **metadata** PDF → `exiftool challenge.pdf`.

**Flag:** `flag{dog_monkey_grandpa}`

## 3. fake-extension — `flag{DoNotTrustTheApparentExtension}`

**Đề:** file `notepad_...zip`. Giải nén được một file *trông như* .txt nhưng thực chất là loại khác (phần mở
rộng giả — có thể dùng RLO hoặc icon giả). Flag nói thẳng bài học: đừng tin phần mở rộng hiển thị.

**Flag:** `flag{DoNotTrustTheApparentExtension}`

## 4. nested-encoding — `flag{jp_bmllc2k=}`

**Đề:** bảng A|B, A là mã quốc gia 2 ký tự, B là chuỗi. Điền `●|■` còn thiếu.

**Phân tích:**
1. B là **Base64** → decode ra chuỗi lộn xộn (chỉ `au`→`sydney` là đọc được).
2. Áp **ROT (Caesar)** với bước tăng dần -2, -4, -6... theo từng dòng → ra tên thành phố.
3. Đây là **các thành phố đăng cai Olympic**: Sydney(2000), Athens(2004), Beijing(2008), London(2012),
   Rio(2016), **Tokyo(2020)**, Paris(2024), LA(2028)...
4. Dòng `●|■` thiếu chính là **Tokyo 2020 → `jp`**. Mã hóa "tokyo" bằng ROT20 → `niesi` → Base64 `bmllc2k=`.

**Flag:** `flag{jp_bmllc2k=}`  *(đã kiểm chứng: ROT20("tokyo")="niesi", base64="bmllc2k=")*

## 5. twin-files — `flag{File0623_79054025255fb1a26e4bc422aef54eb4}`

**Đề:** trong File001..File999, tìm file **cùng đặc điểm** với `File`, kèm bằng chứng.

**Phân tích:** `File` và `File0623` có **cùng md5sum** = `79054025255fb1a26e4bc422aef54eb4`.
Đây chính là giá trị MD5 nổi tiếng trong **cặp va chạm MD5 (MD5 collision)** của Wang et al. — hai file **khác
nhau** nhưng **cùng MD5**. "Đặc điểm chung" = cùng MD5 dù nội dung khác (minh họa MD5 không an toàn chống va chạm).

**Flag:** `flag{File0623_79054025255fb1a26e4bc422aef54eb4}`

## 6. libssh-bypass — libSSH auth bypass (CVE-2018-10993)

**Đề:** target `10.3.204.203:2222`. `nc` thấy banner `SSH-2.0-libssh_0.8.1`.

**Phân tích & lời giải:** libssh 0.8.1 dính **CVE-2018-10993** — bypass xác thực bằng cách gửi
`SSH2_MSG_USERAUTH_SUCCESS` từ phía client. Dùng PoC public:
```
python exploitssh.py 10.3.204.203 -p 2222 -c "cat flag.txt"
```
**Flag:** *không ghi trong repo.*

## 7. hidden-message
⚠️ **Repo không có lời giải sẵn** (README rỗng, không có file đề). Tên gợi ý steganography/ẩn thông điệp.

## 8. trimmed-auth
⚠️ **Repo không có lời giải sẵn** (README rỗng). Tên gợi ý lỗi auth do *trim/whitespace* trong so khớp.

## 9. number-canvas — `flag{PLUCK}`

**Đề:** một đoạn Base64 lớn.

**Phân tích:**
1. Base64 decode → một khối số dài (chỉ gồm 0-8).
2. Đây là **stego dạng ASCII-art**: khi tô sáng các ký tự `0` và `8` trong khối số, chúng tạo hình chữ
   **"PLUCK"** (xem `the_sword.png`).

**Flag:** `flag{PLUCK}`

## 10. fullwidth-mail — `flag{Th3_Emb3zzl3r_15_Fumie}`

**Đề:** email chứa chuỗi `/EF/BC/B6/EF/BC/A7/...`.

**Phân tích:**
1. Chuỗi `/EF/BC/B6/...` là **các byte UTF-8** của ký tự **fullwidth** (ví dụ `Ｖ`=EF BC B6).
2. Unhex → ra chuỗi fullwidth; chuẩn hóa **NFKC** (fullwidth→ASCII) → Base64 `VGgzX0VtYjN6emwzcl8xNV9GdW1pZQ==`.
3. Base64 decode → `Th3_Emb3zzl3r_15_Fumie`.

**Flag:** `flag{Th3_Emb3zzl3r_15_Fumie}`  *(đã kiểm chứng toàn bộ chuỗi)*

## 11. layered-powershell — `flag{Fileless_Malware_Often_Uses_ShellScript}`

**Đề:** một blob Base64 lớn.

**Phân tích (nhiều lớp):**
1. Base64 decode → một **PowerShell one-liner** dạng `((( <danh sách số> ) | %{[char]$_}) -Join '') | &(...)`.
2. Danh sách số là **mã ASCII** → ghép lại thành script PowerShell thật:
   hàm `ShowDummyFlag($flag)` tính MD5 phần trong `{}` rồi được gọi với
   `ShowDummyFlag("flag{Fileless_Malware_Often_Uses_ShellScript}")`.
3. Flag nằm ngay trong tham số truyền vào.

**Flag:** `flag{Fileless_Malware_Often_Uses_ShellScript}`

## 12. intro-binary
⚠️ **Repo không có lời giải sẵn** (README rỗng). Có file đề `...bdb5baaf...zip` (6.9 KB). Bài nhập môn 50đ.

## 13. long-delay — `flag{s133p1ng_f0r3st}`

**Đề:** ELF `sleep` chạy rất lâu (delay khổng lồ).

**Phân tích & lời giải:**
1. Mở bằng IDA, tìm chuỗi "sleepy" → thấy hằng delay `0x2600000000`.
2. **Patch** hằng số này về `0`, lưu thành `sleep-patched`.
3. Chạy bản patched → in ngay: `I'm so sleepy...` rồi `Flag is s133p1ng_f0r3st`.

**Flag:** `flag{s133p1ng_f0r3st}`

## 14. debugger-gift — `flag{TEST_EASY_IS_DEBUGGER_PRESENT!!}`

**Đề:** `present.exe` chỉ in `Oops...`.

**Phân tích & lời giải:**
1. PEiD cho thấy file bị đóng gói **UPX** → unpack (`upx -d`) ra `present-unpack.exe`.
2. Nạp IDA, tìm chuỗi `Oops` → có lệnh `jz short loc_4014E7` trước khi in "Oops".
   Đây là anti-debug kiểu `IsDebuggerPresent` (tên flag gợi ý).
3. **Patch** `jz`→`jnz` để đi vào nhánh đúng → chương trình in Base64
   `ZmxhZ3tURVNUX0VBU1lfSVNfREVCVUdHRVJfUFJFU0VOVCEhfQ==` → decode ra flag.

**Flag:** `flag{TEST_EASY_IS_DEBUGGER_PRESENT!!}`

## 15. managed-branch — `flag{dotN3T_pr0gr4m_de6ugg1ng_1s_e4sy}`

**Đề:** `fee201a96c8e30d09141f7493457f1b6.exe` in ra một chuỗi Base64 → decode ra fake flag `flag{th1s_1s_dummy_f14g}`.

**Phân tích & lời giải:**
1. File là **.NET** → decompile bằng **dnSpy**.
2. Có if-block kiểm tra biến `flag`(bool); nhánh true mới in flag thật.
3. Trong dnSpy, đặt breakpoint ở Entry Point, chạy, **sửa biến `flag`=true** khi runtime → in Base64
   `ZmxhZ3tkb3ROM1RfcHIwZ3I0bV9kZTZ1Z2cxbmdfMXNfZTRzeX0=`.

**Flag:** `flag{dotN3T_pr0gr4m_de6ugg1ng_1s_e4sy}`
⚠️ **Đính chính:** README gốc ghi nhầm `cflag{...}` (thừa chữ "c"). Flag đúng bắt đầu bằng `flag{`.

## 16. tls-unlock — `flag{cf8236571e9dd3bcaf44b188bba4f15d}`

**Đề:** zip chứa `unlock.pcapng` và khóa riêng `server.key`.

**Phân tích & lời giải:**
1. `tree` thấy `server.key` (RSA private key của server).
2. Trong pcap có GET `flag.txt` nhưng server redirect sang **HTTPS** → traffic bị mã hóa TLS.
3. Nạp `server.key` vào Wireshark (RSA keys list) → giải mã TLS → Follow > TLS Stream đọc được flag.
   *(Chỉ hoạt động với TLS dùng RSA key exchange, không phải (EC)DHE forward-secrecy.)*

**Flag:** `flag{cf8236571e9dd3bcaf44b188bba4f15d}`

## 17-18, 20. Which / Record / Calc (OS)
⚠️ **Repo không có lời giải sẵn** (README rỗng, không có file đề). Nhóm bài OS/Reverse.

## 19. missing-library — `flag{specify_the_library}`

**Đề:** zip gồm `main.exe` (ELF x86-64) và `libflag.so`. Chạy `main.exe` báo lỗi.

**Phân tích & lời giải:**
1. `strace ./main.exe` thấy nó cố `open` `libflag.so` ở **rất nhiều thư mục** khác nhau nhưng đều thiếu.
2. **Copy `libflag.so`** vào các thư mục mà strace cho thấy nó tìm (hoặc đặt `LD_LIBRARY_PATH`).
3. Chạy lại → in `flag{specify_the_library}`.

**Flag:** `flag{specify_the_library}`

## 21. fuzzy-match
⚠️ **Repo không có lời giải sẵn** (README rỗng). File đề: `Fuzzy_8648...exe` + `Fuzzy_b863...zip`.
Tên "Fuzzy" gợi ý **fuzzy hashing (ssdeep)** để tìm độ tương đồng.

## 22. broken-zip-header — *writeup dở dang*

**Đề:** zip hỏng không giải nén được.

**Phân tích (từ writeup gốc, còn "Under Construction"):**
1. 4 byte đầu là `DE AD BE EF` (giả) → sửa thành magic ZIP `50 4B 03 04` (PK\x03\x04) bằng vim+xxd.
2. Sau đó `Filename Length` trong Local Header bị sai (`1F55`=8021) → tên file "nuốt" cả dữ liệu, CRC sai.
   Cần sửa lại trường độ dài tên file về đúng (`important.bmp` = 13 ký tự) để rút được `important.bmp`.
3. `important.bmp` (BMP) nhiều khả năng chứa flag ẩn (stego/sửa header).

⚠️ **Repo chưa hoàn thành bài này — không có flag.**

## 23-25. Starting / Notes / PDF-JPGS (Forensic)
⚠️ **Repo không có lời giải sẵn** (README rỗng). PDF-JPGS gợi ý tách ảnh JPG nhúng trong PDF.

## 26. intact-capture
⚠️ **Repo không có lời giải sẵn** (README rỗng). File đề: `Intact_8688...pcapng` (12 KB). Phân tích gói tin.

## 27. wifi-capture — `flag{192.168.11.202}`

**Đề:** pcap bắt gói **802.11 (WiFi)**. Tìm IP server mà client yêu cầu.

**Phân tích & lời giải:**
1. Convert pcapng→pcap. Chỉ có 1 ESSID.
2. Bẻ khóa WPA bằng `aircrack-ng` → mật khẩu AP là `pass1234`.
3. Giải mã traffic: `airdecap-ng -e <ESSID> -p pass1234 ...` → `WLANcapture-dec.pcap`.
4. Mở Wireshark → thấy client request tới server **192.168.11.202**.

**Flag:** `flag{192.168.11.202}`

## 28. jwt-none-auth — `flag{SXMgdGhlIGNvcnJlY3QgYW5zd2VyISBDb25ncmF0cyE}`

**Đề:** web có đăng ký/đăng nhập, trả về **JWT**. Trang chính trả 401.

**Phân tích & lời giải (JWT `alg:none`):**
1. JWT trả về chứa trường `auth` nhưng **không có chữ ký và không có thuật toán** (dạng `alg:none`).
2. Tự tạo JWT mới với `auth=1` (dùng CyberChef) — vì server không verify chữ ký.
3. Thay header `Authorization` → server trả toàn bộ dữ liệu user (có flag).

**Flag:** `flag{SXMgdGhlIGNvcnJlY3QgYW5zd2VyISBDb25ncmF0cyE}`
*(phần trong `{}` giải Base64 ra "Is the correct answer! Congrats!")*

## 29. router-firmware-upload — `flag{94550b955569733446ebf2105ed54e9c22276d912befab7a4c}`

**Đề:** web quản trị router `10.3.204.206`.

**Phân tích & lời giải:**
1. **Bypass login** bằng cách gửi `password` dạng **mảng** (`password[]=`) → ứng dụng PHP so sánh lỏng lẻo
   (type juggling / `strcmp` với array trả NULL) → đăng nhập được.
2. Chức năng "Update Firmware" cho upload **ZIP**; file mẫu `1.1.zip` gồm 1 PHP + 1 TXT.
3. **Chèn webshell** `<?php system($_POST['cmd']); ?>` vào file PHP, nén lại, upload → "Check update result".
4. RCE: chạy `ls` thấy `flag.php` → `cat flag.php` lấy flag.

**Flag:** `flag{94550b955569733446ebf2105ed54e9c22276d912befab7a4c}`

## 30. struts-tomcat-rce — Struts2/Tomcat RCE

**Đề:** target chạy **Apache Tomcat 7.0.96** (thấy ở trang 404).

**Phân tích & lời giải:** dựa gợi ý "well-known vulnerability" → dùng exploit public (Struts2 OGNL RCE) để
chạy lệnh trên server và đọc flag. **Flag không ghi trong repo.**

## 31. captcha-ocr — *script giải có, flag runtime*

**Đề:** server yêu cầu giải CAPTCHA đúng 1000/1000 lần để lấy flag.

**Phân tích & lời giải:** script `captcha.py` (Python 2): lặp tải ảnh `/image`, dùng **OCR `gocr`** nhận dạng,
hiệu chỉnh ký tự dễ nhầm (`_`→`Q`, `f`→`F`, loại kết quả có `O`/`0`), rồi POST tới `/challenge`. Khi đạt
`1000/1000` server in flag. **Flag không ghi trong repo** (xuất hiện lúc chạy thật).

## 32-33. operand mistake / WAF (Web)
⚠️ **Repo không có lời giải sẵn** (README rỗng). WAF(250) gợi ý bypass Web Application Firewall;
"operand mistake" gợi ý lỗi so sánh/toán tử (type juggling, v.v.).

---

## Phụ lục: hash file đề (đối chiếu toàn vẹn)

Một số file đề nhỏ đã tải và tính md5/sha1 THẬT (không execute):

| File | md5 (tính thật) | Khớp tên file? |
|------|-----------------|----------------|
| Shared .zip | `04dca129c011213979aded2e7bef71d3` | ✅ khớp |
| Intact .pcapng | `8688e1a1263c414450b12985e0d5620b` | ✅ khớp |
| notepad .zip | `44b9e842fc87324c1f756c61835ee62a` | ⚠️ KHÁC tên (`2976ac4a...`) |
| Binary_Ultra .zip | `0e22e8be56bb87af3be9a21c04ac4f59` | ⚠️ KHÁC tên (`bdb5baaf...`) |
| fee201a96c8e30d09141f7493457f1b6.exe | `fee201a96c8e30d09141f7493457f1b6` | (tên chỉ ghi "fee") |

> Bản chi tiết (PASS 2) bổ sung đầy đủ hash + phân tích sâu từng bài.
