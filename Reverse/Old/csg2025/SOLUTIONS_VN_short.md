# Cyber SEA Game 2025 — Lời giải chi tiết (Tiếng Việt)

> Tổng hợp & viết lại từ writeup gốc trong repo [kaisonox/CTFs](https://github.com/kaisonox/CTFs),
> thư mục con `2025-Cyber-SEA-Game`. Toàn bộ phân tích là **tĩnh** (không chạy
> binary/exe tải về). Writeup gốc chỗ nào thiếu bước, mình bổ sung suy luận.

---

## 1. Tổng quan giải

**Cyber SEA Game** là giải CTF khu vực Đông Nam Á (SEA), phiên bản 2025 gồm nhiều
thể loại: reverse engineering (dịch ngược), forensics (điều tra số), crypto (mật
mã), stego (giấu tin), misc (hỗn hợp) và một bài thiên hướng pwn/cloud. Các challenge
trong repo được đặt tên theo **tên quốc gia** (Angola, Australia, China…) kèm mã
bài (C1, N1, R6…) — đây là cách BTC đánh số đề.

Định dạng flag chuẩn của giải là `CSG_FLAG{...}` (CSG = Cyber SEA Game). Một vài
bài ngoại lệ: Angola chỉ trả về một "mật khẩu" trần, Australia là bài thao tác hệ
thống (mục tiêu là tắt máy chứ không có chuỗi flag).

### Giải thích nhanh vài thuật ngữ dùng xuyên suốt

- **Flag**: chuỗi bí mật cần tìm để nộp, chứng minh đã giải được bài.
- **Base64**: cách mã hoá dữ liệu nhị phân thành ký tự chữ-số an toàn để truyền. Giải mã (decode) để lấy lại dữ liệu gốc.
- **XOR**: phép "hoặc loại trừ" trên từng bit; tính chất quan trọng: `A XOR B XOR B = A`, nên XOR hai lần cùng một khoá sẽ khôi phục dữ liệu gốc. Là nền của nhiều mã dòng.
- **Hex (hexadecimal)**: hệ cơ số 16, mỗi byte viết thành 2 ký tự `00`–`ff`.
- **PE (Portable Executable)**: định dạng file `.exe`/`.dll` của Windows; luôn bắt đầu bằng 2 byte `MZ`.
- **RC4 / AES**: hai thuật toán mã hoá. RC4 là mã dòng (stream); AES là mã khối (block), ở đây dùng chế độ ECB.
- **PCAP**: file bắt gói tin mạng (dùng Wireshark/tshark/scapy để mổ xẻ).

### Bảng challenge

| # | Tên bài (thư mục) | Quốc gia / mã | Category | Độ khó | Flag |
|---|---|---|---|---|---|
| 1 | Do You Think I'm Fragile | Angola / C2 | misc / scripting | Trung bình | `F1r3NIc3$4Lyfe` (mật khẩu, không có `CSG_FLAG{}`) |
| 2 | M1 (shutdown) | Australia / M1 | misc / cloud / pwn | Dễ–TB | *(không có chuỗi flag — mục tiêu: tắt máy)* |
| 3 | A Very Old Odd File | Central African Rep. / C6 | misc / encoding | Trung bình | `CSG_FLAG{PUNCHCARDSAREDEADNOW}` |
| 4 | C1 | China / C1 | crypto | Dễ–TB | `CSG_FLAG{Wont_U_make_Lemonade}` |
| 5 | Plato | DR Congo / C2 | forensics / stego | Trung bình | `CSG_FLAG{Yay!==You-are-successfully-decoded-Vigenere-cipher-inside-pictures!-Congratulations!!}` |
| 6 | N1 | France / N1 | crypto / stego | Khó | *(flag host trên S3 — xem phần phân tích; QR + SSE-C)* |
| 7 | Silent Call, Loud Message | Germany / N2 | forensics / network | Trung bình | `CSG_FLAG{Y0UAREDECODEDV01P}` |
| 8 | Packer | Greece / R2 | reverse | Trung bình | `CSG_FLAG{packer_daisuki}` |
| 9 | Matryoshka | R6 | reverse / web (PHP) | Dễ–TB | `CSG_FLAG{A_Matryoshka_Obfuscated_Script}` |
| 10 | Corrupted | Saudi Arabia / R1 Q1 | reverse | Dễ | `CSG_FLAG{finding_the_magic_now!}` |
| 11 | Fake C2 | Sweden / R3 | reverse (Go) | Dễ–TB | `CSG_FLAG{go_rev_startingpoint}` |
| 12 | Betrayer | Switzerland / N4 | forensics / network | Khó | `CSG_FLAG{bob::WINDOMAIN:46f4...}` (xem đầy đủ bên dưới) |
| 13 | S3 | Tanzania / S3 | forensics / stego | Dễ–TB | `CSG_FLAG{Y0u-Are-Found-Hidd3n-Fi1e}` |
| 14 | csg_ctf | Zambia / C4 | reverse / crypto | Trung bình | `CSG_FLAG{001112233446cDdefL}` |

**Phân loại theo category:** Reverse: 5 (Greece, R6, Saudi, Sweden, Zambia) · Forensics/Network/Stego: 4 (Congo, Germany, Switzerland, Tanzania) · Crypto: 2 (China, France) · Misc/Encoding: 2 (Angola, C6) · Misc/Cloud/Pwn: 1 (Australia).

---

## 2. Angola C2 — Do You Think I'm Fragile

**Category:** misc / scripting · **Flag:** `F1r3NIc3$4Lyfe`

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/Angola_C2_DoYouThinkImFragile/`
- `kimpampara.txt` — một chuỗi dữ liệu mã hoá
- `command.txt` — batch script Windows đã được giải ra (để tham khảo)
- `unf0rgiven.zip`, `solve.py`

### Phân tích (từng bước, giải thích tại sao)
1. **Nhận diện lớp mã hoá.** `kimpampara.txt` nhìn như base64. Decode một lần ra vẫn là base64 → **base64 hai lần** (double Base64). Đây là mẹo che giấu rất phổ biến: mỗi lần decode "bóc" một lớp vỏ.
2. **Sau khi decode 2 lần**, kết quả không phải văn bản thường mà là dãy các điểm mã Unicode dạng `U+HHHH` (ví dụ `U+0040`). Vì sao? Vì tác giả biểu diễn từng ký tự của script dưới dạng codepoint để tránh lộ nội dung khi nhìn thô. Ta chỉ cần lấy phần hex `HHHH` của mỗi `U+` và đổi thành ký tự (`chr(int(hhhh,16))`).
3. **Ghép lại** ta được một **batch script Windows** (`command.txt`). Script này không in thẳng mật khẩu mà dùng thủ thuật `%VAR:~offset,1%` — cú pháp cmd.exe lấy **1 ký tự** tại vị trí `offset` trong biến `VAR`. Ví dụ `%BeoPl:~14,1%` = ký tự thứ 14 (đếm từ 0) của chuỗi `BeoPl`.
4. **Ba bảng chữ cái gốc** được đặt ở đầu script:
   ```
   HPOJs=YXSWCJUBLPNZGIAHDMKRVFTEQO
   BeoPl=clpadkuxztisfnerygwobmhqvj
   kufzE=8394265017
   ```
   Các dòng tiếp theo dùng `%VAR:~i,1%` để **lắp chữ cái** thành các lệnh (`@echo off`, `cls`, `setlocal …`) và để **định nghĩa thêm 3 bảng mới** (`set NAME=...`). Cuối cùng một dòng `echo` dài dùng những bảng đó (ký hiệu `%%VAR:~i,1%%` — dấu `%` nhân đôi vì đang ở trong một lệnh được tạo động) để **ráp ra chuỗi mật khẩu**.

### Lời giải chi tiết
File `solve.py` mô phỏng (emulate) đúng logic trên thay vì chạy batch thật:

```python
# Bước 1+2: base64 x2 -> chuỗi "U+HHHH" -> text batch
inner = base64.b64decode(base64.b64decode(b64_blob))
cps   = re.findall(rb"U\+([0-9A-Fa-f]{4})", inner)   # lấy các mã U+HHHH
text  = "".join(chr(int(cp, 16)) for cp in cps)      # đổi thành ký tự
```

```python
# Bước 3+4: mô phỏng cmd.exe
env = {"HPOJs": "...", "BeoPl": "...", "kufzE": "8394265017"}

def expand(line):
    # thay mọi %VAR:~OFF,1% bằng đúng 1 ký tự env[VAR][OFF]
    return re.sub(r"%([A-Za-z]+):~(\d+),1%",
                  lambda m: env[m.group(1)][int(m.group(2))], line)

# resolve các dòng `set NAME=...` để tạo thêm bảng chữ cái
# rồi expand dòng `echo` cuối -> ra mật khẩu
```

Lưu ý quan trọng trong emulate: sau khi expand, mọi `%x%` còn sót lại là tham chiếu
biến **không tồn tại** trong cmd.exe → nở thành rỗng. Script xử lý bằng cách bỏ hết
dấu `%` (không ký tự nào của mật khẩu là `%` thật). Kết quả chạy ra mật khẩu.

### Flag
```
F1r3NIc3$4Lyfe
```
*(Đây là bài trả về mật khẩu trần, không bọc trong `CSG_FLAG{}`.)*

---

## 3. Australia M1 — Tắt máy (shutdown)

**Category:** misc / cloud / pwn · **Flag:** không có chuỗi flag; mục tiêu là **tắt được máy mục tiêu**.

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/Australia_M1/`
- `linpeas.txt` — thực chất là **EC2 user-data script** (script khởi tạo máy ảo AWS khi boot). File này vô tình để lộ toàn bộ cấu hình của máy.

### Phân tích
Đọc kỹ `linpeas.txt`, ta thấy chuỗi cấu hình đã "dọn sẵn một con đường" để tắt máy:
1. Tạo user thường tên `user`, mật khẩu `IamTheUser!`, và **bật SSH đăng nhập bằng mật khẩu** (`PasswordAuthentication yes`).
2. Thêm một luật PAM vào `/etc/pam.d/su`:
   ```
   auth [success=ignore default=1] pam_succeed_if.so user = shutdown
   auth sufficient                 pam_succeed_if.so use_uid user = user
   ```
   Nghĩa là: khi **`user` chạy `su shutdown`**, điều kiện khớp → `pam_succeed_if` trả về "đủ điều kiện" (`sufficient`) → **không cần nhập mật khẩu** của `shutdown`.
3. User `shutdown` có **login shell** là `/sbin/system/shutdown.sh`, nội dung chỉ gồm:
   ```bash
   #!/bin/bash
   sudo poweroff -i
   ```
   File này còn được gắn **SUID** (`chmod u+s`).
4. sudoers cấp: `shutdown ALL=NOPASSWD: /usr/sbin/poweroff -i` — tức `shutdown` được chạy `poweroff -i` **không cần mật khẩu**.

Ghép lại: đây là một chuỗi leo đặc quyền đã "được cài sẵn" để bất kỳ ai vào được `user` đều có thể tắt máy.

### Lời giải chi tiết
```bash
ssh user@<target>      # mật khẩu: IamTheUser!
su shutdown            # PAM cho qua không cần mật khẩu
                       #  -> login shell = shutdown.sh -> sudo poweroff -i
```
Ngay khi `su shutdown` thành công, login shell của `shutdown` tự chạy `shutdown.sh`
→ `sudo poweroff -i` → **máy tắt**. Bài này chấm bằng việc máy mục tiêu ngừng hoạt động,
không có chuỗi `CSG_FLAG{}`.

---

## 4. Central African Republic C6 — A Very Old Odd File

**Category:** misc / encoding · **Flag:** `CSG_FLAG{PUNCHCARDSAREDEADNOW}`

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/C6_a_very_old_odd_file/`
- `C6_a_very_old_odd_file.txt` — một luồng dài chỉ gồm ký tự `.` và `-`
- `description.txt` — gợi ý về "telegraph / Morse", và nói flag dạng `CSG_FLAG{LOOK.SOMETHING.LIKE.THIS}`

### Phân tích
1. **Không phải Morse (bẫy!).** Đề cố tình nhắc Morse. Nhưng Morse có độ dài ký tự thay đổi và cần khoảng trắng ngăn giữa các chữ/từ. Một luồng `.-` **dài, đều, không có dấu phân tách** không thể tách gọn thành A–Z kiểu Morse → dấu hiệu đây là mã **độ dài cố định**.
2. **"Cổ hơn Morse" = Baudot / ITA2.** Đây là mã điện báo teleprinter, mỗi ký tự đúng **5 bit**. Rất hợp với luồng đều không dấu cách. (ITA2 = International Telegraph Alphabet No. 2.)
3. **Giải mã ITA2:** map `.`/`-` → bit, cắt thành nhóm 5 bit, tra **bảng chữ cái (LETTERS)** của ITA2. Vì không biết chiều quy ước, thử **4 biến thể**: (`.`=1,`-`=0) và đảo lại, mỗi cái kèm trường hợp **đảo thứ tự bit trong mỗi nhóm 5 bit**. Một biến thể sẽ cho ra chữ "sạch".
4. **Lớp tiếp theo — bảng chính tả vô tuyến Thuỵ Điển (Swedish spelling alphabet).** Văn bản giải ra là một chuỗi **tên** như `ADAM, BERTIL, CAESAR, DAVID, ERIK, …, SIGURD, GUSTAV`. Mỗi tên tương ứng chữ cái đầu: ADAM→A, BERTIL→B, CAESAR→C… Ghép các chữ cái đầu lại được:
   ```
   CSG UNDERSCORE FLAG OPENING BRACE PUNCH CARDS ARE DEAD NOW CLOSING BRACE
   ```
5. **Chuẩn hoá token** từ sang ký hiệu: `UNDERSCORE → _`, `OPENINGBRACE → {`, `CLOSINGBRACE → }`.

### Lời giải chi tiết
`solve.py` chạy toàn bộ pipeline và **tự chọn biến thể bit đúng** (chấm điểm biến thể nào tạo ra nhiều tên Thuỵ Điển hợp lệ nhất):
```python
def bits_from_stream(stream, dot_as, dash_as, reverse_chunk):
    b = stream.replace('.', dot_as).replace('-', dash_as)   # . , - -> bit
    # (tuỳ chọn) đảo 5 bit trong mỗi nhóm
    ...
def ita2_force_letters(bitstr):   # tra bảng LETTERS của ITA2, mỗi 5 bit 1 ký tự
    ...
def swedish_words_to_letters(text):  # ADAM->A, BERTIL->B, ...
    ...
# thử 4 biến thể, chọn cái ra nhiều chữ hợp lệ nhất
# rồi UNDERSCORE->_, OPENINGBRACE->{, CLOSINGBRACE->}
```

### Flag
```
CSG_FLAG{PUNCHCARDSAREDEADNOW}
```

---

## 5. China C1 — XOR + Base64

**Category:** crypto · **Flag:** `CSG_FLAG{Wont_U_make_Lemonade}`

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/China_C1/`
- `chall.txt` — các cặp (ciphertext, plaintext) ví dụ, và một ciphertext cần giải ra flag.

### Phân tích
1. **Quan sát cấu trúc.** Mỗi ciphertext có độ dài **chẵn**, chia làm **hai nửa bằng nhau**.
2. **Suy luận khoá.** Với các cặp ví dụ biết trước plaintext (`Great Scott!`, `Hello? Hello? Anybody home?`), ta thử: lấy `base64(plaintext)` rồi XOR với nửa đầu ciphertext → kết quả chính là **nửa sau**. Tức:
   - **Nửa sau = keystream (khoá) thô.**
   - **Nửa đầu = base64(plaintext) XOR khoá.**
3. **Công thức giải mã:** `plaintext = base64_decode( nửa_đầu XOR nửa_sau )`.

Tại sao chắc chắn? Vì kiểm chứng ngược với 2 cặp ví dụ đều ra đúng plaintext → mô hình đúng, áp lên ciphertext của flag.

### Lời giải chi tiết
```python
import base64
cipher = [ ... 80 byte ... ]      # ciphertext của flag
half = len(cipher) // 2
data, key = cipher[:half], cipher[half:]        # tách 2 nửa
b64  = bytes(d ^ k for d, k in zip(data, key))  # XOR -> chuỗi base64
print(base64.b64decode(b64).decode())           # decode -> flag
```

### Flag
```
CSG_FLAG{Wont_U_make_Lemonade}
```

---

## 6. DR Congo C2 — Plato

**Category:** forensics / stego · **Flag:** `CSG_FLAG{Yay!==You-are-successfully-decoded-Vigenere-cipher-inside-pictures!-Congratulations!!}`

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/Democratic_Republic_of_the_Congo_C2_Plato/`
- `C2_Plato.jpg` — ảnh JPEG bức *The Death of Socrates* (Cái chết của Socrates, Jacques-Louis David).

### Phân tích
1. **Carve archive ẩn.** Ảnh JPEG có một **file ZIP được nối thêm vào đuôi** (polyglot). `binwalk C2_Plato.jpg` tách được ZIP. ZIP có mật khẩu và giải nén ra **12 mảnh ảnh (tiles)** của bức tranh.
2. **Lấy mảnh text.** Chạy `strings` trên mỗi tile → mỗi ảnh chứa **một đoạn text ngắn bị xáo**:
   ```
   q-pvothd  ef!-Ooas  g-aeq-sh  eeq-cvbh  rd-iaeiq  ocressgl
   uemthdag  guoae!!}  {Ynk!==Yb  qd-Iugrz  OST_RLNS  yk-drooq
   ```
3. **Sắp thứ tự tile.** Ráp lại bức tranh gốc cho đúng vị trí, suy ra thứ tự các mảnh:
   ```
   11 - 9 - 3 - 6 - 12 - 10 - 4 - 5 - 1 - 2 - 7 - 8
   ```
   Nối các đoạn text theo đúng thứ tự đó được một chuỗi dài:
   ```
   OST_RLNS{Ynk!==Ybg-aeq-shocressglyk-drooqqd-Iugrzeeq-cvbhrd-iaeiqq-pvothdef!-Ooasuemthdagguoae!!}
   ```
4. **Vigenère.** Để ý `OST_RLNS` rất giống `CSG_FLAG` bị dịch → đây là **mã Vigenère** (mã thay thế đa bảng, dịch mỗi chữ theo một khoá lặp). Vì biết cặp `OST_RLNS` ↔ `CSG_FLAG`, ta suy ra khoá và giải toàn bộ chuỗi ra văn bản đọc được → flag.

### Lời giải chi tiết
Writeup gốc không kèm script; đây là các bước tái lập:
1. `binwalk -e C2_Plato.jpg` (hoặc carve từ chữ ký `PK\x03\x04`) → lấy ZIP.
2. Giải nén ZIP (mật khẩu là một đoạn trong đề / trong strings), được 12 tile.
3. `strings` từng tile, ghép theo thứ tự ráp tranh ở trên.
4. Giải Vigenère: lấy khoá bằng cách khớp `CSG_FLAG` với `OST_RLNS` (C−O, S−S, G−T… → khoá), rồi decrypt phần còn lại. Có thể dùng công cụ như CyberChef/dcode hoặc tự viết:
   ```python
   # pt[i] = (ct[i] - key[i % len(key)]) mod 26  (chỉ dịch ký tự A-Z/a-z)
   ```

### Flag
```
CSG_FLAG{Yay!==You-are-successfully-decoded-Vigenere-cipher-inside-pictures!-Congratulations!!}
```

---

## 7. France N1 — QR ẩn trong HTML + S3 SSE-C

**Category:** crypto / stego · **Flag:** host trên S3 (xem bên dưới)

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/France_N1/`
- `index.html` — một trang web; cần kiểm tra để tìm flag.

### Phân tích
1. **4 ảnh base64 trong HTML.** HTML vẽ một bảng 4 ô, mỗi ô có nền là một ảnh PNG mã hoá base64 (`.bg1`..`.bg4`). Nhìn riêng từng ảnh chỉ thấy **nhiễu như một QR hỏng**.
2. **Visual cryptography / QR share.** 4 ảnh là **4 "mảnh chia" (shares)** của một QR; phải **kết hợp** chúng mới hiện ra QR sạch. Vì sao thử nhiều phép? Vì không biết chính xác cách chia → script thử hàng loạt: lọc nhiễu/ngưỡng/đảo màu từng ảnh, rồi kết hợp 4 ảnh bằng median / min / max / XOR / độ lệch chuẩn, cộng thêm phóng to. Một tổ hợp sẽ ra QR đọc được.
3. **Giải QR tự động** bằng `cv2.QRCodeDetector`. QR giải ra một URL S3:
   ```
   https://cyberseagame2025.s3.us-east-2.amazonaws.com/ltnytc9p84wy8pcw8y4tc.txt
   ```
4. **Rào chắn SSE-C.** Truy cập thẳng URL S3 **thất bại** vì object được lưu với **SSE-C** (mã hoá phía máy chủ bằng khoá AES-256 do khách cung cấp). GET trần trả lỗi:
   ```
   InvalidRequest: The object was stored using a form of Server Side Encryption...
   ```
   Hướng khai thác dự kiến (intended) là dùng **proxy `fetch.php`** (do BTC cung cấp) để lấy nội dung — proxy đã gắn sẵn khoá SSE-C đúng, nên request đi qua proxy mới đọc được file txt chứa flag.

### Lời giải chi tiết
`extract_decode.py`:
```python
# 1. Rút 4 ảnh base64 từ data:image/...;base64,<...> trong HTML
pattern = re.compile(r"data:image/[^;]+;base64,([A-Za-z0-9+/=]+)")
# 2. Tạo hàng loạt biến thể: lọc median, đảo màu, ngưỡng; kết hợp
#    median/max/min/XOR/std giữa 4 ảnh; phóng to 1.5x/2x/3x
# 3. detectAndDecode từng biến thể -> ra URL S3
# Kết quả: DECODED from var_14.png: https://...s3.../ltnytc9p84wy8pcw8y4tc.txt
```
Sau khi có URL: vì object dùng SSE-C nên **không GET trực tiếp được**; phải đi qua
`fetch.php` (proxy có khoá) để đọc file `.txt` → đó là nơi chứa flag thật.

### Flag
Writeup gốc dừng ở bước xác định cơ chế SSE-C và proxy `fetch.php`; **chuỗi flag cuối
không có sẵn trong repo** (phụ thuộc hạ tầng S3 của giải, đã gỡ). Bài giải đến mức:
*QR → URL S3 → cần proxy `fetch.php` để vượt SSE-C → đọc file txt lấy flag.*

---

## 8. Germany N2 — Silent Call, Loud Message (VoIP Morse)

**Category:** forensics / network · **Flag:** `CSG_FLAG{Y0UAREDECODEDV01P}`

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/Germany_N2/`
- `packet.pcap` — bắt gói một phiên gọi VoIP.
- `sonic_visualiser.png` — ảnh phổ âm thanh (gợi ý).

### Phân tích
1. **Xác định codec từ SDP.** Trong các gói SIP (UDP cổng 5060), phần SDP có dòng `a=rtpmap:0 PCMU/8000` → media là RTP payload type `0` = **G.711 µ-law (PCMU)**, 8 kHz. (SIP = giao thức báo hiệu cuộc gọi; RTP = luồng mang âm thanh; codec = cách nén tiếng nói.)
2. **Ráp lại luồng RTP.** Đọc pcap, nhận diện gói RTP (version 2, header ≥ 12 byte, không phải RTCP), nhóm theo **SSRC** (định danh nguồn luồng), sắp theo sequence/timestamp để đúng thứ tự.
3. **Giải G.711 µ-law → PCM.** Nối các payload PT=0, giải µ-law thành PCM16 @ 8 kHz, ghi ra file WAV.
4. **"Nghe" tín hiệu ẩn.** Âm thanh thu được **không phải giọng nói**. Mở bằng Sonic Visualiser thấy các "chùm tone" bật/tắt — chính là **mã Morse**:
   ```
   -.-- ----- ..- .- .-. . -.. . -.-. --- -.. . -.. ...- ----- .---- .--.
    Y    0    U  A  R  E   D  E   C   O  D   E  D   V    0    1    P
   ```

### Lời giải chi tiết
Các bước code (writeup mô tả, không kèm file py):
```python
# đọc pcap, lọc RTP PT=0, gom theo SSRC, sort theo seq/timestamp
# audioop.ulaw2lin(payload, 2) để giải µ-law -> PCM16
# ghi WAV 8000 Hz mono, rồi mở Sonic Visualiser xem các burst = Morse
# dịch Morse -> Y0UAREDECODEDV01P
```
Giải mã Morse cho ra `Y0UAREDECODEDV01P` (chú ý `0`=zero và `1`=one theo phong cách leet).

### Flag
```
CSG_FLAG{Y0UAREDECODEDV01P}
```

---

## 9. Greece R2 — Packer (AES-128 ECB)

**Category:** reverse · **Flag:** `CSG_FLAG{packer_daisuki}`

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/Greece/`
- `packed.exe` — file PE32+ là một **packer tự chế**, mang theo payload đã mã hoá.

### Phân tích
1. **Packer là gì?** Là chương trình "gói" một payload (ở đây là DLL) đã mã hoá; khi chạy, stub sẽ giải mã rồi nạp payload vào bộ nhớ. Ta không cần chạy — chỉ cần dịch ngược stub để biết **thuật toán + khoá + vị trí payload**.
2. **Dịch ngược stub** cho thấy: giải mã blob nhúng bằng **AES-128 ECB** với **khoá cứng (hardcoded)**, rồi load kết quả như một DLL. Các hằng số moi ra từ binary:
   - Payload tại **RVA `0xF370`**, kích thước `0x19A00` (RVA = địa chỉ ảo tương đối trong PE).
   - Khoá AES: `49 6D 6C 39 43 90 AF 04 DD 0A BF D8 DF F1 9F B9`.
3. **Kiểm chứng.** Sau khi AES-ECB decrypt, kết quả phải là **PE hợp lệ** — bắt đầu `MZ`, và tại `e_lfanew` có chữ ký `PE\0\0`. Nếu đúng → đã decrypt chuẩn.
4. **Flag là chuỗi thường** nằm trong DLL đã giải mã → chỉ việc `strings | grep CSG`.

### Lời giải chi tiết
`decrypt_payload.py` (cần `pefile`, `pycryptodome`):
```python
pe = pefile.PE("packed.exe")
fo = pe.get_offset_from_rva(0xF370)        # RVA -> offset file
enc = open("packed.exe","rb").read()[fo:fo+0x19A00]
dec = AES.new(KEY, AES.MODE_ECB).decrypt(enc)
assert dec[:2] == b"MZ"                     # kiểm tra là PE
# e_lfanew tại offset 0x3C; kiểm PE\0\0
open("payload.dll","wb").write(dec)
# regex tìm (flag|FLAG|CSG...){...} trong dec
```
Sau đó `strings payload.dll | grep CSG` ra flag.

### Flag
```
CSG_FLAG{packer_daisuki}
```
*(`daisuki` tiếng Nhật nghĩa là "rất thích".)*

---

## 10. R6 — Matryoshka (PHP lồng nhiều lớp)

**Category:** reverse / web (PHP) · **Flag:** `CSG_FLAG{A_Matryoshka_Obfuscated_Script}`

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/R6_matryoshka/`
- Lớp ngoài cùng ~**130 MB** (một `eval(hex2bin("…"))` khổng lồ).
- `final.php` — lớp trong cùng (146 byte) chứa flag.

### Phân tích
"Matryoshka" = búp bê Nga lồng nhau. Mỗi lớp PHP khi chạy chỉ **decode rồi `eval`**
lớp kế tiếp. Bộ "từ vựng" các phép bọc có thể đảo ngược:
```
hex2bin(...)   -> giải hex thành ASCII
base64_decode  -> giải base64
gzinflate(...) -> giải nén raw DEFLATE
eval(...)      -> chạy chuỗi kết quả
```
Mẫu lặp điển hình khi bóc dần:
```
eval(hex2bin("6261736536345f6465636f6465..."))   # -> "base64_decode..."
  -> base64_decode("aGV4MmJpbigi...")             # -> "hex2bin(..."
     -> hex2bin("677a696e666c617465...")          # -> "gzinflate(hex..."
        -> gzinflate(hex2bin("..."))              # giải nén -> lớp kế
           -> eval(... lớp tiếp ...)
```
**Cách bóc an toàn (tĩnh):** thay vì `eval`, mỗi lớp ta **in ra** (thay `eval` bằng
`echo`/`file_put_contents`) để lấy chuỗi lớp tiếp, lặp lại cho tới lớp cuối. Không
chạy mã lạ, chỉ giải mã.

### Lớp cuối & mẹo cuối cùng
```php
<?php
$s='print("I have a flag!\n"); /* CSG_FLAG{A_Matryoshka_Obfuscated_Script} */ print("Congrats!!\n");';
$s=substr($s, 0, 27);   // cắt còn 27 ký tự ĐẦU
eval($s);               // chỉ chạy: print("I have a flag!\n")
?>
```
**Bẫy:** `$s` bị cắt còn 27 ký tự trước khi `eval`, nên đoạn thực sự chạy chỉ là
`print("I have a flag!\n")`. Flag **không nằm ở phần chạy** mà nằm trong **comment
`/* ... */`** của chuỗi gốc. Người giải phải đọc chuỗi, không chỉ chạy nó.

### Flag
```
CSG_FLAG{A_Matryoshka_Obfuscated_Script}
```

---

## 11. Saudi Arabia R1 Q1 — Corrupted (sửa header PE)

**Category:** reverse · **Flag:** `CSG_FLAG{finding_the_magic_now!}`

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/Saudi_Arabia/R1_Q1/`
- `corrupted.exe` — file exe bị hỏng, không chạy được. Phải khôi phục rồi chạy (không tham số) để lấy flag.

### Phân tích
PE hợp lệ phải mở đầu bằng 2 byte `MZ` (0x4D 0x5A). So sánh đầu file:
```
corrupted: 00 04 99 01 40 01 b1 a3 00 00 5a 5a 90 00 03 00 ...
restored : 4d 5a 90 00 03 00 00 00 04 00 ...   -> "MZ"
```
Nhận ra hai lỗi:
1. **Thừa 10 byte rác ở đầu** (`00 04 99 01 40 01 b1 a3 00 00`). Bỏ 10 byte này thì byte tiếp theo là `5a 5a` = `ZZ`.
2. **Magic bị sai**: cần `4d 5a` (`MZ`) nhưng đang là `5a 5a` (`ZZ`). Sửa byte đầu `5a`→`4d` (tức ép về `'M'`).

Sau 2 bước → PE32 console hợp lệ.

### Lời giải chi tiết
`fix_corrupted.py`:
```python
data = open("corrupted.exe","rb").read()
data = data[10:]            # bỏ 10 byte rác đầu
data = b"M" + data[1:]      # ép byte đầu về 'M' -> "MZ"
open("restored.exe","wb").write(data)
```
Phân tích tĩnh phần `main` cho thấy flag được ráp từ format string:
```c
printf("CSG_FLAG{%sing_%s_%s_%s!}\n", "find", "the", "magic", "now");
```
`%sing` với `"find"` → `finding`. Ghép lại ra flag. *(An toàn: chỉ đọc disassembly,
không cần chạy exe.)*

### Flag
```
CSG_FLAG{finding_the_magic_now!}
```

---

## 12. Sweden R3 — Fake C2 (Go binary, RC4)

**Category:** reverse (Go) · **Flag:** `CSG_FLAG{go_rev_startingpoint}`

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/Sweeden_R3_FakeC2/`
- `fakeC2.exe` — binary viết bằng Go, mô phỏng đơn giản một implant giao tiếp C2.

### Phân tích
1. **Luồng chương trình.** `main.main` gọi `main.startServer` (đăng ký route `/check`, `/post`) rồi `main.runClient`. Client kiểm tra `http://127.0.0.1:5555/check`, hỏi key giải mã, POST JSON `{"decryptkey": <key>}` tới `/post`, in phản hồi.
2. **Handler `/post`** (`main.startServer.func2`): đọc JSON, lấy `decryptkey`, so với global `main.expectedKey`. Nếu đúng → **RC4-decrypt** một buffer ciphertext nhúng rồi trả plaintext.
3. **Trích hằng số từ binary** (Go để lộ tên symbol rõ ràng, dễ tìm bằng Ghidra/IDA + strings):
   - `main.expectedKey` = `"RC4JsonMarshalLocalC2"`
   - `main.flag` = buffer 73 byte ciphertext.
4. **Giải mã.** RC4 với khoá `RC4JsonMarshalLocalC2` áp lên 73 byte → ra JSON chứa flag. (Không cần chạy exe — chỉ cần khoá + ciphertext.)

### Lời giải chi tiết
`solve.py` tự cài RC4 thuần Python:
```python
KEY = b"RC4JsonMarshalLocalC2"
CT  = bytes([0x03,0x7a,0x4f,0x22, ...])   # 73 byte lấy từ main.flag

def rc4(data, key):
    S = list(range(256)); j = 0
    for i in range(256):                   # KSA: khởi tạo hộp S
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:                         # PRGA: sinh keystream & XOR
        i = (i+1) & 0xFF; j = (j+S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i]+S[j]) & 0xFF])
    return bytes(out)

print(rc4(CT, KEY).decode(errors="ignore"))   # JSON chứa flag
```

### Flag
```
CSG_FLAG{go_rev_startingpoint}
```

---

## 13. Switzerland N4 — Betrayer (NTLMv2 capture)

**Category:** forensics / network · **Flag:** xem bên dưới

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/Switzerland_N4_betrayer/`
- `betrayer.pcap` — nghi ngờ "nội gián" trên `192.168.56.104`, credential có thể bị lộ từ `192.168.56.33`.
- Dạng flag: `CSG_FLAG{<user>::<domain>:<16 hex>:<32 hex>:<620 hex>}`

### Phân tích
1. **Nhận diện tấn công.** PCAP có traffic NBNS/NetBIOS rồi SMB kèm **NTLMSSP** — chữ ký kinh điển của **đánh cắp NTLMv2** (LLMNR/NBT-NS poisoning / SMB relay). Kẻ tấn công giả mạo phản hồi phân giải tên để nạn nhân "chào hỏi" và gửi chứng thực NTLM.
2. **Khớp format flag với trường NTLMv2.** Dạng flag trùng khít các trường của một phiên chứng thực NTLMv2:
   - **server challenge** — từ gói NTLMSSP **Type 2 (CHALLENGE)** (16 hex = 8 byte).
   - **NT proof** + **blob** — từ NTLMSSP **Type 3 (AUTHENTICATE)**: `NTProofStr` là **16 byte đầu** của NTLMv2 response (→ 32 hex), phần còn lại là **blob** (→ 620 hex).
3. **Rút trường bằng tshark** (hoặc parse thủ công offset NTLMSSP):
   ```bash
   # server challenge (Type 2)
   tshark -r betrayer.pcap -Y "ntlmssp.ntlmserverchallenge" \
          -T fields -e ntlmssp.ntlmserverchallenge | head -n1   # 46f422cd882b169d
   # user, domain, NTLMv2 response (Type 3)
   tshark -r betrayer.pcap -Y "ntlmssp.auth.username && ntlmssp.auth.ntresponse" \
          -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain \
          -e ntlmssp.auth.ntresponse        # bob  WINDOMAIN  4837e8d2...
   ```
4. **Tách NTLMv2 response:** `ntresponse[0:32]` = NT proof, `ntresponse[32:]` = blob.

### Lời giải chi tiết
`analyze_pcap.py` (dùng scapy) tự động hoá: đọc pcap, tìm chữ ký `NTLMSSP\x00`,
đọc MessageType (offset +8), với Type 2 lấy server challenge (byte 24–32), với Type 3
parse các trường Domain/User/Workstation và NT response theo offset chuẩn, rồi in ra
flag + dòng hashcat `-m 5600` để crack mật khẩu nếu muốn.

Giá trị khôi phục:
- User / domain: `bob` / `WINDOMAIN`
- Server challenge: `46f422cd882b169d`
- NT proof: `4837e8d20080f19cc2762798c9373a8e`
- Blob (620 hex): `0101000000000000934f159ee807dc01...0000000000`

**Kẻ phản bội:** `WINDOMAIN\bob`.

### Flag
```
CSG_FLAG{bob::WINDOMAIN:46f422cd882b169d:4837e8d20080f19cc2762798c9373a8e:0101000000000000934f159ee807dc01c70a33e89710d3140000000002001200570049004e0044004f004d00410049004e0001000e00570049004e00310030002d00320004001e00770069006e0064006f006d00610069006e002e006c006f00630061006c0003002e00770069006e00310030002d0032002e00770069006e0064006f006d00610069006e002e006c006f00630061006c0005001e00770069006e0064006f006d00610069006e002e006c006f00630061006c0007000800934f159ee807dc0106000400020000000800300030000000000000000000000000200000d680c970ffd7be19f29a3b7d61c7d3353ee63fdfa4fd83344a83f7681a6b65980a001000000000000000000000000000000000000900140063006900660073002f00640063006300300032000000000000000000}
```

---

## 14. Tanzania S3 — JPEG giấu ZIP (AES-256)

**Category:** forensics / stego · **Flag:** `CSG_FLAG{Y0u-Are-Found-Hidd3n-Fi1e}`

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/Tanza_S3/`
- `S3.jpg` — ảnh JPEG trông bình thường nhưng giấu dữ liệu bên trong.

### Phân tích
1. **Tìm hint mật khẩu.** Dùng `strings`/EXIF trên ảnh thấy các token `P1`, `P2`, `P3`. Ghép lại (viết hoa, nối bằng dấu gạch nối) ra mật khẩu `WATPHO-RECLINING-BUDDHA` (Wat Pho — chùa Phật nằm nổi tiếng ở Bangkok).
2. **Carve ZIP từ JPEG.** Giống bài Congo: JPEG có ZIP nối ở đuôi. Tìm chữ ký `PK\x03\x04` và lưu phần đuôi từ đó thành file ZIP.
3. **Giải nén ZIP mã hoá AES-256.** ZIP này dùng mã hoá AES-256 (ZipCrypto thường không, nhưng AES cần 7-Zip/WinZip). Giải bằng 7-Zip với mật khẩu ở trên.
4. Đọc `flag.txt` bên trong.

### Lời giải chi tiết
`solve.py`:
```python
PASSWORD = b"WATPHO-RECLINING-BUDDHA"
data = open("S3.jpg","rb").read()
idx  = data.find(b"PK\x03\x04")          # tìm đầu ZIP
open("embedded.zip","wb").write(data[idx:])   # carve
# 7z x -y -p<password> embedded.zip -o<dir>   (AES-256 cần 7-Zip)
print(open("flag.txt").read().strip())
```

### Flag
```
CSG_FLAG{Y0u-Are-Found-Hidd3n-Fi1e}
```

---

## 15. Zambia C4 — csg_ctf (HTA crackme, MD5)

**Category:** reverse / crypto · **Flag:** `CSG_FLAG{001112233446cDdefL}`

### Đề bài
Thư mục: `2025-Cyber-SEA-Game/Zambia_C4_csg_ctf/`
- `C4_csg_ctf.HTA` — HTML Application (ứng dụng chạy bằng `mshta.exe` trên Windows) dạng crackme kiểm tra mật khẩu bằng JavaScript.

### Phân tích
1. **Cơ chế kiểm tra.** JS trong HTA tính **MD5** của mật khẩu nhập vào. Mật khẩu (24 ô, có khoảng trắng đầu) được **tách thành 3 phần h1, h2, h3** theo mảng vị trí `nl`. Mỗi phần được MD5, so với một giá trị đã bị **obfuscate** (`ko`, `ka`, `kq`).
2. **Biến khoá:**
   ```js
   nl = [0,6,17,14,1,18,16,7,11,13,8,12,2,3,0,15,4,0,9,5,0,0,10,0,0]
   ko = "58b4cb64f141e5c914640c5c8cc8e5d5"  // h1: 8 chữ số
   ka = "8a1828526galf607b8257cb552b0e6c8"  // h2: 4 ký tự alphanum
   kq = "z99za5c140689zc2d2a1052c8z5e4b9d"  // h3: 6 ký tự alphanum
   ```
3. **Gỡ lớp biến đổi.** Hàm so sánh áp các phép thay ký tự rồi **đảo ngược chuỗi** (hàm `dfgtrfd...` chỉ là `reverse`). Đọc JS:
   ```js
   co(o) === reverse( ko.replace(/4/g,'a').replace(/d/g,'3').replace(/e/g,'7') )
   ca(a) === reverse( ka.replace(/f/g,'3').replace(/l/g,'d').replace(/g/g,'9') )
   cq(q) === reverse( kq.replace(/2/g,'f').replace(/b/g,'7').replace(/z/g,'3') )
   ```
   Áp dụng ta có 3 **MD5 đích**:
   - h1: `53578cc8c5c0a6a19c571a1fa6bcab85`
   - h2: `8c6e0b255bc7528b7063da96258281a8`
   - h3: `d974e538cf501afdfc3986041c5a3993`
4. **Crack hash** (brute-force vì không gian nhỏ):
   - h1 = 8 chữ số → `20231114` (giống một ngày tháng).
   - h2 = 4 alphanum → `fL46`.
   - h3 = 6 alphanum → `Dec0d3` (dùng hashcat `-m 0 -a 3 ?1?1?1?1?1?1 -1 ?u?l?d`).
5. **Ráp lại mật khẩu** theo mảng `nl` (bảng thứ tự trong writeup gốc ghi rõ ô nào lấy ký tự nào của h1/h2/h3).

### Lời giải chi tiết
`solve.py`:
```python
TARGET_H1 = "53578cc8c5c0a6a19c571a1fa6bcab85"  # 8 digits
TARGET_H2 = "8c6e0b255bc7528b7063da96258281a8"  # 4 alphanum
TARGET_H3 = "d974e538cf501afdfc3986041c5a3993"  # 6 alphanum (hashcat)

# brute-force h2 (nhỏ nhất) và h1 (8 chữ số) bằng itertools.product + md5
# h3 lấy từ hashcat = "Dec0d3"

def reconstruct_password(h1,h2,h3):
    return ''.join([h1[1],h3[3],h1[4],h1[5],h1[6],h1[0],h1[2],h1[3],
                    h3[5],h1[7],h2[2],h2[3],h3[2],h3[0],h3[4],h3[1],
                    h2[0],h2[1]])
# h1=20231114, h2=fL46, h3=Dec0d3  -> 001112233446cDdefL
```

### Flag
```
CSG_FLAG{001112233446cDdefL}
```

---

## Phụ lục — Ghi chú & vấn đề gặp phải

- **France N1** là bài duy nhất **không có chuỗi flag cuối** trong repo: writeup dừng
  ở việc giải QR ra URL S3 và xác định cần proxy `fetch.php` để vượt mã hoá SSE-C.
  Flag thật phụ thuộc hạ tầng S3 của giải (đã bị gỡ sau giải).
- **DR Congo C2 (Plato)** không có script solve, chỉ có README mô tả; phần giải
  Vigenère ở trên là suy luận bổ sung (khớp `CSG_FLAG` ↔ `OST_RLNS` để tìm khoá).
- **Germany N2** không kèm file `.py`; các bước xử lý RTP/µ-law/Morse là tái lập từ README.
- Toàn bộ phân tích exe/binary (`packed.exe`, `fakeC2.exe`, `corrupted.exe`, `C4_csg_ctf.HTA`)
  đều **tĩnh** — không thực thi file nào, đúng yêu cầu an toàn.
