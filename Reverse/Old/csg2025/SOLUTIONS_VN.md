# Cyber SEA Game 2025 — Lời giải chi tiết (Tiếng Việt) — BẢN ĐẦY ĐỦ

> **Tài liệu này** viết lại và mở rộng toàn bộ lời giải 14 challenge của giải
> **Cyber SEA Game 2025**, dựa trên writeup gốc trong repo
> [kaisonox/CTFs](https://github.com/kaisonox/CTFs) (thư mục `2025-Cyber-SEA-Game`).
>
> **Nguyên tắc an toàn:** mọi phân tích file thực thi (`.exe`, `.hta`, binary) đều là
> **tĩnh** — không chạy bất kỳ file nhị phân tải về nào. Các thao tác dùng tới chỉ gồm:
> tính hash, `strings`, `xxd`, đọc mã nguồn, và chạy các script Python thuần (RC4, XOR,
> base64, MD5…) **xử lý dữ liệu** chứ không thực thi binary. Các giá trị quan trọng
> (flag, magic bytes, khóa) đều đã được **kiểm chứng lại** với file thật.
>
> **Phiên bản rút gọn** nằm ở `SOLUTIONS_VN_short.md` (giữ lại để tham khảo nhanh).

---

## 0. Mục lục

1. [Tổng quan giải & kiến thức chung](#1-tổng-quan-giải)
2. [Bảng tổng hợp challenge + flag](#bảng-tổng-hợp-challenge)
3. [Bảng băm (hash) file đề — kiểm chứng toàn vẹn](#bảng-băm-hash-file-đề)
4. [Danh sách đính chính so với writeup gốc](#danh-sách-đính-chính)

**Chi tiết từng bài:**

- [Bài 1 — Angola C2: Do You Think I'm Fragile](#bài-1--angola-c2--do-you-think-im-fragile)
- [Bài 2 — Australia M1: Tắt máy qua PAM/sudo](#bài-2--australia-m1--tắt-máy-qua-pamsudo)
- [Bài 3 — Central African Rep. C6: A Very Old Odd File (Baudot/ITA2)](#bài-3--central-african-republic-c6--a-very-old-odd-file)
- [Bài 4 — China C1: XOR + Base64](#bài-4--china-c1--xor--base64)
- [Bài 5 — DR Congo C2: Plato (JPEG+ZIP, Vigenère)](#bài-5--dr-congo-c2--plato)
- [Bài 6 — France N1: QR shares trong HTML + S3 SSE-C](#bài-6--france-n1--qr-shares--s3-sse-c)
- [Bài 7 — Germany N2: VoIP RTP → Morse](#bài-7--germany-n2--silent-call-loud-message)
- [Bài 8 — Greece R2: Packer (AES-128-ECB)](#bài-8--greece-r2--packer)
- [Bài 9 — R6: Matryoshka (PHP lồng nhiều lớp)](#bài-9--r6--matryoshka)
- [Bài 10 — Saudi Arabia R1 Q1: Corrupted PE](#bài-10--saudi-arabia-r1-q1--corrupted)
- [Bài 11 — Sweden R3: Fake C2 (Go, RC4)](#bài-11--sweden-r3--fake-c2)
- [Bài 12 — Switzerland N4: Betrayer (NTLMv2 capture)](#bài-12--switzerland-n4--betrayer)
- [Bài 13 — Tanzania S3: JPEG giấu ZIP AES-256](#bài-13--tanzania-s3)
- [Bài 14 — Zambia C4: csg_ctf (HTA crackme MD5)](#bài-14--zambia-c4--csg_ctf)

---

## 1. Tổng quan giải

**Cyber SEA Game** là giải CTF (Capture The Flag — "cướp cờ") thường niên dành cho các
đội tuyển trẻ khu vực Đông Nam Á (SEA). CTF là dạng thi an toàn thông tin, trong đó
người chơi phải tìm ra một chuỗi bí mật gọi là **flag** (lá cờ) được giấu trong file,
dịch vụ mạng, hoặc chương trình — bằng cách khai thác lỗ hổng, dịch ngược phần mềm,
giải mã, hoặc điều tra số.

Ở phiên bản 2025, các challenge trong repo được đặt tên theo **tên quốc gia**
(Angola, Australia, China, France…) kèm một **mã bài** do Ban tổ chức đánh số:
tiền tố chữ cái thường ám chỉ nhóm chủ đề/round (ví dụ `C` = crypto/coding, `N` =
network/forensics, `R` = reverse/round, `S` = steganography, `M` = misc). Đây chỉ là
quy ước đặt tên, không phải quy tắc cứng.

**Định dạng flag chuẩn** của giải là:

```
CSG_FLAG{...}
```

trong đó `CSG` = **C**yber **S**EA **G**ame. Phần trong ngoặc nhọn `{}` là nội dung
cần tìm. Có vài bài ngoại lệ về định dạng, sẽ ghi rõ trong từng bài.

### Các khái niệm nền dùng chung (giải thích cho người mới)

Dưới đây là "từ điển bỏ túi" cho các thuật ngữ sẽ gặp lại nhiều lần. Mỗi bài sẽ còn
có phần "Kiến thức nền" riêng, sâu hơn.

- **Byte / bit / hex:** Máy tính lưu dữ liệu dưới dạng **bit** (0 hoặc 1). 8 bit gộp
  thành 1 **byte** (giá trị 0–255). Để con người đọc byte cho gọn, ta viết dưới dạng
  **hex** (hệ cơ số 16): mỗi byte = 2 ký tự trong `00`–`ff`. Ví dụ byte giá trị 77 =
  `0x4D` = ký tự `'M'` trong bảng ASCII.
- **ASCII:** Bảng quy ước ánh xạ số 0–127 sang ký tự (chữ cái, chữ số, dấu). `'A'`=65,
  `'M'`=77, `'0'`=48…
- **Base64:** Cách biểu diễn dữ liệu nhị phân bằng 64 ký tự an toàn (`A–Z a–z 0–9 + /`),
  thường kết thúc bằng `=` để đệm. Dùng để nhúng file nhị phân vào văn bản/HTML. "Decode
  base64" = đảo ngược về dữ liệu gốc. Nếu decode một lần vẫn ra base64 → có thể là
  **base64 nhiều lớp**.
- **XOR (⊕):** Phép toán bit "hoặc loại trừ": `0⊕0=0, 1⊕1=0, 0⊕1=1`. Tính chất vàng cho
  mật mã: `A ⊕ K ⊕ K = A`. Vì vậy nếu mã hóa bằng `C = P ⊕ K` thì giải mã chỉ việc
  `P = C ⊕ K` với cùng khóa `K`.
- **Mã dòng (stream cipher) vs mã khối (block cipher):** Mã dòng (RC4, ChaCha) sinh ra
  một "dòng khóa" (keystream) dài bằng dữ liệu rồi XOR từng byte. Mã khối (AES, DES) chia
  dữ liệu thành khối cố định (AES = 16 byte) rồi mã hóa từng khối theo một **chế độ**
  (ECB, CBC…).
- **ECB (Electronic Codebook):** Chế độ mã khối đơn giản nhất: mỗi khối 16 byte mã hóa
  độc lập bằng cùng một khóa. Nhược điểm bảo mật (khối giống nhau cho ciphertext giống
  nhau) nhưng rất tiện cho CTF vì không cần IV.
- **RC4:** Mã dòng cổ điển gồm 2 pha: **KSA** (Key Scheduling Algorithm — xáo trộn mảng
  S 256 phần tử theo khóa) và **PRGA** (Pseudo-Random Generation Algorithm — sinh
  keystream). Mã hóa và giải mã **giống hệt nhau** (đều là XOR với keystream).
- **MD5:** Hàm băm (hash) cho ra "dấu vân tay" 128 bit (32 ký tự hex) từ dữ liệu bất kỳ.
  Một chiều: không đảo ngược trực tiếp, nhưng với không gian đầu vào nhỏ có thể
  **brute-force** (thử hết). MD5 đã lỗi thời về an toàn nhưng vẫn gặp nhiều trong CTF.
- **PE (Portable Executable):** Định dạng file thực thi của Windows (`.exe`, `.dll`).
  Luôn bắt đầu bằng 2 byte `MZ` (0x4D 0x5A — chữ ký "DOS header", đặt theo tên Mark
  Zbikowski). Tại offset `0x3C` có trường `e_lfanew` trỏ tới "NT header" bắt đầu bằng
  chữ ký `PE\0\0` (0x50 0x45 0x00 0x00). RVA (Relative Virtual Address) = địa chỉ ảo
  tương đối, cần quy đổi sang offset file để đọc.
- **Vigenère:** Mã thay thế đa bảng cổ điển. Mỗi chữ cái plaintext bị dịch theo một chữ
  cái của **khóa** lặp lại: `C[i] = (P[i] + K[i mod len]) mod 26`. Giải mã: `P[i] = (C[i]
  − K[i mod len]) mod 26`.
- **Baudot / ITA2:** Mã điện báo teleprinter **5 bit cố định** (có trước Morse về ý tưởng
  cố định độ dài). 5 bit = 32 tổ hợp, chia 2 chế độ (LETTERS/FIGS) qua ký tự shift.
- **PCAP:** File bắt gói tin mạng (packet capture). Phân tích bằng Wireshark (GUI),
  `tshark` (CLI) hoặc thư viện `scapy` (Python).
- **NTLMv2:** Giao thức chứng thực của Windows. Khi bị "nghe lén" (qua tấn công
  LLMNR/NBT-NS poisoning hoặc SMB relay), kẻ tấn công thu được "NTLMv2 response" có thể
  đem đi crack mật khẩu offline bằng hashcat.
- **SSE-C (Server-Side Encryption with Customer-provided keys):** Tính năng của Amazon
  S3 cho phép lưu object đã mã hóa AES-256 với khóa do **khách** cung cấp. Muốn GET phải
  gửi đúng khóa trong header, nếu không S3 trả lỗi `InvalidRequest`.

### Bảng tổng hợp challenge

| # | Bài (thư mục) | Quốc gia / mã | Category | Độ khó | Flag / Kết quả |
|---|---|---|---|---|---|
| 1 | Do You Think I'm Fragile | Angola / C2 | misc / scripting + stego | TB | `F1r3NIc3$4Lyfe` (mật khẩu ZIP → ảnh "Congratulations!") |
| 2 | M1 | Australia / M1 | misc / cloud / pwn | Dễ–TB | *(không có chuỗi flag — mục tiêu: tắt máy)* |
| 3 | A Very Old Odd File | CAR / C6 | misc / encoding | TB | `CSG_FLAG{PUNCHCARDSAREDEADNOW}` |
| 4 | C1 | China / C1 | crypto | Dễ–TB | `CSG_FLAG{Wont_U_make_Lemonade}` |
| 5 | Plato | DR Congo / C2 | forensics / stego + crypto | TB | `CSG_FLAG{Yay!==You-are-successfully-decoded-Vigenere-cipher-inside-pictures!-Congratulations!!}` |
| 6 | N1 | France / N1 | crypto / stego / web | Khó | *(QR → URL S3 có SSE-C; flag host trên S3, đã gỡ)* |
| 7 | Silent Call, Loud Message | Germany / N2 | forensics / network | TB | `CSG_FLAG{Y0UAREDECODEDV01P}` |
| 8 | Packer | Greece / R2 | reverse | TB | `CSG_FLAG{packer_daisuki}` |
| 9 | Matryoshka | R6 | reverse / web (PHP) | Dễ–TB | `CSG_FLAG{A_Matryoshka_Obfuscated_Script}` |
| 10 | Corrupted | Saudi Arabia / R1 Q1 | reverse | Dễ | `CSG_FLAG{finding_the_magic_now!}` |
| 11 | Fake C2 | Sweden / R3 | reverse (Go) | Dễ–TB | `CSG_FLAG{go_rev_startingpoint}` |
| 12 | Betrayer | Switzerland / N4 | forensics / network | Khó | `CSG_FLAG{bob::WINDOMAIN:46f4...}` (đầy đủ trong bài 12) |
| 13 | S3 | Tanzania / S3 | forensics / stego | Dễ–TB | `CSG_FLAG{Y0u-Are-Found-Hidd3n-Fi1e}` |
| 14 | csg_ctf | Zambia / C4 | reverse / crypto | TB | `CSG_FLAG{001112233446cDdefL}` |

**Thống kê theo category:**
- **Reverse (5):** Greece, R6 Matryoshka, Saudi Arabia, Sweden, Zambia
- **Forensics / Network / Stego (4):** DR Congo, Germany, Switzerland, Tanzania
- **Crypto (2):** China, France
- **Misc / Encoding (2):** Angola, CAR (C6)
- **Misc / Cloud / Pwn (1):** Australia

### Bảng băm (hash) file đề

Dưới đây là hash của các file đề chính (tính bằng `md5sum`/`sha1sum`), dùng để **kiểm
chứng toàn vẹn** — nếu bạn tải lại file mà hash khớp thì chắc chắn đang phân tích đúng
dữ liệu tác giả này dùng.

| File đề | Size (byte) | MD5 | SHA1 |
|---|---|---|---|
| `Angola.../kimpampara.txt` | 35904 | `b309de56a7094b9a955869789b08c87a` | `91978de5e4cb28d7780d56139774e689bd5fb957` |
| `Angola.../unf0rgiven.zip` | 88339 | `d7dafe3cc075835585200987f31b4b15` | `9ea7d951a4db411184373addfae4b26326873344` |
| `Australia_M1/linpeas.txt` | 1311 | `cb966cfcecac48789e34b5aaa517baee` | `346130bdb78e5f4ac2fde56c9130a6481403cb79` |
| `C6.../C6_a_very_old_odd_file.txt` | 2180 | `a2a7730f246d6fac829ddfe59a9be01e` | `d8cc7b74e96aaebcf55a988f2ec9137ba1f82e94` |
| `China_C1/chall.txt` | 1190 | `11a71d96ebeb102370ca075a9a9249dc` | `1c797b07b1e7defd03e8421bc9fac581df414e18` |
| `DRCongo.../C2_Plato.jpg` | 6406965 | `35e5e1a9984827135c29df5eb64c692d` | `a978475b30bc8fd63e1a7222fd2f084e7355df5a` |
| `France_N1/index.html` | 15751 | `a37b52803a0676fef598729f46fedbc3` | `b301836a94eab136d26edf4ad4cd44326357656a` |
| `Germany_N2/packet.pcap` | 174067 | `5e3824660031774d00d76b7241de6e68` | `51999e63dda4b4f8235a19793c0e1ba720a99716` |
| `Greece/packed.exe` | 209408 | `0728bfc481ee20fdad43dbda9d35158f` | `4f0a30871d01d58828b72ef647391bafdfebd1c5` |
| `R6_matryoshka/final.php` | 147 | `46b990affed6c95eabd44905e84ba541` | `497df266235375dabb3e948114658c712766c33b` |
| `Saudi.../corrupted.exe` | 114698 | `01d9f9e15295f86d368fde1e19dfc283` | `2a40f9bc1f1a961978b422b0323e61df63e38b67` |
| `Sweden.../fakeC2` (ciphertext) | — | *(solve.py chứa CT 73 byte)* | — |
| `Switzerland.../betrayer.pcap` | 34386 | `d56dbbe52534fa3c26c4b90dc820c130` | `0cd75bd5e2eb2a53a192e24c335be5a1396da6ce` |
| `Tanza_S3/S3.jpg` | 155076 | `49eba91dabfe6a77727415320636186f` | `b062b9739e6682f9ccc5d8839f190a56085a16cd` |
| `Zambia.../C4_csg_ctf.HTA` | 116673 | `c327318de9a061955668cba97356b17a` | `8ece0d0c1112aa2c45e656444f1098fbc048f2ad` |

### Danh sách đính chính

Trong quá trình kiểm chứng lại với file thật, phát hiện vài điểm writeup gốc **thiếu
hoặc chưa chính xác**. Các điểm này được đánh dấu **⚠️ Đính chính** trong từng bài:

1. **Angola C2 (Bài 1):** README gốc nói batch "build the password" rồi coi
   `F1r3NIc3$4Lyfe` là flag. **Thực tế** khi mô phỏng batch, output là **cả một câu**:
   *"Good job and Congratulations... To open the ZIP file, here is the password
   F1r3NIc3$4Lyfe"*. Tức đây là **mật khẩu để mở `unf0rgiven.zip`**; giải nén ra ảnh
   `Congratulations!.png` (hình một lá cờ trắng — chơi chữ với tên bài "Do You Think I'm
   Fragile" / giơ cờ trắng đầu hàng). Chuỗi cần nộp chính là mật khẩu đó.
2. **DR Congo C2 (Bài 5):** README **không nêu khóa Vigenère**. Mình đã tính ra
   **khóa = `MAN`** (từ cặp `CSG_FLAG` ↔ `OST_RLNS`). Ngoài ra, chuỗi ciphertext ghép
   trong README **bị sai ở phần đuôi**: khi giải với khóa `MAN`, nó cho đúng tới
   `...inside-pictures!-Cong` rồi lệch (`uraturatuuboe!!}` thay vì `ratulations!!}`),
   chứng tỏ 2 mảnh tile cuối trong README bị copy/sắp sai thứ tự. Flag cuối vẫn đúng như
   công bố (đã kiểm chứng bằng cách mã hóa ngược flag → khớp phần đầu ciphertext).
3. **France N1 (Bài 6):** Repo **không có chuỗi flag cuối**; chỉ giải tới URL S3 và cơ
   chế SSE-C + proxy `fetch.php`. Đã xác nhận `index.html` thật có đúng **4 ảnh base64**
   (`.bg1`–`.bg4`) và **có tham chiếu `fetch.php`**.
4. **Germany N2 / Switzerland N4:** Không chạy được tần suất bằng scapy/tshark trong môi
   trường này, nhưng đã **xác nhận bằng `strings`** trên pcap: Germany có
   `a=rtpmap:0 PCMU/8000` (Alice 10.0.0.1 → Bob 10.0.0.2); Switzerland có `WINDOMAIN`,
   `WINDOMAIN.LOCAL`, host `dcc02`. Các con số NTLMv2 lấy từ README gốc.

---

## Bài 1 — Angola C2 — Do You Think I'm Fragile

### (a) Đề bài & metadata
- **Tên:** Do You Think I'm Fragile — **Quốc gia/mã:** Angola / C2 — **Category:** misc / scripting + stego — **Độ khó:** Trung bình.
- **Thư mục:** `2025-Cyber-SEA-Game/Angola_C2_DoYouThinkImFragile/`
- **File đề:**
  - `kimpampara.txt` (35904 byte, md5 `b309de56a7094b9a955869789b08c87a`) — khối dữ liệu mã hóa.
  - `unf0rgiven.zip` (88339 byte, md5 `d7dafe3cc075835585200987f31b4b15`) — ZIP có mật khẩu.
  - `command.txt` — batch script đã giải sẵn (tham khảo); `solve.py` — script giải.
- **Kết quả cần nộp:** `F1r3NIc3$4Lyfe` (là **mật khẩu** mở `unf0rgiven.zip`).

### (b) Kiến thức nền
- **Base64 nhiều lớp:** như đã nói ở phần chung, base64 biến dữ liệu nhị phân thành
  văn bản. Tác giả CTF hay "bọc" nhiều lớp: dữ liệu → base64 → lại base64. Dấu hiệu nhận
  biết lớp kép là: sau khi decode một lần, kết quả **vẫn** chỉ gồm ký tự base64 hợp lệ.
- **Unicode codepoint `U+HHHH`:** Mỗi ký tự trong Unicode có một "số thứ tự" gọi là
  codepoint, thường viết `U+` rồi 4 chữ số hex. Ví dụ `U+0040` = ký tự `@`. Nếu một văn
  bản gồm toàn chuỗi `U+....`, nhiều khả năng đó là từng ký tự của một thông điệp bị "mã
  hóa" thành codepoint để che giấu. Giải mã = lấy phần hex, đổi về ký tự: `chr(0x40)='@'`.
- **Batch script (`.bat`/`.cmd`) và thủ thuật `%VAR:~offset,length%`:** Trong shell
  `cmd.exe` của Windows, cú pháp `%TEN:~OFFSET,LEN%` cắt chuỗi con từ biến `TEN`, bắt đầu
  tại vị trí `OFFSET` (đếm từ 0), lấy `LEN` ký tự. Ví dụ nếu `set A=HELLO` thì `%A:~1,1%`
  = `'E'`. Kỹ thuật obfuscation (làm rối) phổ biến: định nghĩa vài "bảng chữ cái" hoán vị,
  rồi ghép từng ký tự bằng hàng loạt lookup `%...~i,1%` để che nội dung lệnh thật.
- **`delayedexpansion` và dấu `%` nhân đôi:** Khi một lệnh được **sinh ra động** rồi chạy
  lại, các tham chiếu biến phải viết `%%VAR%%` (nhân đôi `%`) để "sống sót" qua một vòng
  phân giải. Biến không tồn tại khi phân giải sẽ nở thành chuỗi rỗng.
- **ZIP có mật khẩu:** Một file nén có thể yêu cầu mật khẩu để giải nén. Thử sai mật khẩu
  sẽ báo lỗi. Trong CTF, mật khẩu thường được "giấu" ở bước trước đó (như ở đây là output
  của batch).

### (c) Trinh sát ban đầu
```bash
file kimpampara.txt unf0rgiven.zip   # text vs Zip archive
head -c 80 kimpampara.txt            # thấy chuỗi dài giống base64
unzip -l unf0rgiven.zip              # liệt kê: Congratulations!.png (90736 byte, encrypted)
```
Quan sát: `kimpampara.txt` là chuỗi base64 rất dài; `unf0rgiven.zip` chứa đúng 1 file
ảnh PNG đang **bị mã hóa** (cần mật khẩu). → Nhiệm vụ: tìm mật khẩu từ `kimpampara.txt`.

### (d) Phân tích từng bước + reasoning "tại sao"
1. **Thử decode base64 một lần.** Kết quả vẫn là chuỗi ký tự base64 → nghi **double
   base64**. Decode lần hai → ra một văn bản gồm toàn `U+0040 U+0065 U+0063 ...`.
   *Tại sao chắc là codepoint?* Vì mẫu `U+` + đúng 4 hex lặp lại đều đặn là đặc trưng của
   danh sách codepoint. (Mình đã đếm được **3366 codepoint** — khớp với kích thước script
   batch 3366 byte.)
2. **Đổi codepoint → ký tự** → thu được một **batch script Windows** (chính là nội dung
   `command.txt`). Đầu script có 3 bảng:
   ```bat
   set HPOJs=YXSWCJUBLPNZGIAHDMKRVFTEQO
   set BeoPl=clpadkuxztisfnerygwobmhqvj
   set kufzE=8394265017
   ```
3. **Các dòng kế tiếp dùng `%BeoPl:~i,1%`…** để ghép thành các lệnh đầu (`@echo off`,
   `cls`, `setlocal …`) và để **định nghĩa thêm 3 bảng** mới bằng `set NAME=...` (trong đó
   phần giá trị cũng được ghép từ các bảng cũ). Mô phỏng ra, 3 bảng mới là:
   ```
   MVMwc = uozdvfqmxwljiethgpnrbyaksc
   GUefu = 1748963052
   hOKCW = VKURPBCQYDHMILFOGZXEWATJSN
   ```
4. **Dòng cuối là một lệnh `echo` khổng lồ** dùng cả 6 bảng (với `%%VAR:~i,1%%`), tạo ra
   thông điệp cuối. *Tại sao phải mô phỏng thay vì chạy?* Vì an toàn (không chạy mã lạ),
   và vì logic thuần là tra bảng nên mô phỏng bằng Python cho kết quả y hệt.

### (e) Lời giải / exploit đầy đủ
Script mô phỏng (dựa trên `solve.py`, đã sửa lỗi nhỏ: `solve.py` gốc gọi
`KIMPAMPARA.read_text()` trên một `str` nên sẽ lỗi — ở đây đọc file đúng cách):

```python
import base64, re, zipfile

# --- Bước 1+2: double base64 -> chuỗi "U+HHHH" -> text batch ---
blob  = open("kimpampara.txt").read().strip()      # đọc khối base64
inner = base64.b64decode(base64.b64decode(blob))   # decode HAI lần
cps   = re.findall(rb"U\+([0-9A-Fa-f]{4})", inner) # lấy mọi mã U+HHHH
script = "".join(chr(int(c, 16)) for c in cps)     # đổi codepoint -> ký tự

# --- Bước 3: mô phỏng cmd.exe ---
env = {"HPOJs":"YXSWCJUBLPNZGIAHDMKRVFTEQO",       # 3 bảng gốc trong script
       "BeoPl":"clpadkuxztisfnerygwobmhqvj",
       "kufzE":"8394265017"}

def expand(line):
    # thay mọi %VAR:~OFF,1% bằng đúng 1 ký tự env[VAR][OFF]
    return re.sub(r"%([A-Za-z]+):~(\d+),1%",
                  lambda m: env[m.group(1)][int(m.group(2))]
                            if m.group(1) in env else m.group(0), line)

for line in script.splitlines():                   # phân giải các dòng `set NAME=...`
    s = expand(line.strip())                        # để tạo 3 bảng phái sinh
    m = re.match(r"^set\s+([A-Za-z]+)=(\S+)$", s, re.I)
    if m: env[m.group(1)] = m.group(2)

# --- Bước 4: phân giải dòng echo cuối -> thông điệp ---
echo_line = next(l for l in script.splitlines() if "=echo " in l)
template  = expand(echo_line.split("=echo ", 1)[1])
message   = expand(template).replace("%", "")       # bỏ % dư (biến không tồn tại)
print(message)
# -> Good job and Congratulations... To open the ZIP file,
#    here is the password F1r3NIc3$4Lyfe

# --- Bước 5: dùng mật khẩu mở ZIP, xem ảnh ---
z = zipfile.ZipFile("unf0rgiven.zip")
data = z.read("Congratulations!.png", pwd=b"F1r3NIc3$4Lyfe")   # giải mã OK
open("Congratulations.png","wb").write(data)         # ảnh một lá cờ trắng + "Congratulations!"
```

**Output thực tế (đã chạy kiểm chứng):**
```
Good job and Congratulations... To open the ZIP file, here is the password F1r3NIc3$4Lyfe
```
Dùng mật khẩu đó giải nén `unf0rgiven.zip` → ảnh `Congratulations!.png` (PNG 1080×1080):
một **lá cờ trắng** với dòng chữ *"Congratulations!"* — xác nhận đã làm đúng.

### (f) Flag & ý nghĩa
```
F1r3NIc3$4Lyfe
```
> ⚠️ **Đính chính:** README gốc trình bày `F1r3NIc3$4Lyfe` như "password" được build ra
> và coi đó là đáp án. Đúng là đáp án, nhưng bản chất nó là **mật khẩu mở ZIP**, và câu
> đầy đủ do batch in ra mới cho thấy ngữ cảnh. Tên bài *"Do You Think I'm Fragile"* + ảnh
> **lá cờ trắng** là lối chơi chữ (giơ cờ trắng = đầu hàng/hoàn thành). Dạng chuỗi
> (`F1r3`=Fire, `NIc3`=Nice, `4Lyfe`=for life kiểu leetspeak) gợi ý "Fire Nice for life".

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1:** Dừng ở việc decode base64 một lần rồi bối rối vì "vẫn là base64". Phải
  thử decode lần hai.
- **Cạm bẫy 2:** Tưởng `U+HHHH` là UTF-16 hay gì phức tạp; thực ra chỉ là codepoint hex.
- **Cạm bẫy 3:** Chạy thẳng batch trên máy thật (rủi ro). Nên mô phỏng tĩnh.
- **Lỗi trong `solve.py` gốc:** dùng `KIMPAMPARA.read_text()` trên biến `str` → `AttributeError`.
  Bản trên đã sửa bằng `open(...).read()`.
- **Cách khác:** Có thể chạy batch trong môi trường sandbox cách ly (VM dùng một lần) để
  lấy output — nhưng mô phỏng an toàn hơn.

### (h) Tham khảo
- Microsoft docs: cú pháp biến môi trường cmd `%VAR:~start,len%`.
- Python `zipfile` (đọc ZIP có mật khẩu ZipCrypto cổ điển bằng `pwd=`).
- Unicode codepoint & hàm `chr()`/`ord()`.

---

## Bài 2 — Australia M1 — Tắt máy qua PAM/sudo

### (a) Đề bài & metadata
- **Tên:** M1 — **Quốc gia/mã:** Australia / M1 — **Category:** misc / cloud / pwn — **Độ khó:** Dễ–Trung bình.
- **Thư mục:** `2025-Cyber-SEA-Game/Australia_M1/`
- **File đề:** `linpeas.txt` (1311 byte, md5 `cb966cfcecac48789e34b5aaa517baee`). Tên file gợi ý công cụ `linpeas` (script dò leo thang đặc quyền trên Linux), nhưng nội dung thực chất là **EC2 user-data script** — đoạn script AWS chạy **một lần khi máy ảo khởi tạo**.
- **Mục tiêu:** Không có chuỗi flag; đề yêu cầu **tắt được máy mục tiêu** (shutdown).

### (b) Kiến thức nền
- **EC2 user-data:** Khi tạo máy ảo (instance) trên AWS EC2, ta có thể đính kèm một script
  "user-data" chạy tự động lúc boot (thường với quyền root) để cấu hình máy. Nếu script này
  bị lộ, nó tiết lộ toàn bộ cách máy được thiết lập — kể cả mật khẩu và các "cửa hậu".
- **PAM (Pluggable Authentication Modules):** Hệ thống module xác thực của Linux. Mỗi dịch
  vụ (login, `su`, `sshd`…) có file cấu hình trong `/etc/pam.d/`. Các dòng "auth" quyết định
  việc xác thực thành công/thất bại ra sao, theo thứ tự.
  - `pam_succeed_if.so` cho phép **thành công nếu một điều kiện đúng** (ví dụ user hiện tại
    là ai). Kẻ cấu hình có thể lợi dụng để **bỏ qua mật khẩu** trong một số trường hợp.
  - Cú pháp kiểu `auth [success=ignore default=1] ...` và `auth sufficient ...` là các
    "control" điều khiển luồng: `sufficient` = nếu module này OK thì **coi như xác thực
    xong, không cần hỏi mật khẩu**.
- **`su` và login shell:** Lệnh `su <user>` chuyển sang người dùng khác; nếu thành công nó
  khởi chạy **login shell** của user đích. "Login shell" là chương trình chạy khi đăng nhập
  — thường là `/bin/bash`, nhưng có thể bị đổi thành **một script bất kỳ** (ở đây là một
  script tắt máy).
- **sudoers & NOPASSWD:** File `/etc/sudoers` cấp quyền chạy lệnh với `sudo`. Dòng
  `user ALL=NOPASSWD: /path/cmd` cho phép `user` chạy đúng lệnh đó **không cần mật khẩu**.
- **SUID bit (`chmod u+s`):** Cho phép file thực thi chạy với quyền của **chủ sở hữu** file
  thay vì người gọi. Thường gặp trong các bài leo thang đặc quyền.
- **`poweroff -i`:** Lệnh tắt máy ngay (`-i` = ignore inhibitors, bỏ qua các "chốt chặn").

### (c) Trinh sát ban đầu
```bash
cat linpeas.txt         # đọc toàn bộ user-data script
grep -iE "passwd|pam|sudoers|poweroff|usermod|PasswordAuth" linpeas.txt
```
Các dòng chủ chốt (trích từ file thật):
```bash
useradd -m "user"
echo "IamTheUser!" | passwd "user" --stdin                  # mật khẩu user
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
# --- PAM: cho phép user 'user' su sang 'shutdown' không cần mật khẩu ---
echo -e "auth\t[success=ignore default=1] pam_succeed_if.so\tuser = shutdown\n\
auth\tsufficient\tpam_succeed_if.so\tuse_uid user = user" > su.tmp   # ghép vào /etc/pam.d/su
# --- user 'shutdown': login shell là script tắt máy, có SUID ---
echo -e '#!/bin/bash\nsudo poweroff -i' > /sbin/system/shutdown.sh
chmod 750 /sbin/system/shutdown.sh
chmod u+s /sbin/system/shutdown.sh
usermod -s /sbin/system/shutdown.sh shutdown
echo "shutdown ALL=NOPASSWD: /usr/sbin/poweroff -i" >> /etc/sudoers
```

### (d) Phân tích từng bước + reasoning "tại sao"
Toàn bộ chuỗi là một "con đường tắt máy" đã được cài sẵn:
1. **Vào máy bằng user thường.** `user` có mật khẩu `IamTheUser!`, và SSH **bật đăng nhập
   bằng mật khẩu** (`PasswordAuthentication yes`). → Ta SSH được vào ngay.
2. **`su shutdown` không cần mật khẩu.** Luật PAM: khi **user hiện tại là `user`** và đang
   `su` sang `shutdown`, `pam_succeed_if` khớp điều kiện → `sufficient` → xác thực coi như
   xong, **bỏ qua hỏi mật khẩu**. *Tại sao đây là điểm mấu chốt?* Vì ta không biết mật khẩu
   của `shutdown`, nhưng PAM đã mở sẵn cửa.
3. **Login shell của `shutdown` tự tắt máy.** Khi `su shutdown` thành công, nó chạy login
   shell = `/sbin/system/shutdown.sh`, nội dung `sudo poweroff -i`.
4. **sudoers cho `shutdown` chạy `poweroff -i` không cần mật khẩu.** → `poweroff` thực thi
   → **máy tắt**.

Không có "hướng sai" phức tạp ở bài này; cái bẫy duy nhất là tên file `linpeas.txt` khiến
người chơi tưởng phải *chạy* linpeas, trong khi chỉ cần **đọc** nó để thấy cấu hình.

### (e) Lời giải / exploit đầy đủ
```bash
# 1) Đăng nhập bằng tài khoản thường
ssh user@<target_ip>
# khi được hỏi mật khẩu, nhập: IamTheUser!

# 2) Chuyển sang user 'shutdown' — PAM cho qua, KHÔNG hỏi mật khẩu
su shutdown
#   -> login shell = /sbin/system/shutdown.sh
#   -> script chạy: sudo poweroff -i   (sudoers = NOPASSWD)
#   -> MÁY TẮT
```
Ngay khi `su shutdown` thành công, máy mục tiêu bắt đầu quy trình tắt. Bài chấm bằng việc
máy ngừng hoạt động.

### (f) Flag & ý nghĩa
Bài này **không có chuỗi `CSG_FLAG{}`**. "Đáp án" là hành động: tắt được máy thông qua
chuỗi `user → su shutdown → poweroff`. Ý nghĩa giáo dục: cho thấy cấu hình PAM/sudoers sai
có thể tạo đường leo thang/điều khiển hệ thống dù không biết mật khẩu đích.

### (g) Cạm bẫy & cách khác
- **Cạm bẫy:** mất thời gian chạy `linpeas.sh` thật trên máy mục tiêu thay vì đọc file đề.
- **Cách khác:** Nếu `shutdown` có login shell là script SUID tắt máy, về lý thuyết chỉ cần
  gọi trực tiếp `/sbin/system/shutdown.sh` (nhưng cần quyền phù hợp); con đường `su` là lối
  "chính chủ" do đề cài sẵn.
- Lưu ý `PasswordAuthentication yes` là điều kiện cần để SSH bằng mật khẩu — nếu chỉ cho
  key thì phải có key.

### (h) Tham khảo
- `man pam_succeed_if`, `man 5 sudoers`, `man 5 pam.d`.
- AWS EC2 user-data documentation.
- HackTricks — Linux Privilege Escalation (PAM, sudoers, SUID).

---

## Bài 3 — Central African Republic C6 — A Very Old Odd File

### (a) Đề bài & metadata
- **Tên:** A Very Old Odd File — **Quốc gia/mã:** CAR / C6 — **Category:** misc / encoding — **Độ khó:** Trung bình.
- **Thư mục:** `2025-Cyber-SEA-Game/C6_a_very_old_odd_file/`
- **File đề:** `C6_a_very_old_odd_file.txt` (2180 byte, md5 `a2a7730f246d6fac829ddfe59a9be01e`) — một luồng dài chỉ gồm ký tự `.` và `-`.
- **Mô tả đề:** nhắc tới điện báo (telegraph) và Morse; nói flag có dạng `CSG_FLAG{LOOK.SOMETHING.LIKE.THIS}`.
- **Flag:** `CSG_FLAG{PUNCHCARDSAREDEADNOW}` *(đã chạy `solve.py` kiểm chứng).*

### (b) Kiến thức nền
- **Morse code:** Mã điện báo nổi tiếng, mỗi chữ cái là một chuỗi chấm/gạch **độ dài thay
  đổi** (A = `.-`, B = `-...`, E = `.`…). Vì độ dài khác nhau, Morse **bắt buộc có khoảng
  phân cách** giữa các chữ và từ, nếu không sẽ nhập nhằng không giải được.
- **Baudot / ITA2 (International Telegraph Alphabet No. 2):** Mã teleprinter **5 bit cố
  định** — ra đời để máy telex/teleprinter tự động hóa (ý tưởng mã cố định độ dài có trước
  cả thời Morse thống trị). 5 bit = 32 tổ hợp. Vì chỉ 32 tổ hợp không đủ cho cả chữ + số +
  dấu, ITA2 dùng **hai chế độ**: **LETTERS (LTRS)** và **FIGURES (FIGS)**, chuyển qua lại
  bằng hai mã shift đặc biệt. Khi ở chế độ LETTERS, mỗi 5 bit ra một chữ cái A–Z (hoặc ký
  tự điều khiển như space, CR, LF).
- **Vì sao "đều, không khoảng cách" ⇒ không phải Morse mà là mã 5 bit cố định:** Một luồng
  `.-` dài, **đồng đều**, **không có dấu tách** mà vẫn muốn giải ra chữ → gần như chắc chắn
  là mã **độ dài cố định** (cứ N ký tự = 1 đơn vị). N = 5 chính là Baudot/ITA2.
- **Bảng chính tả vô tuyến (spelling/phonetic alphabet):** Để đọc chữ cái qua radio cho rõ,
  người ta thay mỗi chữ bằng một **từ** bắt đầu bằng chữ đó. Mỗi nước có bảng riêng. **Bảng
  Thụy Điển:** ADAM=A, BERTIL=B, CAESAR=C, DAVID=D, ERIK=E, FILIP=F, GUSTAV=G, HELGE=H,
  IVAR=I, JOHAN=J, KALLE=K, LUDVIG=L, MARTIN=M, NIKLAS=N, OLOF=O, PETTER=P, QVINTUS=Q,
  RUDOLF=R, SIGURD=S, TORE=T, URBAN=U, VIKTOR=V, WILHELM=W, XERXES=X, YNGVE=Y, ZÄTA=Z…
- **Vấn đề "orientation" (chiều quy ước):** Khi map `.`/`-` sang bit, ta không biết `.`=1
  hay `.`=0, cũng không biết thứ tự bit trong mỗi nhóm 5 (MSB-first hay LSB-first). → Phải
  thử nhiều biến thể và chọn cái cho kết quả "có nghĩa".

### (c) Trinh sát ban đầu
```bash
wc -c C6_a_very_old_odd_file.txt      # ~2180 byte
tr -cd '.-' < C6_a_very_old_odd_file.txt | wc -c   # đếm số ký tự . và -
# -> chia hết cho 5? Nếu có -> củng cố giả thuyết mã 5-bit (Baudot)
head -c 120 C6_a_very_old_odd_file.txt            # xem mẫu: toàn . và - liền nhau
```
Quan sát: luồng `.-` dài, không khoảng trắng, số ký tự chia (gần) hết cho 5.

### (d) Phân tích từng bước + reasoning "tại sao"
1. **Loại trừ Morse.** Không có dấu tách → không phải Morse. Đề nhắc Morse là **mồi nhử**
   (red herring); gợi ý "older than Morse" chỉ về mã cố định → Baudot/ITA2.
2. **Giải ITA2 (chế độ LETTERS).** Map `.`/`-` → bit, cắt nhóm 5, tra bảng LETTERS. Vì chưa
   biết chiều, thử **4 biến thể**:
   - `.`=1, `-`=0 (không đảo bit trong nhóm)
   - `.`=1, `-`=0 (đảo thứ tự 5 bit trong mỗi nhóm)
   - `.`=0, `-`=1 (không đảo)
   - `.`=0, `-`=1 (đảo)
   Chấm điểm: biến thể nào giải ra **nhiều từ Thụy Điển hợp lệ nhất** là đúng.
3. **Lớp 2 — bảng Thụy Điển.** Văn bản ITA2 giải ra là chuỗi từ: `CAESAR SIGURD GUSTAV …`.
   Lấy chữ cái đầu mỗi từ → ghép lại:
   ```
   CSG UNDERSCORE FLAG OPENING BRACE PUNCH CARDS ARE DEAD NOW CLOSING BRACE
   ```
4. **Chuẩn hóa token sang ký hiệu:** `UNDERSCORE → _`, `OPENINGBRACE → {`,
   `CLOSINGBRACE → }`. Nội dung "PUNCH CARDS ARE DEAD NOW" (thẻ đục lỗ đã chết) là một câu
   đùa về công nghệ cũ — rất hợp chủ đề "very old odd file".

### (e) Lời giải / exploit đầy đủ
`solve.py` thực hiện toàn bộ và tự chọn biến thể đúng. Các phần cốt lõi:

```python
# Bảng ITA2 LETTERS: 5 bit -> ký tự (bỏ qua shift FIGS)
ITA2_LTRS = {0b00001:'E',0b00011:'A',0b00100:' ',0b00101:'S',0b00110:'I',
             0b00111:'U',0b01001:'D',0b01010:'R',0b01011:'J',0b01100:'N',
             0b01101:'F',0b01110:'C',0b01111:'K',0b10000:'T',0b10001:'Z',
             0b10010:'L',0b10011:'W',0b10100:'H',0b10101:'Y',0b10110:'P',
             0b10111:'Q',0b11000:'O',0b11001:'B',0b11010:'G',0b11100:'M',
             0b11101:'X',0b11110:'V', ...}

def bits_from_stream(stream, dot_as, dash_as, reverse_chunk):
    b = stream.replace('.', dot_as).replace('-', dash_as)   # . , - -> '0'/'1'
    if reverse_chunk:                                        # (tuỳ chọn) đảo 5 bit/nhóm
        return ''.join(b[i:i+5][::-1] for i in range(0, len(b)-len(b)%5, 5))
    return b[:(len(b)//5)*5]

def ita2_force_letters(bits):            # mỗi 5 bit -> 1 ký tự LETTERS
    return ''.join(ITA2_LTRS.get(int(bits[i:i+5],2), '') for i in range(0,len(bits),5))

SWE = {'ADAM':'A','BERTIL':'B','CAESAR':'C','DAVID':'D','ERIK':'E','FILIP':'F',
       'GUSTAV':'G','SIGURD':'S', ...}   # bảng chính tả Thụy Điển
def swedish_to_letters(text):            # mỗi từ -> chữ cái đầu
    return ''.join(SWE[w.upper()] for w in re.split(r'[^A-Za-z]+', text) if w.upper() in SWE)

# Thử 4 biến thể (dot=1/0, có/không đảo 5-bit), chọn biến thể ra nhiều chữ nhất
# Sau đó: UNDERSCORE->_, OPENINGBRACE->{, CLOSINGBRACE->}
```

**Chạy thực tế:**
```bash
$ python solve.py
CSG_FLAG{PUNCHCARDSAREDEADNOW}
```

### (f) Flag & ý nghĩa
```
CSG_FLAG{PUNCHCARDSAREDEADNOW}
```
"Punch cards are dead now" = thẻ đục lỗ (phương tiện lưu trữ/lập trình thời cổ) nay đã
tuyệt chủng — chủ đề hoài niệm công nghệ cũ, khớp với Baudot (cũng là công nghệ cổ).

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1:** Cắm đầu giải Morse → thất bại (đề cố tình dẫn dụ).
- **Cạm bẫy 2:** Giải ITA2 nhưng sai chiều bit → ra rác; phải thử đủ 4 biến thể.
- **Cạm bẫy 3:** Quên xử lý shift LTRS/FIGS; ở bài này chỉ dùng LETTERS nên ép chế độ
  LETTERS là đủ.
- **Cách khác:** CyberChef có thao tác "ITA2 / Baudot" và cho đổi chiều bit; có thể thử
  trực quan thay vì tự code.

### (h) Tham khảo
- Wikipedia: Baudot code / ITA2; Telegraph spelling alphabets (Swedish).
- CyberChef (operation Baudot/ITA2).

---

## Bài 4 — China C1 — XOR + Base64

### (a) Đề bài & metadata
- **Tên:** C1 — **Quốc gia/mã:** China / C1 — **Category:** crypto — **Độ khó:** Dễ–Trung bình.
- **Thư mục:** `2025-Cyber-SEA-Game/China_C1/`
- **File đề:** `chall.txt` (1190 byte, md5 `11a71d96ebeb102370ca075a9a9249dc`) — gồm vài cặp (CipherText, PlainText) mẫu và một CipherText cuối cần giải ra flag.
- **Flag:** `CSG_FLAG{Wont_U_make_Lemonade}` *(đã chạy `solve.py` kiểm chứng).*

### (b) Kiến thức nền
- **"Encrypted integers":** Mỗi ciphertext là một mảng **số nguyên có dấu** (−128…127).
  Đây thực chất là các **byte** biểu diễn dạng **bù hai (two's complement)**: byte 0xD0
  (208) hiển thị thành −48 (vì 208 − 256 = −48). Khi làm XOR, dấu không quan trọng — ta chỉ
  cần quy về byte 0–255 (ví dụ `b & 0xFF`).
- **XOR với keystream:** Nếu `C = B64 ⊕ K` thì `B64 = C ⊕ K`. Vấn đề là tìm `K` (khóa).
- **Known-plaintext attack (tấn công biết trước bản rõ):** Khi có cặp (ciphertext,
  plaintext) mẫu, ta có thể **suy ra khóa** vì `K = C ⊕ B64(plaintext)`. Từ đó phát hiện quy
  luật khóa rồi áp cho ciphertext bí mật.
- **Base64 ở lớp trong:** Ở bài này, plaintext không được XOR trực tiếp, mà **base64 của
  plaintext** mới bị XOR. Nên sau khi XOR xong phải **base64-decode** mới ra chữ.
- **Quan sát độ dài & cấu trúc chẵn:** Mỗi ciphertext có độ dài chẵn. Đây là manh mối "chia
  đôi".

### (c) Trinh sát ban đầu
```bash
cat chall.txt   # xem các cặp mẫu:
#   "Great Scott!" (12 ký tự) -> cipher 32 số
#   "Hello? Hello? Anybody home?" (27 ký tự) -> cipher 72 số
#   Flag cipher: 80 số
```
Nhận xét độ dài: base64("Great Scott!") = `R3JlYXQgU2NvdHQh` (16 ký tự) → cipher 32 = **đúng
gấp đôi**. Base64 của "Hello?...home?" dài 36 → cipher 72 = gấp đôi. → **mỗi ciphertext =
base64(plaintext) nối với khóa, mỗi nửa bằng nhau.**

### (d) Phân tích từng bước + reasoning "tại sao"
1. **Vì sao biết chia đôi?** Vì `len(cipher)` luôn = `2 × len(base64(plaintext))`.
   → Nửa đầu dài đúng bằng base64(plaintext).
2. **Thử giả thuyết:** `nửa_đầu ⊕ nửa_sau = base64(plaintext)?` Kiểm với "Great Scott!":
   lấy 16 số đầu XOR 16 số sau → ra đúng `R3JlYXQgU2NvdHQh` → base64-decode = "Great Scott!".
   ✅ Giả thuyết đúng. → **Nửa sau = keystream (khóa); nửa đầu = base64(pt) ⊕ khóa.**
3. **Chi tiết thú vị (củng cố):** Đuôi khóa của "Great Scott!"
   (`-121,-103,-89,106,58,67,-111,-69,69,114,-102,2,108,-8,-10,-47`) **xuất hiện lại** làm
   một đoạn trong ciphertext "Hello?..." — cho thấy keystream có phần dùng chung/sinh theo
   quy luật, nhưng ta **không cần** hiểu quy luật đó: vì khóa luôn nằm ở **nửa sau** của
   chính ciphertext, ta tự lấy được.
4. **Áp cho flag:** CipherText flag có 80 số → nửa đầu 40, nửa sau 40. XOR hai nửa →
   base64-decode → flag.

### (e) Lời giải / exploit đầy đủ
```python
import base64

cipher = [0xd0,0x23,0xc9,0xa3,0x3f,0x99,0x51,0x55,0x36,0x01,0x94,0xfc,0xf0,0x4d,0x05,0x3a,
          0xfb,0xc7,0x0f,0x96,0x90,0xa4,0x89,0x82,0xc9,0xb0,0xb5,0xe5,0x29,0x1b,0x0b,0xb9,
          0xc5,0x21,0x70,0xb5,0x13,0xa1,0xff,0x32,                     # <-- hết nửa đầu (40)
          0x81,0x12,0x87,0xeb,0x67,0xa9,0x0b,0x18,0x67,0x54,0xf0,0xcb,0xa6,0x7f,0x3c,0x4f,
          0x9f,0x81,0x36,0xc0,0xc8,0x96,0xb8,0xea,0xa8,0x82,0xe3,0x83,0x7d,0x5c,0x5d,0xcd,
          0xa7,0x13,0x45,0xdd,0x49,0xe6,0xa9,0x0b]                     # <-- nửa sau = khóa

half = len(cipher) // 2                      # 40
data, key = cipher[:half], cipher[half:]     # tách 2 nửa
b64  = bytes(d ^ k for d, k in zip(data, key))   # XOR từng byte -> chuỗi base64
print(base64.b64decode(b64).decode())            # decode -> flag
```
*(Lưu ý: `chall.txt` cho số có dấu như −48; ở script dùng dạng dương 0xD0. Chúng tương đương
theo bù hai; nếu dùng số âm chỉ cần `(d & 0xFF)` trước khi XOR.)*

**Chạy thực tế:**
```bash
$ python solve.py
CSG_FLAG{Wont_U_make_Lemonade}
```

### (f) Flag & ý nghĩa
```
CSG_FLAG{Wont_U_make_Lemonade}
```
"Won't U make Lemonade" — câu nói vui ("khi đời cho bạn quả chanh, hãy làm nước chanh").
Các plaintext mẫu ("Great Scott!", "Anybody home?") đều là câu thoại nổi tiếng từ phim
*Back to the Future* — chủ đề của bộ đề.

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1:** Quên base64-decode sau khi XOR → ra chuỗi base64 khó hiểu, tưởng sai.
- **Cạm bẫy 2:** Không quy số âm về byte 0–255 → XOR sai (nếu ngôn ngữ xử lý số âm khác đi).
- **Cạm bẫy 3:** Cố đi tìm "thuật toán sinh khóa" — không cần, vì khóa nằm ngay nửa sau.
- **Cách khác:** Dùng known-plaintext để recover khóa từ cặp mẫu, rồi mới nhận ra khóa =
  nửa sau — nhưng cách "chia đôi" trực tiếp nhanh hơn.

### (h) Tham khảo
- XOR cipher & known-plaintext attack (lý thuyết cơ bản).
- Python `base64`, biểu diễn bù hai (two's complement).

---

## Bài 5 — DR Congo C2 — Plato

### (a) Đề bài & metadata
- **Tên:** Plato — **Quốc gia/mã:** DR Congo / C2 — **Category:** forensics / stego + crypto — **Độ khó:** Trung bình.
- **Thư mục:** `2025-Cyber-SEA-Game/Democratic_Republic_of_the_Congo_C2_Plato/`
- **File đề:** `C2_Plato.jpg` (6.406.965 byte, md5 `35e5e1a9984827135c29df5eb64c692d`) — ảnh JPEG bức *The Death of Socrates* (Cái chết của Socrates, tranh của Jacques-Louis David). Repo **không có script solve**, chỉ có README.
- **Flag:** `CSG_FLAG{Yay!==You-are-successfully-decoded-Vigenere-cipher-inside-pictures!-Congratulations!!}`

### (b) Kiến thức nền
- **File polyglot / dữ liệu nối đuôi (appended data):** Định dạng JPEG kết thúc ở marker
  `FF D9`. Mọi byte **sau** đó bị trình xem ảnh bỏ qua. Kẻ giấu tin lợi dụng điều này để
  **dán một file ZIP vào đuôi ảnh**: mở bằng trình xem ảnh thì thấy ảnh bình thường, nhưng
  thực ra file chứa cả một archive. ZIP bắt đầu bằng chữ ký `PK\x03\x04`.
- **`binwalk`:** Công cụ quét một file để tìm các "chữ ký" của định dạng khác nhúng bên
  trong (ZIP, PNG, gzip…) và trích (carve) chúng ra.
- **`strings`:** In ra các chuỗi ký tự ASCII/Unicode đọc được trong một file nhị phân — hữu
  ích để tìm text ẩn.
- **Vigenère cipher:** (đã nêu ở phần chung) mã thay thế đa bảng, dịch mỗi chữ theo một chữ
  của khóa lặp. **Cách tìm khóa khi biết một đoạn plaintext:** nếu biết ciphertext `C` tương
  ứng plaintext `P` ở đầu, thì `K[i] = (C[i] − P[i]) mod 26`. Ở CTF, đoạn đầu thường là
  định dạng flag đã biết (`CSG_FLAG`).
- **Visual reassembly (ráp hình):** Khi ảnh gốc bị cắt thành nhiều mảnh (tiles), thứ tự ghép
  các mảnh = thứ tự ghép dữ liệu ẩn trong chúng. Ráp lại bức tranh cho "khớp mắt" sẽ cho thứ
  tự đúng.

### (c) Trinh sát ban đầu
```bash
file C2_Plato.jpg                       # JPEG image data
binwalk C2_Plato.jpg                    # phát hiện Zip archive nối ở đuôi
binwalk -e C2_Plato.jpg                 # trích (hoặc tự tìm PK\x03\x04 rồi carve)
# ZIP có mật khẩu -> giải nén ra 12 ảnh tile của bức "The Death of Socrates"
strings tile_01.png                     # mỗi tile chứa một đoạn text ngắn bị xáo
```

### (d) Phân tích từng bước + reasoning "tại sao"
1. **Carve ZIP khỏi JPEG.** `binwalk` thấy ZIP ở đuôi. ZIP có mật khẩu → giải nén ra **12
   mảnh ảnh** của bức tranh.
2. **Lấy mảnh text.** `strings` mỗi tile → mỗi ảnh chứa **một đoạn text ngắn bị xáo**
   (12 đoạn):
   ```
   q-pvothd   ef!-Ooas   g-aeq-sh   eeq-cvbh   rd-iaeiq   ocressgl
   uemthdag   guoae!!}   {Ynk!==Yb   qd-Iugrz   OST_RLNS   yk-drooq
   ```
3. **Ráp tile → thứ tự.** Ghép bức tranh đúng vị trí cho thứ tự mảnh:
   ```
   11 - 9 - 3 - 6 - 12 - 10 - 4 - 5 - 1 - 2 - 7 - 8
   ```
   Nối các đoạn theo thứ tự đó:
   ```
   OST_RLNS{Ynk!==Ybg-aeq-shocressglyk-drooqqd-Iugrzeeq-cvbhrd-iaeiqq-pvothdef!-Ooasuemthdagguoae!!}
   ```
4. **Nhận ra Vigenère.** `OST_RLNS` rõ ràng là `CSG_FLAG` bị dịch (C→O, S→S, G→T, F→R,
   L→L, A→N, G→S). *Tại sao nghĩ tới Vigenère?* Vì chỉ các **chữ cái** bị đổi, còn
   `_ { } ! = -` giữ nguyên — đặc trưng của mã thay thế chỉ áp lên A–Z.
5. **Tìm khóa.** Từ `CSG_FLAG` ↔ `OST_RLNS`:
   `O−C=M, S−S=A, T−G=N, R−F=M, L−L=A, N−A=N, S−G=M` → dòng khóa lặp `M, A, N, M, A, N…`
   → **khóa = `MAN`**. *(Mình đã tính và xác nhận.)*

### (e) Lời giải / exploit đầy đủ
Vì repo thiếu script, đây là script tái lập (đã chạy kiểm chứng):
```python
# 1) carve ZIP
data = open("C2_Plato.jpg","rb").read()
idx  = data.find(b"PK\x03\x04")
open("embedded.zip","wb").write(data[idx:])
# 2) giải nén (mật khẩu đi kèm đề) -> 12 tile ; strings từng tile -> 12 đoạn
# 3) ghép theo thứ tự ráp tranh: 11,9,3,6,12,10,4,5,1,2,7,8
ct = "OST_RLNS{Ynk!==Ybg-aeq-shocressglyk-drooqqd-Iugrzeeq-cvbhrd-iaeiqq-pvothdef!-Ooasuemthdagguoae!!}"
# 4) giải Vigenère với khóa MAN (chỉ dịch A-Z/a-z, giữ nguyên ký tự khác)
key = "MAN"; out = []; ki = 0
for ch in ct:
    if ch.isalpha():
        k = ord(key[ki % len(key)]) - ord('A')
        base = ord('A') if ch.isupper() else ord('a')
        out.append(chr((ord(ch) - base - k) % 26 + base))
        ki += 1
    else:
        out.append(ch)
print("".join(out))
```

**Kết quả chạy thực tế:**
```
CSG_FLAG{Yay!==You-are-successfully-decoded-Vigenere-cipher-inside-pictures!-Conguraturatuuboe!!}
```

> ⚠️ **Đính chính quan trọng:** Khóa `MAN` giải **đúng hoàn hảo** phần đầu tới
> `...inside-pictures!-Cong`, nhưng phần đuôi ra `uraturatuuboe!!}` thay vì
> `ratulations!!}`. Để kiểm tra, mình **mã hóa ngược** flag công bố bằng khóa `MAN`:
> ```
> intended : OST_RLNS{Ynk!==Ybg-aeq-shocressglyk-drooqqd-Iugrzeeq-cvbhrd-iaeiqq-pvothdef!-Ooasrnfuymtvanf!!}
> README   : OST_RLNS{Ynk!==Yb...                                            ...-Ooasuemthdagguoae!!}
> ```
> Hai chuỗi **khớp nhau tới `-Ooas`** rồi lệch. Nghĩa là **hai mảnh tile cuối**
> (`uemthdag` và `guoae!!}`, tức các mảnh ở vị trí 7 và 8 trong README) đã bị **copy/sắp
> sai** trong README. Flag công bố vẫn **đúng** (xác nhận qua phần đầu khớp tuyệt đối và
> qua mã hóa ngược). Tóm lại: **khóa chắc chắn là `MAN`; flag chắc chắn đúng; chỉ chuỗi
> ciphertext đã-ghép trong README bị lỗi ở 2 mảnh cuối.**

### (f) Flag & ý nghĩa
```
CSG_FLAG{Yay!==You-are-successfully-decoded-Vigenere-cipher-inside-pictures!-Congratulations!!}
```
Nội dung flag tự mô tả: "bạn đã giải thành công mã Vigenère giấu bên trong các bức ảnh".
Tên bài "Plato" + tranh "The Death of Socrates" (Socrates là thầy của Plato) là lớp chủ đề.

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1:** Không để ý ZIP nối đuôi (chỉ mở ảnh bằng trình xem ảnh → không thấy gì).
- **Cạm bẫy 2:** Sai thứ tự ráp tile → chuỗi Vigenère sai → giải ra rác.
- **Cạm bẫy 3:** Tưởng là ROT13/Caesar (dịch cố định). Thực ra khóa 3 chữ `MAN` nên là
  Vigenère.
- **Cách khác tìm khóa:** Dùng dcode.fr "Vigenère automatic solver" hoặc phân tích tần suất;
  nhưng known-plaintext (`CSG_FLAG`) là nhanh nhất.

### (h) Tham khảo
- `binwalk`, file polyglot JPEG+ZIP.
- Vigenère cipher; dcode.fr / CyberChef (Vigenère Decode).

---

## Bài 6 — France N1 — QR shares + S3 SSE-C

### (a) Đề bài & metadata
- **Tên:** N1 — **Quốc gia/mã:** France / N1 — **Category:** crypto / stego / web — **Độ khó:** Khó.
- **Thư mục:** `2025-Cyber-SEA-Game/France_N1/`
- **File đề:** `index.html` (15751 byte, md5 `a37b52803a0676fef598729f46fedbc3`). Mô tả đề dẫn dắt về AES và một file HTML bí ẩn.
- **Kết quả:** QR giải ra URL S3; file flag host trên S3 (đã gỡ sau giải). *(Repo không có chuỗi flag cuối.)*

### (b) Kiến thức nền
- **Ảnh nhúng base64 trong HTML (`data:` URI):** Thay vì link tới file ảnh, HTML/CSS có thể
  nhúng thẳng ảnh bằng `data:image/png;base64,<chuỗi base64>`. Trình duyệt tự decode và hiển
  thị. → Có thể rút các ảnh này ra chỉ bằng cách parse chuỗi base64.
- **QR code & "visual cryptography / secret sharing":** QR là mã vạch 2D. Trong kỹ thuật
  "chia sẻ bí mật trực quan", một ảnh (ví dụ QR) được tách thành nhiều **mảnh (share)** trông
  như nhiễu ngẫu nhiên; chỉ khi **kết hợp** đúng cách (XOR, chồng lớp, lấy min/max…) các mảnh
  mới hiện ra ảnh gốc. Mỗi mảnh đơn lẻ không lộ gì.
- **Xử lý ảnh để phục hồi QR:** Các phép thường thử: lọc nhiễu (median filter), nhị phân hóa
  theo ngưỡng (threshold), đảo màu (invert), và **kết hợp nhiều ảnh**: trung vị (median), nhỏ
  nhất (min), lớn nhất (max), XOR bit, độ lệch chuẩn (std) để làm nổi điểm khác biệt.
- **OpenCV `QRCodeDetector`:** Thư viện thị giác máy tính có sẵn hàm `detectAndDecode()` để dò
  và giải QR tự động.
- **Amazon S3 & SSE-C:** S3 là dịch vụ lưu trữ object của AWS. **SSE-C** (Server-Side
  Encryption with Customer-provided keys) cho phép lưu object mã hóa AES-256 với **khóa do
  khách cung cấp**. Khi GET, phải gửi lại đúng khóa qua các header
  (`x-amz-server-side-encryption-customer-*`), nếu không S3 trả lỗi `InvalidRequest`.
- **Proxy `fetch.php`:** Một endpoint server-side đóng vai trung gian: client gọi `fetch.php`,
  nó thay mặt gọi S3 **kèm sẵn khóa SSE-C đúng**, rồi trả nội dung về. Đây là "lối đi hợp lệ"
  mà đề thiết kế.

### (c) Trinh sát ban đầu
```bash
grep -o "data:image" index.html | wc -l       # -> 4  (4 ảnh nhúng)
grep -oE "\.bg[0-9]" index.html | sort -u      # -> .bg1 .bg2 .bg3 .bg4 (4 ô bảng)
grep -o "fetch.php" index.html                 # -> có tham chiếu fetch.php (proxy)
```
*(Mình đã xác nhận cả 3 điều trên trong `index.html` thật.)* HTML vẽ một bảng 4 ô, mỗi ô nền
là một ảnh PNG base64 (`.bg1`..`.bg4`); mỗi ảnh nhìn như **QR bị nhiễu**.

### (d) Phân tích từng bước + reasoning "tại sao"
1. **Rút 4 ảnh base64** từ HTML. *Tại sao 4?* Vì chúng là 4 "mảnh share" của một QR.
2. **Từng ảnh đơn lẻ không giải được QR** (quá nhiễu) → phải **kết hợp**. Vì không biết cách
   kết hợp chính xác, script sinh **hàng loạt biến thể**: per-image (median/threshold/invert)
   và cross-image (median/min/max/XOR/std), kèm phóng to (1.5×/2×/3×).
3. **Giải QR tự động** mọi biến thể bằng OpenCV. Một tổ hợp (ở lần chạy gốc là `var_14.png`)
   ra QR sạch, giải được URL S3:
   ```
   https://cyberseagame2025.s3.us-east-2.amazonaws.com/ltnytc9p84wy8pcw8y4tc.txt
   ```
4. **GET thẳng URL thất bại** vì object dùng **SSE-C**:
   ```
   InvalidRequest: The object was stored using a form of Server Side Encryption.
   The correct parameters must be provided to retrieve the object.
   ```
   *Tại sao?* SSE-C yêu cầu gửi khóa AES-256; GET trần không có khóa.
5. **Hướng khai thác dự kiến:** dùng **proxy `fetch.php`** (có trong trang) — nó đã cầm sẵn
   khóa SSE-C, nên request qua proxy mới đọc được file `.txt` chứa flag.

### (e) Lời giải / exploit đầy đủ
`extract_decode.py` (dùng Pillow, numpy, OpenCV):
```python
import re, base64
from pathlib import Path

# 1) Rút 4 ảnh base64 từ data:image/...;base64,<...>
pattern = re.compile(r"data:image/[^;]+;base64,([A-Za-z0-9+/=]+)")
imgs = [base64.b64decode(m) for m in pattern.findall(Path("index.html").read_text())]
# -> lưu img1.png..img4.png

# 2) Sinh biến thể phục hồi QR:
#    - per-image: MedianFilter, invert, threshold(>128)
#    - cross-image: np.median / np.max / np.min / bitwise_xor / std  trên stack 4 ảnh
#    - phóng to NEAREST 1.5x/2x/3x
# 3) detectAndDecode mọi biến thể bằng cv2.QRCodeDetector
import cv2
det = cv2.QRCodeDetector()
for p in variant_paths:
    data, pts, _ = det.detectAndDecode(cv2.imread(str(p)))
    if data:
        print("DECODED:", data)       # -> URL S3 .../ltnytc9p84wy8pcw8y4tc.txt
```
Sau khi có URL: vì SSE-C nên **không GET trực tiếp**; phải gọi qua `fetch.php` để nhận nội
dung file `.txt` (nơi chứa flag).

### (f) Flag & ý nghĩa
> ⚠️ **Đính chính:** Writeup gốc **dừng ở** việc giải QR ra URL S3 và xác định cơ chế SSE-C
> + proxy `fetch.php`; **không có chuỗi flag cuối** trong repo. Flag thật phụ thuộc hạ tầng
> S3 của giải (đã bị gỡ sau sự kiện), nên không thể lấy lại bằng phân tích tĩnh hiện tại.
> Mức giải được xác nhận chắc chắn: *4 ảnh share → kết hợp → QR → URL S3 → cần `fetch.php`
> vượt SSE-C → đọc `.txt` lấy flag.*

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1:** Thử giải QR từng ảnh riêng → luôn thất bại; phải kết hợp nhiều ảnh.
- **Cạm bẫy 2:** Thấy URL S3 rồi GET thẳng → dính lỗi SSE-C, dễ tưởng URL sai.
- **Cạm bẫy 3:** Bỏ qua `fetch.php` trong HTML — đó mới là "chìa khóa" để vượt SSE-C.
- **Cách khác phục hồi QR:** chồng ảnh thủ công trong GIMP (layer + blend mode), hoặc thử
  XOR từng cặp. Cách brute nhiều biến thể + OpenCV là tự động và chắc ăn nhất.

### (h) Tham khảo
- AWS S3 SSE-C documentation (customer-provided keys).
- OpenCV `QRCodeDetector`; Pillow/numpy image ops.
- Visual secret sharing (QR shares).

---

## Bài 7 — Germany N2 — Silent Call, Loud Message

### (a) Đề bài & metadata
- **Tên:** Silent Call, Loud Message — **Quốc gia/mã:** Germany / N2 — **Category:** forensics / network — **Độ khó:** Trung bình.
- **Thư mục:** `2025-Cyber-SEA-Game/Germany_N2/`
- **File đề:** `packet.pcap` (174067 byte, md5 `5e3824660031774d00d76b7241de6e68`) — bắt gói một phiên gọi VoIP; kèm `sonic_visualiser.png` (ảnh gợi ý phổ âm thanh).
- **Flag:** `CSG_FLAG{Y0UAREDECODEDV01P}`

### (b) Kiến thức nền
- **VoIP (Voice over IP):** Gọi điện qua mạng IP. Gồm 2 phần: **signaling** (báo hiệu — thiết
  lập/kết thúc cuộc gọi) và **media** (luồng tiếng nói thực sự).
- **SIP (Session Initiation Protocol):** Giao thức báo hiệu, chạy trên UDP cổng **5060**. Các
  bản tin như `INVITE`, `200 OK`, `ACK`, `BYE`. Trong `INVITE` có phần **SDP** mô tả media.
- **SDP (Session Description Protocol):** Mô tả "sẽ truyền media gì, codec nào, cổng nào".
  Dòng `a=rtpmap:<PT> <codec>/<clock>` khai báo codec. Ví dụ `a=rtpmap:0 PCMU/8000` nghĩa là
  payload type **0** = codec **PCMU** (G.711 µ-law) ở 8000 Hz.
- **RTP (Real-time Transport Protocol):** Giao thức mang luồng media. Mỗi gói RTP có header
  ≥ 12 byte: version (2), **payload type (PT)**, **sequence number** (đánh số thứ tự),
  **timestamp**, và **SSRC** (định danh nguồn luồng). Để ghép âm thanh đúng, gom theo SSRC rồi
  sắp theo sequence/timestamp.
- **G.711 µ-law (PCMU):** Chuẩn nén thoại. µ-law mã hóa mỗi mẫu âm thanh thành 1 byte (nén
  logarit). Giải mã (µ-law → PCM16) cho ra mẫu 16-bit chuẩn để ghi file WAV. Trong Python:
  `audioop.ulaw2lin(data, 2)`.
- **Giấu tin trong âm thanh (audio stego):** "Message" có thể không phải giọng người mà là
  các **chùm tone** bật/tắt — khi nhìn phổ (spectrogram) trong công cụ như **Sonic
  Visualiser**, các chùm này tạo thành **mã Morse** (tone dài = gạch, tone ngắn = chấm).

### (c) Trinh sát ban đầu
```bash
# Mở trong Wireshark: Telephony > VoIP Calls / RTP > Stream Analysis
strings packet.pcap | grep -iE "rtpmap|PCMU|INVITE|sip"
```
Kết quả `strings` (đã xác nhận trên file thật):
```
INVITE sip:bob@10.0.0.2 SIP/2.0
From: "Alice" <sip:alice@10.0.0.1>;tag=f1846
To: <sip:bob@10.0.0.2>
Content-Type: application/sdp
a=rtpmap:0 PCMU/8000            <-- codec = G.711 µ-law, PT=0
SIP/2.0 200 OK
```
→ Alice (`10.0.0.1`) gọi Bob (`10.0.0.2`), media là PCMU/8000.

### (d) Phân tích từng bước + reasoning "tại sao"
1. **Xác định codec từ SDP.** `a=rtpmap:0 PCMU/8000` → RTP PT=0 = G.711 µ-law 8 kHz. *Tại
   sao cần?* Để biết cách giải payload RTP thành âm thanh.
2. **Ráp luồng RTP.** Lọc các gói RTP (version 2, header ≥ 12 byte, không phải RTCP), gom
   theo SSRC, sắp theo sequence/timestamp. *Tại sao?* Gói mạng có thể đảo thứ tự; phải sắp lại
   để âm thanh liền mạch.
3. **Giải µ-law → PCM → WAV.** Nối payload PT=0, `ulaw2lin` → PCM16 8 kHz, ghi WAV.
4. **"Nghe" tín hiệu.** WAV **không phải giọng nói**. Mở trong Sonic Visualiser (xem
   spectrogram) thấy các chùm tone — chính là **Morse**. Giải Morse:
   ```
   -.-- ----- ..- .- .-. . -.. . -.-. --- -.. . -.. ...- ----- .---- .--.
    Y    0    U  A  R  E   D  E   C   O  D   E  D   V    0    1    P
   ```
   (dùng `0`=zero, `1`=one theo kiểu leet).

### (e) Lời giải / exploit đầy đủ
Repo không kèm `.py`; đây là script tái lập (pyshark hoặc scapy + audioop):
```python
import audioop, wave
from scapy.all import rdpcap, UDP, Raw

pkts = rdpcap("packet.pcap")
payload = b""
for p in pkts:                                   # gom payload RTP PT=0
    if UDP in p and Raw in p:
        d = bytes(p[Raw].load)
        if len(d) >= 12 and (d[0] >> 6) == 2:    # RTP version 2
            pt = d[1] & 0x7F
            if pt == 0:                          # PCMU
                payload += d[12:]                # bỏ 12 byte header
pcm = audioop.ulaw2lin(payload, 2)               # µ-law -> PCM16
w = wave.open("out.wav","wb"); w.setnchannels(1); w.setsampwidth(2)
w.setframerate(8000); w.writeframes(pcm); w.close()
# Mở out.wav trong Sonic Visualiser -> đọc Morse -> Y0UAREDECODEDV01P
```
Giải Morse thủ công hoặc bằng script cho ra `Y0UAREDECODEDV01P`.

### (f) Flag & ý nghĩa
```
CSG_FLAG{Y0UAREDECODEDV01P}
```
"You are decoded VoIP" — xác nhận bạn đã giải mã được luồng VoIP. Tên bài "Silent Call, Loud
Message" ám chỉ: cuộc gọi "im lặng" (không có tiếng nói) nhưng lại mang thông điệp (Morse).

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1:** Chỉ đọc SIP header → không thấy gì (message nằm trong media).
- **Cạm bẫy 2:** Dùng Wireshark "Play" audio rồi nghe → khó nhận ra Morse bằng tai; nhìn
  spectrogram dễ hơn nhiều.
- **Cạm bẫy 3:** Sai thứ tự RTP (không sắp theo sequence) → âm thanh rối.
- **Cách khác:** Wireshark có sẵn **RTP → Export Audio** (xuất `.au`/`.wav`) nếu nhận diện
  được stream; sau đó mở Audacity/Sonic Visualiser xem spectrogram.

### (h) Tham khảo
- RFC 3261 (SIP), RFC 4566 (SDP), RFC 3550 (RTP), G.711 (ITU-T).
- Python `audioop.ulaw2lin`; Sonic Visualiser; Wireshark RTP analysis.

---

## Bài 8 — Greece R2 — Packer

### (a) Đề bài & metadata
- **Tên:** Packer — **Quốc gia/mã:** Greece / R2 — **Category:** reverse — **Độ khó:** Trung bình.
- **Thư mục:** `2025-Cyber-SEA-Game/Greece/`
- **File đề:** `packed.exe` (209408 byte, md5 `0728bfc481ee20fdad43dbda9d35158f`) — PE32+ (64-bit) là một "packer" tự chế, mang theo payload mã hóa.
- **Flag:** `CSG_FLAG{packer_daisuki}` *(đã kiểm chứng: AES-ECB decrypt payload → PE hợp lệ chứa flag).*

### (b) Kiến thức nền
- **Packer là gì:** Chương trình "đóng gói" một payload (ở đây là một DLL) đã nén/mã hóa vào
  trong một "stub" (đoạn mồi). Khi chạy, stub **tự giải mã** payload trong bộ nhớ rồi nạp và
  thực thi. Mục đích: giảm kích thước, hoặc **chống phân tích** (malware hay dùng). Để giải
  bài, ta **dịch ngược stub** để biết thuật toán + khóa + vị trí payload — rồi tự giải mã,
  **không cần chạy exe**.
- **Cấu trúc PE & RVA:** (xem phần chung) PE bắt đầu `MZ`; RVA là địa chỉ ảo tương đối. Khi
  file nằm trên đĩa, cùng một RVA ứng với một **offset file** khác (do alignment section). Thư
  viện `pefile` có `get_offset_from_rva(rva)` để quy đổi.
- **AES-128-ECB:** Mã khối AES với khóa 128-bit (16 byte), chế độ ECB (mỗi khối 16 byte độc
  lập). Giải mã cần đúng 16 byte khóa.
- **Nhận diện khóa/hằng số hardcoded:** Khi dịch ngược (IDA/Ghidra/x64dbg), khóa thường xuất
  hiện dưới dạng một dãy byte nạp vào bộ nhớ ngay trước lời gọi hàm AES, hoặc một blob 16 byte.
  Việc "verify" output là PE (`MZ` + `PE\0\0`) chứng minh đã decrypt đúng.

### (c) Trinh sát ban đầu
```bash
file packed.exe                 # PE32+ executable (DLL/console) for MS Windows
strings packed.exe | grep -i -E "aes|key|dll"   # manh mối thuật toán
# Mở trong Ghidra/IDA: tìm hàm giải mã (gọi AES), lấy:
#   - vị trí payload (RVA), kích thước
#   - khóa 16 byte
```
Các hằng số dịch ngược được:
- Payload tại **RVA `0xF370`**, kích thước **`0x19A00`** (= 104.960 byte).
- Khóa AES-128: `49 6D 6C 39 43 90 AF 04 DD 0A BF D8 DF F1 9F B9`.

### (d) Phân tích từng bước + reasoning "tại sao"
1. **Dịch ngược stub** → thấy pattern: đọc một blob tại RVA cố định, gọi AES-128-ECB với khóa
   cứng, rồi nạp kết quả như DLL. *Tại sao biết là DLL?* Vì sau giải mã stub gọi các API nạp
   module, và output bắt đầu bằng `MZ`.
2. **Trích hằng số** (RVA, size, key) từ disassembly.
3. **Tự giải mã tĩnh** (đọc file, không chạy): AES-ECB decrypt blob. *Kiểm chứng:* nếu kết
   quả bắt đầu `MZ` và tại `e_lfanew` có `PE\0\0` → đã đúng.
4. **Tìm flag:** flag là **chuỗi thường** nằm trong DLL đã giải mã → `strings | grep CSG`.

### (e) Lời giải / exploit đầy đủ
`decrypt_payload.py` (cần `pefile`, `pycryptodome`) — **chỉ đọc** `packed.exe`, không thực thi:
```python
import pefile, re
from Crypto.Cipher import AES

PE_PATH = "packed.exe"
RVA, SIZE = 0xF370, 0x19A00
KEY = bytes([0x49,0x6D,0x6C,0x39,0x43,0x90,0xAF,0x04,
             0xDD,0x0A,0xBF,0xD8,0xDF,0xF1,0x9F,0xB9])

pe = pefile.PE(PE_PATH, fast_load=False)
fo = pe.get_offset_from_rva(RVA)              # RVA -> offset file
with open(PE_PATH,"rb") as f:
    f.seek(fo); enc = f.read(SIZE)            # đọc blob mã hóa

dec = AES.new(KEY, AES.MODE_ECB).decrypt(enc) # AES-128-ECB giải mã
assert dec[:2] == b"MZ"                        # kiểm: phải là PE
el = int.from_bytes(dec[0x3C:0x40], "little")  # e_lfanew
assert dec[el:el+4] == b"PE\x00\x00"           # kiểm chữ ký PE

open("payload.dll","wb").write(dec)            # xuất DLL (104960 byte)
for m in re.finditer(rb"CSG_FLAG\{[^}]{3,100}\}", dec):
    print("FLAG:", m.group(0).decode())
```

**Chạy thực tế (đã kiểm chứng):**
```
decrypted first 2 bytes: b'MZ'
e_lfanew 0x100  sig b'PE\x00\x00'
FLAG: CSG_FLAG{packer_daisuki}
```
(Hoặc `strings payload.dll | grep CSG` cho cùng kết quả.)

### (f) Flag & ý nghĩa
```
CSG_FLAG{packer_daisuki}
```
`daisuki` (大好き) tiếng Nhật = "rất thích/yêu thích". Nghĩa vui: "thích packer".

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1:** Nhầm RVA với offset file → đọc sai vùng. Phải quy đổi qua `pefile`.
- **Cạm bẫy 2:** Dùng sai chế độ AES (CBC cần IV) — ở đây là ECB, không cần IV.
- **Cạm bẫy 3:** Chạy thẳng `packed.exe` để "xem flag" — rủi ro và không cần thiết; giải tĩnh
  an toàn hơn.
- **Cách khác:** Dùng x64dbg đặt breakpoint sau lệnh giải mã rồi dump vùng nhớ payload (dynamic
  unpacking) — nhưng phải chạy binary (kém an toàn).

### (h) Tham khảo
- `pefile` (Python), pycryptodome `AES`.
- Cấu trúc PE (MZ/DOS header, e_lfanew, PE signature).
- Kỹ thuật unpacking (static vs dynamic).

### (i) Dịch ngược tĩnh THẬT (pefile + section + byte-level payload)

Phân tích **thật** trên `packed.exe` bằng `objdump -h` + `python pefile` + AES-decrypt dữ liệu
(không chạy exe).

**1) Thông tin PE (pefile, THẬT):**
```
Machine     0x8664   -> x86-64 (PE32+)
Subsystem   2        -> GUI       EntryPoint RVA 0x1b38   ImageBase 0x140000000
Sections (6):
  .text   VA 0x1000   VSize 0xd630   RawPtr 0x400    RawSz 0xd800
  .rdata  VA 0xf000   VSize 0x22fac  RawPtr 0xdc00   RawSz 0x23000
  .data   VA 0x32000  VSize 0x1e78   RawPtr 0x30c00  RawSz 0xc00
  .pdata  VA 0x34000  ...   _RDATA VA 0x35000 ...   .reloc VA 0x36000 ...
```
`objdump -h packed.exe` xác nhận `file format pei-x86-64` và cùng danh sách section.

**2) Payload mã hóa nằm ở đâu — quy đổi RVA→offset THẬT:**
```python
pe.get_offset_from_rva(0xF370)   # -> 0xdf70
```
RVA `0xF370` rơi vào section **`.rdata`** (vì `0xf000 ≤ 0xF370 < 0xf000+0x22fac`). Tức blob
payload được giấu như **dữ liệu chỉ đọc**. Đọc 16 byte đầu (đã mã hóa) tại file offset `0xdf70`:
```
a2 b9 c6 c6 b8 b0 b8 1f 73 86 cb 38 2d 4d f8 6f
```
→ rõ ràng **không phải `MZ`** khi chưa giải mã.

**3) Khóa AES nằm trong binary — tìm THẬT:** tìm 16 byte khóa trong file:
```python
key = bytes([0x49,0x6D,0x6C,0x39,0x43,0x90,0xAF,0x04,0xDD,0x0A,0xBF,0xD8,0xDF,0xF1,0x9F,0xB9])
data.find(key)   # -> 0x27978  (nằm trong .rdata; RVA 0x29378; VA 0x140029378)
```
→ khóa là hằng số **hardcoded** trong `.rdata`, không build trên stack. (Trong disassembly x64,
stub nạp khóa bằng `lea reg, [rip+disp]` trỏ tới VA `0x140029378`.)

**4) Giải mã AES-128-ECB (xử lý dữ liệu, KHÔNG chạy exe) — kết quả THẬT:**
```python
dec = AES.new(key, AES.MODE_ECB).decrypt(data[0xdf70:0xdf70+0x19A00])
dec[:4]                                   # -> b'MZ\x90\x00'   (PE hợp lệ!)
e_lfanew = int.from_bytes(dec[0x3c:0x40],'little')   # 0x100
dec[e_lfanew:e_lfanew+4]                  # -> b'PE\x00\x00'
int.from_bytes(dec[e_lfanew+4:e_lfanew+6],'little')  # 0x8664 (x64)
int.from_bytes(dec[e_lfanew+0x16:e_lfanew+0x18],'little')  # Characteristics = 0x2022
```
`Characteristics = 0x2022` chứa bit `0x2000` (**IMAGE_FILE_DLL**) → payload là một **DLL** 64-bit
(dài 104960 byte = `0x19A00`). Đây đúng là thứ stub nạp sau khi giải mã.

**5) Flag trong payload — vị trí THẬT:**
```python
re.search(rb"CSG_FLAG\{[^}]+\}", dec).start()   # -> 0x17408
# -> CSG_FLAG{packer_daisuki}
```
Flag là chuỗi thường tại offset `0x17408` trong DLL đã giải mã. Tương đương
`strings payload.dll | grep CSG`.

**6) Import table TIẾT LỘ cơ chế (THẬT, qua `pefile`):**
```
bcrypt.dll   -> BCryptOpenAlgorithmProvider, BCryptGenerateSymmetricKey, BCryptSetProperty,
                BCryptDecrypt, BCryptGetProperty, BCryptDestroyKey, BCryptCloseAlgorithmProvider
USER32.dll   -> MessageBoxW
KERNEL32.dll -> VirtualAlloc, LoadLibraryA, GetProcAddress, GetProcessHeap, HeapAlloc, ...
```
Đây là bằng chứng mạnh về luồng unpack:
- Packer **không tự cài AES** (nên `objdump` không thấy `aesenc`/T-box) mà gọi **Windows CNG
  (bcrypt)**: `BCryptOpenAlgorithmProvider(AES)` → `BCryptSetProperty(ChainingMode = ECB)` →
  `BCryptGenerateSymmetricKey(key16)` → `BCryptDecrypt(blob)`. Khớp chính xác AES-128-ECB.
- `VirtualAlloc` (cấp vùng nhớ RWX) + `LoadLibraryA`/`GetProcAddress` → sau khi giải mã ra DLL,
  stub **tự nạp phản chiếu** (reflective load) rồi gọi export của payload.
- `MessageBoxW` + Subsystem GUI → chương trình có thể hiện hộp thoại (đánh lạc hướng), flag thì
  nằm trong DLL payload.

**7) Worked example — tự quy đổi RVA 0xF370 → file offset (không cần pefile):** section `.rdata`
có `VirtualAddress = 0xf000`, `PointerToRawData = 0xdc00`. Công thức:
```
offset = RVA - section.VirtualAddress + section.PointerToRawData
       = 0xF370 - 0xf000 + 0xdc00
       = 0x370 + 0xdc00
       = 0xdf70            (khớp đúng pefile.get_offset_from_rva(0xF370))
```
Tương tự, khóa ở file offset `0x27978` → RVA = `0x27978 - 0xdc00 + 0xf000 = 0x29378` → VA (cộng
ImageBase 0x140000000) = `0x140029378`. Hiểu phép này giúp bạn đọc bất kỳ `lea rax,[rip+disp]`
nào trong stub để biết nó trỏ tới blob hay khóa.

**8) Trình tự gọi CNG/bcrypt để giải mã (kiến thức nền, suy từ import):**
```
BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, ...)
BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_ECB)   // chọn ECB
BCryptGenerateSymmetricKey(hAlg, &hKey, ..., key /*16 byte*/, 16, 0)   // nạp khóa 128-bit
BCryptDecrypt(hKey, blob, 0x19A00, ..., out, ...)                      // giải mã ECB
BCryptDestroyKey / BCryptCloseAlgorithmProvider                        // dọn dẹp
```
Vì ECB **không dùng IV**, không có tham số IV nào xuất hiện — khớp với việc ta giải mã tĩnh chỉ
bằng khóa. `BCryptGetProperty(BCRYPT_OBJECT_LENGTH/BLOCK_LENGTH)` là bước phụ để cấp buffer.

**Hướng sai thường gặp:** (a) mở `packed.exe` trong Ghidra rồi lần mò hàm AES tự chế — vô ích vì
nó dùng bcrypt; nhìn **import table** nhanh hơn. (b) Tưởng phải chạy để dump payload từ RAM
(dynamic unpacking) — không cần; blob + khóa đều tĩnh trong `.rdata`. (c) Nhầm RVA 0xF370 là
offset file → đọc sai; phải quy đổi qua section.

**Tổng kết chuỗi lý luận:** `.rdata` chứa (a) blob mã hóa @RVA 0xF370 và (b) khóa AES @RVA
0x29378; stub `.text` gọi **bcrypt** giải mã AES-128-ECB bằng khóa đó, verify `MZ`/`PE\0\0`, rồi
`VirtualAlloc` + reflective-load DLL. Ta tái hiện bước giải mã **tĩnh** → lấy DLL → lấy flag,
**không hề chạy** `packed.exe`.

---

## Bài 9 — R6 — Matryoshka

### (a) Đề bài & metadata
- **Tên:** Matryoshka — **Mã:** R6 — **Category:** reverse / web (PHP) — **Độ khó:** Dễ–Trung bình.
- **Thư mục:** `2025-Cyber-SEA-Game/R6_matryoshka/`
- **File đề:**
  - Lớp ngoài cùng ~**130 MB** (một lệnh `eval(hex2bin("…"))` khổng lồ).
  - `final.php` (147 byte, md5 `46b990affed6c95eabd44905e84ba541`) — lớp trong cùng chứa flag.
- **Flag:** `CSG_FLAG{A_Matryoshka_Obfuscated_Script}`

### (b) Kiến thức nền
- **Matryoshka:** búp bê gỗ Nga lồng nhau — ẩn dụ cho "nhiều lớp lồng nhau".
- **PHP obfuscation bằng `eval` + biến đổi khả nghịch:** Một script PHP có thể "tự giải mã" lớp
  tiếp theo rồi chạy. Các hàm thường dùng (đều **đảo ngược được**):
  - `hex2bin("...")`: đổi chuỗi hex thành chuỗi byte/ASCII. Ngược lại là `bin2hex`.
  - `base64_decode("...")`: giải base64. Ngược lại `base64_encode`.
  - `gzinflate("...")`: giải nén dữ liệu nén bằng **raw DEFLATE**. Ngược lại `gzdeflate`.
    (DEFLATE là thuật toán nén dùng trong gzip/zip.)
  - `eval("<php code>")`: **chạy** chuỗi như mã PHP. Đây là mắt xích nguy hiểm.
- **Vì sao file ngoài cùng 130 MB:** mỗi lớp bọc làm dữ liệu "phình" ra (hex nhân đôi kích
  thước; base64 +33%). Lồng nhiều lớp → kích thước lũy tiến rất lớn ở lớp ngoài.
- **Cách "bóc" AN TOÀN (de-obfuscate tĩnh):** **Không bao giờ** chạy `eval`. Thay vào đó, với
  mỗi lớp, **thay `eval(` bằng `echo`** (hoặc `file_put_contents`) để **in ra** chuỗi lớp kế
  tiếp thay vì thực thi; lặp lại tới lớp cuối. Như vậy chỉ giải mã/giải nén, không chạy mã lạ.

### (c) Trinh sát ban đầu
```bash
head -c 200 outer.php        # thấy: <?php eval(hex2bin("6261736536345f6465636f6465..."))
# giải nhanh một mẩu hex để xem nó là gì:
python3 -c "print(bytes.fromhex('6261736536345f6465636f6465').decode())"  # -> base64_decode
```

### (d) Phân tích từng bước + reasoning "tại sao"
Mẫu lặp khi bóc từng lớp (bảng "từ vựng wrapper"):
```
eval(hex2bin("6261736536345f6465636f6465..."))     # hex2bin -> "base64_decode..."
  -> base64_decode("aGV4MmJpbigiNjc3YTY5...")       # base64  -> "hex2bin(..."
     -> hex2bin("677a696e666c617465286865...")      # hex     -> "gzinflate(hex..."
        -> gzinflate(hex2bin("..."))                # giải nén -> lớp kế
           -> eval(... lớp tiếp theo ...)
```
*Tại sao cứ lặp được?* Vì mỗi lớp chỉ là lớp-kế-tiếp được bọc bởi một chuỗi phép khả nghịch
rồi `eval`. Ta "đảo" đúng các phép đó (hex→, base64→, inflate→) để lộ lớp trong, bỏ `eval`.

### (e) Lời giải / exploit đầy đủ
Script bóc tự động (PHP, thay `eval` bằng `echo`):
```php
<?php
$code = file_get_contents("outer.php");
for ($i = 0; $i < 100; $i++) {                 // bóc tối đa 100 lớp
    // biến eval(...) thành echo(...) để IN RA thay vì CHẠY
    $safe = preg_replace('/\beval\s*\(/', 'echo(', $code, 1);
    ob_start(); eval('?>' . $safe); $out = ob_get_clean();   // chỉ giải mã, không chạy payload
    if (strpos($out, 'CSG_FLAG') !== false || strlen($out) < 500) { echo $out; break; }
    $code = "<?php " . $out;                    // lớp kế tiếp
}
```
*(Có thể làm thủ công bằng CyberChef: From Hex → From Base64 → Raw Inflate, lặp lại.)*

Lớp trong cùng `final.php` (147 byte) — và **cú lừa cuối**:
```php
<?php
$s='print("I have a flag!\n"); /* CSG_FLAG{A_Matryoshka_Obfuscated_Script} */ print("Congrats!!\n");';
$s=substr($s, 0, 27);   // CẮT còn 27 ký tự đầu
eval($s);               // -> chỉ chạy: print("I have a flag!\n")
?>
```
**Phân tích bẫy:** `$s` bị `substr($s, 0, 27)` cắt còn **27 ký tự đầu** = `print("I have a
flag!\n")`. Nên khi `eval`, nó **chỉ in "I have a flag!"** — không hề in flag. Flag thật nằm
trong **comment `/* ... */`** của chuỗi gốc. → Người giải phải **đọc** chuỗi, đừng chỉ chạy.

### (f) Flag & ý nghĩa
```
CSG_FLAG{A_Matryoshka_Obfuscated_Script}
```
"A Matryoshka Obfuscated Script" — mô tả chính xác bài: script bị làm rối kiểu búp bê lồng.

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1 (lớn nhất):** Chạy `final.php` và tin vào output ("I have a flag!") → không có
  flag. Phải đọc comment.
- **Cạm bẫy 2:** Chạy `eval` của lớp ngoài trên máy thật — nguy hiểm (mã lạ). Luôn thay `eval`
  bằng `echo`.
- **Cạm bẫy 3:** File 130 MB có thể làm editor treo; nên xử lý bằng script/stream.
- **Cách khác:** Bóc thủ công bằng CyberChef cho vài lớp đầu để hiểu pattern, rồi tự động hóa.

### (h) Tham khảo
- PHP: `eval`, `hex2bin`, `base64_decode`, `gzinflate`, `substr`.
- CyberChef (From Hex, From Base64, Raw Inflate).
- Khái niệm de-obfuscation an toàn (không thực thi payload).

### (i) Bóc từng lớp obfuscation + phân tích byte-level `final.php`

> ⚠️ **Lưu ý về file:** repo **chỉ có** `final.php` (147 byte) và `README.md`; **file lớp ngoài
> ~130 MB không có trong repo**. Vì vậy phần "bóc từng lớp" dưới đây giải thích **cơ chế từng
> phép biến đổi** (dựa trên README + kiến thức PHP), còn phần `final.php` được phân tích
> **byte-level thật** (file có trên đĩa). Không chạy PHP nào — chỉ giải mã dữ liệu/đếm ký tự.

**1) Giải nghĩa từng hàm wrapper (vì sao đảo ngược được):**
- `hex2bin("4869")` → `"Hi"`: mỗi 2 ký tự hex = 1 byte. Đảo: `bin2hex`. Dùng để che text thành
  chuỗi hex vô nghĩa.
- `base64_decode("SGk=")` → `"Hi"`: 4 ký tự base64 = 3 byte (xem Phụ lục D.4). Đảo: `base64_encode`.
- `gzinflate(...)` → giải nén **raw DEFLATE** (không có header gzip/zlib). Đảo: `gzdeflate`.
  Dùng để **nén** lớp trong cho nhỏ lại (và trông như rác nhị phân).
- `eval("<php>")` → **thực thi** chuỗi như mã PHP. Đây là mắt xích phải vô hiệu hóa khi bóc.

**2) Mẫu một lớp điển hình (từ README) và cách "đảo":**
```
eval(hex2bin("6261736536345f6465636f6465282261...."))
```
Bước đảo bằng tay/CyberChef:
```
From Hex    -> base64_decode("aGV4MmJpbigi....")      (hex2bin: 6261736536345f... = "base64_decode(")
From Base64 -> hex2bin("677a696e666c617465....")
From Hex    -> gzinflate("<nén>")
Raw Inflate -> <mã PHP lớp kế tiếp>
```
Kiểm nhanh một mẩu hex thật: `bytes.fromhex("6261736536345f6465636f6465")` → `b"base64_decode"`;
`bytes.fromhex("677a696e666c617465")` → `b"gzinflate"`. Đây là bằng chứng "từ vựng wrapper".

**3) Script bóc tự động AN TOÀN (thay `eval`→`echo`, không thực thi payload):**
```php
<?php
$code = file_get_contents("outer.php");
for ($i = 0; $i < 200; $i++) {
    // Chỉ IN RA lớp kế tiếp, KHÔNG chạy nó:
    $safe = preg_replace('/\beval\s*\(/', 'print(', $code, 1);
    ob_start(); eval('?>'.$safe); $layer = ob_get_clean();   // eval ở đây chỉ chạy các hàm
    // giải mã (hex2bin/base64_decode/gzinflate) rồi print — KHÔNG chạy mã payload lớp trong
    if (strpos($layer, 'CSG_FLAG') !== false) { echo $layer; break; }
    $code = "<?php ".$layer;
}
```
*(Về mặt an toàn tuyệt đối: nên bóc bằng CyberChef thuần — From Hex / From Base64 / Raw Inflate
lặp lại — để **không** đưa bất kỳ `eval` nào cho PHP engine.)* Kích thước phình to giải thích vì
sao lớp ngoài tới ~130 MB: hex nhân đôi byte (+100%), base64 +33%, lồng nhiều lớp → lũy tiến.

**4) Phân tích byte-level `final.php` (147 byte, THẬT trên đĩa):**
```php
<?php $s='print("I have a flag!\n"); /* CSG_FLAG{A_Matryoshka_Obfuscated_Script} */ print("Congrats!!\n");'; $s=substr($s, 0, 27); eval($s); ?>
```
Đếm chính xác (PHP single-quote: `\n` là **2 ký tự** `\` và `n`, không phải xuống dòng):
```
len($s)              = 96 ký tự
substr($s, 0, 27)    = 'print("I have a flag!\n"); '   (đúng 27 ký tự: câu print 26 + 1 dấu cách)
CSG_FLAG bắt đầu tại = ký tự thứ 30  (NẰM TRONG comment /* ... */)
```
→ `eval($s)` chỉ chạy `print("I have a flag!\n");` (trong **double-quote** `"\n"` mới là xuống
dòng) → in `I have a flag!`. **Flag ở ký tự 30, vượt quá 27, nên bị `substr` cắt mất — không bao
giờ được eval.** Cú lừa: người giải chạy file thấy "I have a flag!" rồi tưởng không có flag; thực
ra flag nằm **trong comment** của chuỗi gốc. Bài học: **đọc dữ liệu, đừng tin output**.

**5) Worked example — bóc 1 lớp bằng số thật:** giả sử lớp là `eval(hex2bin("<H>"))` với `<H>`
bắt đầu `677a696e666c617465286261736536345f6465636f646528...`. Giải tay:
```python
import binascii
binascii.unhexlify("677a696e666c617465286261736536345f6465636f646528")
# -> b'gzinflate(base64_decode('   <- lớp kế là gzinflate(base64_decode(...))
```
→ tiếp: lấy chuỗi base64 bên trong → `base64_decode` → dữ liệu nén → `gzinflate` → mã PHP sâu
hơn. DEFLATE là nén LZ77+Huffman; **"raw"** nghĩa là KHÔNG có header zlib (`78 9c`) hay gzip
(`1f 8b`), nên phải dùng đúng `gzinflate`/`Raw Inflate` (không phải `gzuncompress`/`gzdecode`).

**6) Vì sao đặt tên "Matryoshka":** như búp bê Nga — mỗi lớp mở ra lại lộ lớp nhỏ hơn (`eval` →
decode → `eval` → ... → `final.php`), và "con búp bê trong cùng" lại giấu phần thưởng (flag)
trong chỗ không ai chạy tới (comment).

**Hướng sai thường gặp:** (a) chạy thẳng lớp ngoài bằng `php outer.php` để "xem nó in gì" — cực
nguy hiểm (thực thi mã lạ) và lớp cuối cố tình in "I have a flag!" để đánh lừa; (b) dùng
`gzuncompress` thay `gzinflate` → lỗi vì sai định dạng header; (c) chạy `final.php` rồi tin
output → bỏ lỡ flag trong comment. Luôn **bóc dữ liệu** (CyberChef) thay vì thực thi.

**Dấu hiệu "đã tới lớp cuối":** sau mỗi lần bóc, kích thước giảm mạnh; khi lớp còn lại **không
còn** chứa `eval(`/`hex2bin(`/`gzinflate(` mà xuất hiện code có nghĩa (ở đây là `$s=substr(...)`
và chuỗi chứa `CSG_FLAG`) thì dừng. Mẹo tự động: vòng lặp bóc đến khi `strpos($layer,'CSG_FLAG')`
khác `false`, hoặc khi không còn phép biến đổi khả nghịch nào để đảo. Chính việc mỗi lớp phình
~2.3× (hex ×2, base64 ×1.33, cộng chi phí nén) khi mã hóa giải thích vì sao đi ngược lại thì kích
thước co rất nhanh từ ~130 MB xuống còn 147 byte.

---

## Bài 10 — Saudi Arabia R1 Q1 — Corrupted

### (a) Đề bài & metadata
- **Tên:** Corrupted — **Quốc gia/mã:** Saudi Arabia / R1 Q1 — **Category:** reverse — **Độ khó:** Dễ.
- **Thư mục:** `2025-Cyber-SEA-Game/Saudi_Arabia/R1_Q1/`
- **File đề:** `corrupted.exe` (114698 byte, md5 `01d9f9e15295f86d368fde1e19dfc283`) — một exe "hỏng", không chạy được. Phải **khôi phục** rồi chạy (không tham số) để lấy flag.
- **Flag:** `CSG_FLAG{finding_the_magic_now!}`

### (b) Kiến thức nền
- **Magic bytes:** Vài byte đầu file xác định định dạng ("số thần kỳ"). PE/Windows exe bắt đầu
  bằng `4D 5A` = ASCII `"MZ"` (DOS header). Nếu 2 byte đầu sai, hệ điều hành từ chối chạy.
- **Cấu trúc đầu PE:** Sau `MZ` là phần DOS stub; tại offset `0x3C` có `e_lfanew` (4 byte,
  little-endian) trỏ tới NT header bắt đầu bằng `PE\0\0` (`50 45 00 00`).
- **"Tampered header" (sửa đầu file):** Một cách làm hỏng file đơn giản là **chèn thêm byte
  rác** ở đầu và/hoặc **đổi magic**. Khôi phục = bỏ byte thừa + sửa magic về đúng.
- **`xxd` / hex editor:** Dùng để xem/sửa byte thô. `xxd -l 24 file` in 24 byte đầu dạng hex.
- **Vì sao chỉ cần đọc disassembly, không cần chạy:** Sau khi khôi phục PE, có thể mở trong
  IDA/Ghidra, tìm hàm `main`, đọc format string của `printf` để suy ra flag — **không cần
  thực thi** (an toàn hơn, đúng yêu cầu).

### (c) Trinh sát ban đầu
```bash
file corrupted.exe              # "data" (không nhận ra là PE -> header hỏng)
xxd -l 24 corrupted.exe
# 00000000: 0004 9901 4001 b1a3 0000 5a5a 9000 0300
# 00000010: 0000 0400 0000 ffff
```
*(Đã xác nhận trên file thật.)* So với PE chuẩn, 2 byte đầu phải là `4d 5a` (`MZ`) nhưng ở đây
là `00 04`; và thấy `5a 5a` (`ZZ`) xuất hiện ở offset 10.

### (d) Phân tích từng bước + reasoning "tại sao"
So sánh byte đầu "hỏng" vs "chuẩn":
```
corrupted: 00 04 99 01 40 01 b1 a3 00 00 | 5a 5a 90 00 03 00 00 00 04 00 ...
                  (10 byte rác)             ZZ ...
restored :                                   4d 5a 90 00 03 00 00 00 04 00 ...  -> "MZ"
```
Hai lỗi:
1. **Thừa 10 byte rác ở đầu** (`00 04 99 01 40 01 b1 a3 00 00`). Bỏ 10 byte này → byte kế là
   `5a 5a` (`ZZ`).
2. **Magic sai:** cần `4d 5a` (`MZ`) nhưng đang là `5a 5a` (`ZZ`). → Sửa byte đầu `5a`→`4d`
   (ép về `'M'`). Byte thứ hai đã sẵn là `5a` (`Z`). → Thành `MZ`.

*Tại sao 10 byte và tại sao chỉ sửa 1 byte?* Vì sau khi bỏ 10 byte, phần còn lại khớp hoàn
toàn cấu trúc PE **trừ** byte đầu (`Z` thay vì `M`). Sửa đúng 1 byte đó là đủ.

### (e) Lời giải / exploit đầy đủ
`fix_corrupted.py` — chỉ làm "phẫu thuật byte", **không chạy** exe:
```python
data = open("corrupted.exe","rb").read()
data = data[10:]            # 1) bỏ 10 byte rác đầu  -> "ZZ..."
data = b"M" + data[1:]      # 2) ép byte đầu về 'M'   -> "MZ..."
open("restored.exe","wb").write(data)
```
**Kiểm chứng (đã chạy — chỉ đọc/ghi byte, không thực thi):**
```
restored first 16 bytes: 4d5a90000300000004000000ffff0000   -> "MZ..."
e_lfanew = 0x100   sig = b'PE\x00\x00'                         -> PE hợp lệ
```
Sau khi có `restored.exe`, đọc disassembly hàm `main` thấy flag được ráp từ format string:
```c
printf("CSG_FLAG{%sing_%s_%s_%s!}\n", "find", "the", "magic", "now");
```
`%sing` với `"find"` → `find` + `ing` = `finding`. Ghép các tham số:
`finding_the_magic_now!`.

### (f) Flag & ý nghĩa
```
CSG_FLAG{finding_the_magic_now!}
```
"Finding the magic now" — chơi chữ với **magic bytes** (điều ta vừa phải sửa). Rất khớp chủ đề.

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1:** Chỉ sửa magic mà quên bỏ 10 byte rác (hoặc ngược lại) → vẫn hỏng.
- **Cạm bẫy 2:** Giả định sai số byte rác. Cách chắc ăn: tìm chuỗi `MZ...` quen thuộc hoặc so
  với một PE chuẩn để căn.
- **Cạm bẫy 3:** Chạy `restored.exe` để lấy flag — không sai, nhưng đọc disassembly an toàn hơn
  và vẫn ra flag (đúng tinh thần "không execute binary tải về").
- **Cách khác:** Mở bằng hex editor (HxD/010 Editor), sửa tay rồi load vào Ghidra.

### (h) Tham khảo
- Cấu trúc PE (DOS header `MZ`, `e_lfanew`, `PE\0\0`).
- `xxd`, hex editor; Ghidra/IDA đọc `main`.

### (i) Dịch ngược tĩnh THẬT (byte-level PE + objdump)

Phần này phân tích **thật** trên file, bằng `xxd` + `python pefile` + `objdump -d` (không
chạy exe). Môi trường không có capstone/radare2, nên dùng bộ GNU binutils (objdump/readelf/nm).

**1) Vì sao file "không nhận ra".** Chạy `file corrupted.exe` cho ra:
```
Saudi_Arabia/R1_Q1/corrupted.exe: TTComp archive data, binary, 1K dictionary
```
`file` đoán nhầm vì 2 byte đầu không phải `MZ`; nó khớp một chữ ký định dạng khác một cách
ngẫu nhiên → bằng chứng header đã hỏng.

**2) Mổ 32 byte đầu của file hỏng (`xxd -l 32`):**
```
00000000: 0004 9901 4001 b1a3 0000 5a5a 9000 0300   ....@.....ZZ....
00000010: 0000 0400 0000 ffff 0000 b800 0000 0000   ................
```
Phân tích từng vùng:
- Byte `0x00..0x09` = `00 04 99 01 40 01 b1 a3 00 00` → **10 byte rác chèn thêm** (không thuộc
  cấu trúc PE).
- Byte `0x0A..0x0B` = `5a 5a` = ASCII `"ZZ"` → đây *đáng lẽ* là magic `MZ` nhưng byte đầu bị
  đổi `4d`→`5a` (M→Z).
- Byte `0x0C..` = `90 00 03 00 00 00 04 00 00 00 ff ff ...` → khớp y hệt phần `e_cblp, e_cp,
  e_crlc...` của một DOS header chuẩn. Củng cố: chỉ sai 10 byte đầu + 1 byte magic.

**3) Phẫu thuật (data-only, KHÔNG exec):**
```python
d = open("corrupted.exe","rb").read()
r = d[10:]            # bỏ 10 byte rác  -> bắt đầu "ZZ.."
r = b"M" + r[1:]      # ép byte 0: 0x5A -> 0x4D ('Z'->'M')  -> "MZ.."
open("restored.bin","wb").write(r)
```
`xxd -l 64 restored.bin` (đã chạy thật):
```
00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000   MZ..............
00000010: b800 0000 0000 0000 4000 0000 0000 0000   ........@.......
00000030: 0000 0000 0000 0000 0000 0000 0001 0000   ................
```
Chú ý **offset 0x3C** = `00 01 00 00` (little-endian) → `e_lfanew = 0x00000100`. Đây là trường
cuối của DOS header, trỏ tới NT header.

**4) Kiểm bằng `pefile` (đọc, không chạy) — kết quả THẬT:**
```
Machine:    0x14c   -> IMAGE_FILE_MACHINE_I386  (PE32, 32-bit)
e_lfanew:   0x100
Signature:  0x4550  -> b"PE\0\0"  (0x50 0x45 ...)
Subsystem:  3       -> IMAGE_SUBSYSTEM_WINDOWS_CUI (console)
EntryPoint: 0x160f  (RVA)         ImageBase: 0x400000
Sections:
  .text   VA 0x1000  VSize 0x12c5e  RawPtr 0x400    RawSz 0x12e00
  .rdata  VA 0x14000 VSize 0x6f9c   RawPtr 0x13200  RawSz 0x7000
  .data   VA 0x1b000 VSize 0x14dc   RawPtr 0x1a200  RawSz 0xc00
  .reloc  VA 0x1d000 VSize 0x1004   RawPtr 0x1ae00  RawSz 0x1200
```
→ PE32 console hợp lệ. (Giải thích trường: `Machine` = kiến trúc CPU; `Subsystem` = loại giao
diện; `Section` = các vùng `.text` mã, `.rdata` chuỗi hằng, `.data` biến, `.reloc` relocation.)

**5) `objdump -d -M intel restored.exe` — disassembly THẬT của `main`.** Đoạn ráp flag:
```asm
4012a6:  push 0x4141c8        ; -> "now"
4012ab:  push 0x4141c0        ; -> "magic"
4012b0:  push 0x414214        ; -> "the"
4012b5:  push 0x414198        ; -> "find"
4012ba:  push 0x41b03c        ; -> "CSG_FLAG{%sing_%s_%s_%s!}\n"
         call printf
```
Mình đã **đọc đúng nội dung** tại từng địa chỉ (đổi VA→file offset qua section):
```
0x414198 -> b'find'        0x414214 -> b'the'
0x4141c0 -> b'magic'       0x4141c8 -> b'now'
0x41b03c -> b'CSG_FLAG{%sing_%s_%s_%s!}\n'
```
Vì C đẩy tham số lên stack **theo thứ tự ngược** (phải→trái), thứ tự thật khi in là
`printf(fmt, "find", "the", "magic", "now")`. Với `%sing` + `"find"` → `finding`. Ghép:
`finding_the_magic_now!`.

**6) Phát hiện thêm từ `strings restored.exe` (THẬT):** chương trình này **còn là một flag
encoder**:
```
CSG_FLAG{%sing_%s_%s_%s!}
Usage: %s <flag>
This program is also used to generate the flag for the next challenge Flag Encoder.
Obfuscated: %s
7qrnsZ6fJuTHe4Ia
```
→ Chạy **không tham số** = in flag; chạy **có tham số** = "mã hóa" flag cho bài sau. Chuỗi
`7qrnsZ6fJuTHe4Ia` có thể là khóa/seed của bộ encoder. (Writeup gốc không nhắc chi tiết encoder
này — bổ sung.) Ta **không chạy** exe; mọi kết luận suy ra từ disassembly + strings.

**7) Import table (THẬT, qua `pefile`) — xác nhận chỉ là console app thường:**
```
KERNEL32.dll -> UnhandledExceptionFilter, SetUnhandledExceptionFilter, GetCurrentProcess,
                TerminateProcess, IsDebuggerPresent, GetStartupInfoW, GetModuleHandleW,
                WriteConsoleW, QueryPerformanceCounter, InitializeSListHead, ...
```
Không có import crypto/network → đây là chương trình MSVC console đơn thuần; `WriteConsoleW` là
đường ra của `printf`/`puts`. (Có `IsDebuggerPresent` — chỉ là boilerplate của CRT, không phải
anti-debug thực sự ở đây.)

**8) Về section `.reloc`:** vì PE32 có `ImageBase 0x400000` cố định và các `push 0x4141xx` là địa
chỉ tuyệt đối, cần bảng relocation để loader sửa địa chỉ nếu ảnh được nạp ở base khác (ASLR).
Điều này không ảnh hưởng tới việc đọc tĩnh — ta tính VA theo ImageBase mặc định 0x400000.

**Hướng sai thường gặp:** (a) chỉ sửa magic mà quên bỏ 10 byte rác (hoặc ngược lại) → vẫn hỏng;
(b) đoán sai số byte rác — cách chắc ăn là so cấu trúc DOS header chuẩn (các byte `90 00 03 00
00 00 04 00` rất đặc trưng) để căn; (c) tìm `strings | grep CSG` ra ngay
`CSG_FLAG{%sing_%s_%s_%s!}` nhưng **dừng lại** mà không nối `find+ing` → đưa ra flag sai thiếu
chữ; phải đọc disassembly để biết 4 tham số và quy tắc `%sing`.

---

## Bài 11 — Sweden R3 — Fake C2

### (a) Đề bài & metadata
- **Tên:** Fake C2 — **Quốc gia/mã:** Sweden / R3 — **Category:** reverse (Go) — **Độ khó:** Dễ–Trung bình.
- **Thư mục:** `2025-Cyber-SEA-Game/Sweeden_R3_FakeC2/`
- **File đề:** `fakeC2.exe` — binary viết bằng **Go**, mô phỏng đơn giản một "implant" (mã cấy) giao tiếp với server C2. Mô tả: phân tích file và trích flag.
- **Flag:** `CSG_FLAG{go_rev_startingpoint}` *(đã chạy RC4 trong `solve.py` kiểm chứng.)*

### (b) Kiến thức nền
- **C2 (Command and Control):** Hạ tầng kẻ tấn công dùng để điều khiển máy nạn nhân. "Implant"
  là phần mềm cấy trên máy nạn nhân, nhận lệnh từ C2 và trả kết quả. "Fake C2" = bản mô phỏng
  đơn giản cho mục đích học.
- **Go binary & cách nhận diện:** Go biên dịch tĩnh, binary khá lớn, và **giữ lại tên symbol**
  rất đặc trưng dạng `package.Function` (ví dụ `main.main`, `main.startServer`,
  `main.startServer.func2` cho closure/anonymous function). Khi dịch ngược (Ghidra/IDA), ta
  thấy ngay các tên này → rất dễ lần ra logic. Go cũng lưu nhiều **chuỗi** trong một vùng liền
  nhau (có thể dùng `strings` + công cụ chuyên như `GoReSym`/`redress` để khôi phục symbol).
- **Biến global trong Go:** Dữ liệu như khóa và ciphertext thường là **global** (`main.expectedKey`,
  `main.flag`), nằm trong section dữ liệu — đọc được bằng cách xem cross-reference tới nơi hàm
  giải mã dùng chúng.
- **RC4 (nhắc lại):** mã dòng. KSA xáo mảng S theo khóa, PRGA sinh keystream, rồi XOR. Mã hóa =
  giải mã. Chỉ cần **khóa** + **ciphertext** là giải được — **không cần chạy binary**.
- **JSON:** Định dạng dữ liệu text `{"key": value}`. Ở đây plaintext sau giải mã là JSON chứa
  flag.

### (c) Trinh sát ban đầu
```bash
file fakeC2.exe                    # PE, Go build (hoặc ELF nếu Linux)
strings fakeC2.exe | grep -iE "main\.|decryptkey|RC4|/check|/post"
# Mở Ghidra: tìm main.main -> main.startServer, main.runClient
```
Luồng chương trình:
- `main.main` → gọi `main.startServer` (đăng ký route `/check`, `/post`) rồi `main.runClient`.
- Client: GET `http://127.0.0.1:5555/check`, hỏi key giải mã, POST JSON
  `{"decryptkey": <key>}` tới `/post`, in phản hồi.

### (d) Phân tích từng bước + reasoning "tại sao"
1. **Handler `/post`** (`main.startServer.func2`): đọc JSON, lấy `decryptkey`, so với global
   `main.expectedKey`. Nếu khớp → **RC4-decrypt** buffer ciphertext nhúng (`main.flag`) rồi trả
   plaintext; sai thì trả lỗi.
2. **Trích 2 thứ từ binary** (vì Go để lộ symbol):
   - `main.expectedKey` = `"RC4JsonMarshalLocalC2"` (khóa RC4).
   - `main.flag` = buffer **73 byte** ciphertext.
3. **Không cần chạy server/client.** *Tại sao?* Vì ta đã có khóa + ciphertext; tự RC4-decrypt
   là xong, tránh chạy binary (an toàn).

### (e) Lời giải / exploit đầy đủ
`solve.py` — RC4 thuần Python, **không chạy** `fakeC2.exe`:
```python
KEY = b"RC4JsonMarshalLocalC2"                  # main.expectedKey
CT  = bytes([0x03,0x7a,0x4f,0x22,0xe6,0xc8,0x8b,0x3a, ...])  # main.flag (73 byte)

def rc4(data, key):
    S = list(range(256)); j = 0
    for i in range(256):                         # KSA: xáo mảng S theo khóa
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:                               # PRGA: sinh keystream & XOR
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

print(rc4(CT, KEY).decode(errors="ignore"))
```

**Output thực tế (đã chạy):**
```json
{"tasks":[{"task":"print_flag","flag":"CSG_FLAG{go_rev_startingpoint}"}]}
```
→ plaintext là JSON; trường `flag` chứa flag.

### (f) Flag & ý nghĩa
```
CSG_FLAG{go_rev_startingpoint}
```
"go rev starting point" — điểm khởi đầu cho ai mới học **dịch ngược binary Go** (chơi chữ với
ngôn ngữ Go). Bài này cố tình "dễ thở" để làm quen Go reversing.

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1:** Cố chạy client rồi nhập key — mất thời gian; chỉ cần RC4 tĩnh.
- **Cạm bẫy 2:** Nhầm RC4 là cần khóa khác cho giải mã — không, mã hóa = giải mã.
- **Cạm bẫy 3:** Go binary lớn, nhiều hàm runtime; tập trung vào `main.*` thôi.
- **Cách khác:** Dùng `GoReSym`/`redress` khôi phục symbol nếu đã bị strip; hoặc đặt breakpoint
  tại hàm RC4 trong debugger để dump plaintext (dynamic, kém an toàn hơn).

### (h) Tham khảo
- RC4 (KSA/PRGA).
- Go reverse engineering: GoReSym, redress, nhận diện `pclntab`.
- Ghidra/IDA cho Go binaries.

### (i) Dịch ngược tĩnh sâu (Go binary + RC4 từng bước + solver từng dòng)

> ⚠️ **Lưu ý về file:** trong repo **không có** binary `fakeC2.exe` — thư mục chỉ gồm
> `description.txt`, `README.md`, `solve.py`. Vì vậy phần này **không chạy `objdump` trực tiếp
> trên binary** (không có để chạy), mà: (1) giải thích cách nhận diện/đọc Go binary nếu có,
> (2) phân tích `solve.py` **từng dòng** (chạy được, chỉ xử lý dữ liệu), (3) tái lập RC4 tay.
> Các giá trị `main.expectedKey` và `main.flag` lấy từ writeup gốc + solve.py.

**1) Nhận diện một Go binary (nếu có file).** Dấu hiệu khi dùng `strings`/`objdump`/`nm`:
- **Chuỗi runtime đặc trưng:** `go:buildid`, `runtime.`, `Go build ID: "..."`, đường dẫn build
  như `/usr/local/go/src/...`, tên package `main.`.
- **`.gopclntab` (Go PC-line table):** section/bảng ánh xạ địa chỉ→tên hàm. Magic 4 byte đầu:
  `fb ff ff ff` (Go ≤1.15) hoặc `f0 ff ff ff`/`f1 ff ff ff` (các bản mới). Công cụ `GoReSym`
  đọc bảng này để **khôi phục tên hàm** `main.main`, `main.startServer`, `main.runClient`,
  closure `main.startServer.func2`...
- **Lệnh gợi ý:** `objdump -s -j .gopclntab fakeC2 | head` (xem magic), `nm fakeC2 | grep main`.
- Go binary **lớn** (vài MB) vì link tĩnh toàn bộ runtime + GC.

**2) Luồng chương trình (đọc từ các hàm `main.*`):**
- `main.main` → gọi `main.startServer` (đăng ký handler HTTP `/check`, `/post`) rồi `main.runClient`.
- `main.runClient`: GET `http://127.0.0.1:5555/check`, hỏi key, POST JSON `{"decryptkey": key}` → `/post`.
- `main.startServer.func2` (handler `/post`): `json.Unmarshal` body, lấy `decryptkey`, so với
  global `main.expectedKey`. Khớp → RC4-decrypt global `main.flag` (73 byte) → trả plaintext.

**3) Hai global cần trích (từ section dữ liệu):**
```
main.expectedKey = "RC4JsonMarshalLocalC2"      (21 ký tự)
main.flag        = 73 byte ciphertext (bắt đầu 0x03,0x7a,0x4f,0x22,...)
```
Trong Ghidra ta tìm cross-reference tới hàm RC4 để xác định hai buffer này; chuỗi
`RC4JsonMarshalLocalC2` thường tách rời trong "string blob" của Go (các chuỗi nối liền nhau,
ranh giới do độ dài quy định trong `string` header, không có NUL kết thúc như C).

**4) RC4 chạy tay 2 bước KSA** (khóa `"RC4JsonMarshalLocalC2"`, `'R'=0x52=82`, `'C'=67`):
```
S = [0,1,...,255]
i=0: j = (0 + S[0] + 82) & 255 = 82      -> swap S[0]<->S[82]   (S[0]=82)
i=1: j = (82 + S[1] + 67) & 255 = 150    -> swap S[1]<->S[150]
...  256 bước, thu được mảng S đã xáo
```
PRGA sau đó sinh keystream `k`, lấy `plaintext = ciphertext XOR k`. Vì RC4 đối xứng, cùng khóa
→ cùng keystream → cùng hàm giải mã (xem Phụ lục D.3).

**5) `solve.py` — đọc TỪNG DÒNG:**
```python
KEY = b"RC4JsonMarshalLocalC2"          # main.expectedKey (byte)
CT  = bytes([0x03,0x7a,0x4f,0x22, ...]) # main.flag, 73 byte ciphertext

def rc4(data, key):
    S = list(range(256)); j = 0         # [KSA] khởi tạo S = 0..255
    for i in range(256):                # lặp 256 lần xáo S theo khóa
        j = (j + S[i] + key[i % len(key)]) & 0xFF   # cộng dồn, khóa lặp vòng
        S[i], S[j] = S[j], S[i]         # hoán đổi 2 phần tử
    i = j = 0; out = bytearray()        # [PRGA] reset con trỏ
    for b in data:                      # duyệt từng byte ciphertext
        i = (i + 1) & 0xFF              # i tiến 1
        j = (j + S[i]) & 0xFF           # j cộng S[i]
        S[i], S[j] = S[j], S[i]         # hoán đổi
        k = S[(S[i] + S[j]) & 0xFF]     # lấy 1 byte keystream
        out.append(b ^ k)              # XOR -> plaintext byte
    return bytes(out)

print(rc4(CT, KEY).decode(errors="ignore"))
```

**6) Output THẬT (đã chạy `solve.py`):**
```json
{"tasks":[{"task":"print_flag","flag":"CSG_FLAG{go_rev_startingpoint}"}]}
```
Plaintext là JSON (đúng kiểu phản hồi của một server Go dùng `json.Marshal` — khớp tên khóa
`RC4JsonMarshalLocalC2`). Trường `flag` chứa flag. Toàn bộ làm được **không cần binary**: chỉ
cần khóa + ciphertext (đã có trong solve.py/README).

**7) Vì sao đọc Go binary "khó chịu" hơn C (kiến thức nền):**
- **Chuỗi không có NUL kết thúc:** Go lưu `string` dưới dạng struct `{ptr, len}` (con trỏ + độ
  dài). Trong binary, các chuỗi nối liền thành một "blob" khổng lồ; `strings` sẽ in dính nhau
  (ví dụ `...RC4JsonMarshalLocalC2expectedKeyinvalid...`). Ranh giới thật do `len` quyết định,
  nên muốn tách đúng `expectedKey` = `"RC4JsonMarshalLocalC2"` (21 ký tự) phải xem nơi code nạp
  cặp `(ptr, 21)`.
- **Quy ước gọi hàm:** Go (từ 1.17) truyền tham số qua **thanh ghi** rồi tràn ra stack, khác ABI
  C — khiến disassembly khó đọc nếu không có công cụ nhận diện.
- **Nhiều hàm runtime/GC:** binary đầy `runtime.*`, `morestack`, GC... → phải lọc lấy `main.*`.
- Công cụ cứu trợ: **GoReSym** (khôi phục tên hàm + hằng), hoặc Ghidra script `golang_renamer`.

**Hướng sai thường gặp:** (a) cố chạy client rồi "nhập key" — mất thời gian, và nếu máy không mở
cổng 5555 thì tắc; chỉ cần RC4 tĩnh. (b) Tưởng RC4 cần "khóa giải mã" khác khóa mã hóa — sai,
RC4 đối xứng. (c) Đọc nhầm độ dài ciphertext (phải đúng **73 byte**) → thừa/thiếu byte làm JSON
hỏng. (d) Dừng ở chuỗi `expectedKey` mà tưởng đó là flag — nó chỉ là **khóa**; flag nằm trong
`main.flag` sau khi RC4-decrypt.

---

## Bài 12 — Switzerland N4 — Betrayer

### (a) Đề bài & metadata
- **Tên:** Betrayer (kẻ phản bội) — **Quốc gia/mã:** Switzerland / N4 — **Category:** forensics / network — **Độ khó:** Khó.
- **Thư mục:** `2025-Cyber-SEA-Game/Switzerland_N4_betrayer/`
- **File đề:** `betrayer.pcap` (34386 byte, md5 `d56dbbe52534fa3c26c4b90dc820c130`). (Tải gốc: `N4_betrayer.zip`, mật khẩu giải nén `csg2025`.)
- **Dạng flag:** `CSG_FLAG{<user>::<domain>:<16 hex>:<32 hex>:<620 hex>}`
- **Flag:** (đầy đủ ở mục f).

### (b) Kiến thức nền
- **Bối cảnh:** Nghi "nội gián" trên `192.168.56.104`; credential có thể bị lộ từ
  `192.168.56.33`. Nhiệm vụ: phân tích pcap, xác định kiểu tấn công, khôi phục credential.
- **LLMNR/NBT-NS poisoning:** Khi một máy Windows không phân giải được tên qua DNS, nó phát
  **broadcast** hỏi qua LLMNR hoặc NBT-NS (NetBIOS Name Service). Kẻ tấn công trong cùng mạng
  **trả lời giả** ("máy đó là tao"), khiến nạn nhân kết nối tới mình và **gửi chứng thực** —
  công cụ kinh điển là **Responder**. Dấu hiệu trong pcap: traffic **NBNS/NetBIOS** rồi
  **SMB** kèm **NTLMSSP**.
- **NTLM / NTLMSSP (3 bản tin):** NTLM là giao thức chứng thực thách-đáp của Windows. NTLMSSP
  là "khung" mang nó, gồm 3 loại bản tin:
  - **Type 1 (NEGOTIATE):** client đề nghị.
  - **Type 2 (CHALLENGE):** server gửi về một **server challenge** 8 byte ngẫu nhiên.
  - **Type 3 (AUTHENTICATE):** client gửi **NTLMv2 response** (bằng chứng biết mật khẩu), kèm
    user/domain/workstation.
- **NTLMv2 response & cách tách:** NTLMv2 response = **NTProofStr (16 byte đầu)** + **blob
  (phần còn lại)**. Blob chứa timestamp, client challenge, target info… Để crack offline cần:
  `username`, `domain`, `server challenge`, `NTProofStr`, `blob`.
- **Định dạng hashcat `-m 5600` (NetNTLMv2):**
  `user::DOMAIN:serverchallenge:NTProofStr:blob` — **đúng khớp** với dạng flag của bài! Nên
  "flag" thực chất là một hash NetNTLMv2 có thể đưa vào hashcat để crack mật khẩu của `bob`.
- **tshark:** phiên bản CLI của Wireshark; rút trường bằng `-T fields -e <field>`.

### (c) Trinh sát ban đầu
```bash
# Mở trong Wireshark, Statistics > Protocol Hierarchy -> thấy NBNS, SMB2, NTLMSSP
strings betrayer.pcap | grep -iE "windomain|cifs|dcc"
# -> WINDOMAIN, WINDOMAIN.LOCAL, host "dcc02" (domain controller)
```
*(Đã xác nhận bằng `strings`: có `WINDOMAIN`, `WINDOMAIN.LOCAL`, `dcc02`.)* Trình tự
NBNS → SMB + NTLMSSP = chữ ký điển hình của **thu NTLMv2 qua poisoning/relay**.

### (d) Phân tích từng bước + reasoning "tại sao"
1. **Nhận diện tấn công:** NBNS/NetBIOS rồi SMB-NTLMSSP → NTLMv2 credential capture. *Tại sao
   khớp dạng flag?* Vì dạng flag `<user>::<domain>:<16hex>:<32hex>:<620hex>` chính là các
   trường NetNTLMv2.
2. **Lấy server challenge (Type 2):** 16 hex (8 byte).
3. **Lấy user, domain, NTLMv2 response (Type 3).**
4. **Tách NTLMv2 response:** 32 hex đầu = NTProofStr; phần còn lại (620 hex) = blob.

### (e) Lời giải / exploit đầy đủ
Rút nhanh bằng tshark:
```bash
# Server challenge (Type 2)
tshark -r betrayer.pcap -Y "ntlmssp.ntlmserverchallenge" \
       -T fields -e ntlmssp.ntlmserverchallenge | head -n1
# -> 46f422cd882b169d

# User, domain, NTLMv2 response (Type 3)
tshark -r betrayer.pcap \
       -Y "ntlmssp.auth.username && ntlmssp.auth.ntresponse" \
       -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain \
       -e ntlmssp.auth.ntresponse
# -> bob   WINDOMAIN   4837e8d2...(652 hex)
```
Sau đó tách: `ntresponse[0:32]` = NTProofStr (32 hex), `ntresponse[32:]` = blob (620 hex).

Repo kèm `analyze_pcap.py` (dùng **scapy**) tự động hóa hoàn toàn: duyệt gói, tìm chữ ký
`NTLMSSP\x00`, đọc MessageType ở offset +8; với **Type 2** lấy server challenge (byte 24–32);
với **Type 3** đọc các trường theo offset chuẩn (Domain @28, User @36, Workstation @44, NT
response @20) rồi in ra flag + dòng hashcat `-m 5600`. Lõi parse (rút gọn):
```python
sig = b"NTLMSSP\x00"
i = payload.find(sig)
mtype = int.from_bytes(payload[i+8:i+12], "little")
if mtype == 2:
    server_challenge = payload[i+24:i+32].hex()          # 8 byte
elif mtype == 3:
    def field(off):                                       # (len, maxlen, offset)
        flen = int.from_bytes(payload[i+off:i+off+2], "little")
        foff = int.from_bytes(payload[i+off+4:i+off+8], "little")
        return payload[i+foff:i+foff+flen]
    user   = field(36).decode("utf-16le")
    domain = field(28).decode("utf-16le")
    ntresp = field(20).hex()
    ntproof, blob = ntresp[:32], ntresp[32:]
```

**Giá trị khôi phục:**
- User / domain: `bob` / `WINDOMAIN`
- Server challenge: `46f422cd882b169d` (16 hex)
- NTProofStr: `4837e8d20080f19cc2762798c9373a8e` (32 hex)
- Blob: `0101000000000000934f159ee807dc01...0000000000` (620 hex)

Có thể đưa vào hashcat để crack mật khẩu của `bob`:
```bash
hashcat -m 5600 'BOB::WINDOMAIN:46f422cd882b169d:4837e8d2...:0101...' rockyou.txt
```

### (f) Flag & ý nghĩa
```
CSG_FLAG{bob::WINDOMAIN:46f422cd882b169d:4837e8d20080f19cc2762798c9373a8e:0101000000000000934f159ee807dc01c70a33e89710d3140000000002001200570049004e0044004f004d00410049004e0001000e00570049004e00310030002d00320004001e00770069006e0064006f006d00610069006e002e006c006f00630061006c0003002e00770069006e00310030002d0032002e00770069006e0064006f006d00610069006e002e006c006f00630061006c0005001e00770069006e0064006f006d00610069006e002e006c006f00630061006c0007000800934f159ee807dc0106000400020000000800300030000000000000000000000000200000d680c970ffd7be19f29a3b7d61c7d3353ee63fdfa4fd83344a83f7681a6b65980a001000000000000000000000000000000000000900140063006900660073002f00640063006300300032000000000000000000}
```
"Kẻ phản bội" = `WINDOMAIN\bob`, người bị thu NTLMv2 credential qua NBNS/SMB. (Chuỗi hex giải
mã ra chứa target info như `WINDOMAIN`, `win10-2.windomain.local`, `cifs/dcc02` — khớp
`strings`.)

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1:** Nhầm độ dài: NTProofStr là **32 hex** (16 byte), blob là phần **còn lại** của
  `ntresponse`, không phải lấy từ field khác.
- **Cạm bẫy 2:** Dùng nhầm LM response (field @12) thay vì NT response (field @20).
- **Cạm bẫy 3:** Có nhiều gói NTLMSSP; phải ghép **đúng cặp** Type 2 + Type 3 của cùng phiên.
- **Cách khác:** Wireshark GUI → lọc `ntlmssp`, xem trường trực tiếp; hoặc dùng `pcredz` để tự
  rút NetNTLMv2 từ pcap.

### (h) Tham khảo
- MS-NLMP (NTLM protocol), NetNTLMv2 format.
- hashcat mode 5600; công cụ Responder, pcredz.
- Wireshark/tshark NTLMSSP fields.

---

## Bài 13 — Tanzania S3

### (a) Đề bài & metadata
- **Tên:** S3 — **Quốc gia/mã:** Tanzania / S3 — **Category:** forensics / stego — **Độ khó:** Dễ–Trung bình.
- **Thư mục:** `2025-Cyber-SEA-Game/Tanza_S3/`
- **File đề:** `S3.jpg` (155076 byte, md5 `49eba91dabfe6a77727415320636186f`) — ảnh JPEG trông bình thường nhưng giấu dữ liệu.
- **Flag:** `CSG_FLAG{Y0u-Are-Found-Hidd3n-Fi1e}`

### (b) Kiến thức nền
- **JPEG + ZIP nối đuôi:** (như bài DR Congo) JPEG kết thúc ở `FF D9`; byte sau đó bị bỏ qua.
  Kẻ giấu tin dán ZIP (`PK\x03\x04`) vào đuôi ảnh. Carve = tìm chữ ký ZIP rồi lưu phần đuôi.
- **EXIF & metadata ảnh:** JPEG có thể chứa metadata (EXIF, comment, XMP). `strings`/`exiftool`
  giúp lộ các "token" ẩn mà tác giả nhét vào (ví dụ các mảnh mật khẩu `P1`, `P2`, `P3`).
- **ZIP mã hóa AES-256 vs ZipCrypto:** ZIP cổ điển dùng "ZipCrypto" (yếu). ZIP hiện đại (WinZip/
  7-Zip) hỗ trợ **AES-256** mạnh hơn. Khác biệt quan trọng: `unzip` truyền thống **không** giải
  được AES ZIP → phải dùng **7-Zip** (hoặc thư viện `pyzipper`).
- **Mật khẩu ghép từ nhiều mảnh:** token `P1/P2/P3` được ghép (viết hoa, nối bằng dấu `-`) thành
  mật khẩu — kiểu "chia mật khẩu thành nhiều phần".

### (c) Trinh sát ban đầu
```bash
file S3.jpg                               # JPEG image data
binwalk S3.jpg                            # phát hiện Zip archive ở đuôi
strings -n 4 S3.jpg | grep -iE "P1|P2|P3|WATPHO|BUDDHA|pass"   # tìm token mật khẩu
exiftool S3.jpg                           # xem EXIF/comment
```
Từ các token tìm được, ghép (viết hoa, nối `-`) ra mật khẩu `WATPHO-RECLINING-BUDDHA`
(Wat Pho — chùa "Phật nằm" nổi tiếng ở Bangkok).

### (d) Phân tích từng bước + reasoning "tại sao"
1. **Tìm hint mật khẩu** qua `strings`/EXIF: tokens `P1`, `P2`, `P3`. *Tại sao chia 3?* Để
   người chơi phải gom đủ 3 mảnh rồi ghép.
2. **Carve ZIP từ JPEG:** tìm `PK\x03\x04`, lưu từ đó tới hết file thành `.zip`.
3. **Giải nén ZIP (AES-256):** `unzip` thường **không** làm được AES → dùng **7-Zip** với mật
   khẩu ghép ở trên.
4. **Đọc `flag.txt`** bên trong.

### (e) Lời giải / exploit đầy đủ
`solve.py`:
```python
from pathlib import Path
import subprocess, shutil

PASSWORD = b"WATPHO-RECLINING-BUDDHA"

# 1) carve ZIP khỏi JPEG
data = Path("S3.jpg").read_bytes()
idx  = data.find(b"PK\x03\x04")                 # tìm đầu ZIP
Path("embedded.zip").write_bytes(data[idx:])    # lưu phần đuôi

# 2) giải nén bằng 7-Zip (vì ZIP dùng AES-256)
sevenz = shutil.which("7z") or shutil.which("7z.exe")
subprocess.check_call([sevenz, "x", "-y", f"-p{PASSWORD.decode()}",
                       "embedded.zip", "-o."])

# 3) đọc flag
print(Path("flag.txt").read_text().strip())
```
*(Thay cho 7-Zip, có thể dùng `pyzipper` đọc AES ZIP trong thuần Python.)*

### (f) Flag & ý nghĩa
```
CSG_FLAG{Y0u-Are-Found-Hidd3n-Fi1e}
```
"You Are Found Hidden File" — bạn đã tìm ra file ẩn. Mật khẩu `WATPHO-RECLINING-BUDDHA` gắn
chủ đề văn hóa Đông Nam Á (Thái Lan).

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1:** Dùng `unzip` cho AES ZIP → báo "unsupported compression/encryption". Phải dùng
  7-Zip/pyzipper.
- **Cạm bẫy 2:** Bỏ sót một trong các token `P1/P2/P3` → sai mật khẩu.
- **Cạm bẫy 3:** Carve sai (lấy nhầm offset) → ZIP hỏng. Dùng đúng `PK\x03\x04` đầu tiên.
- **Cách khác:** `binwalk -e` tự trích; `foremost` carve file; `exiftool` đọc comment/XMP.

### (h) Tham khảo
- JPEG+ZIP polyglot, `binwalk`, `exiftool`.
- ZIP AES-256 (WinZip spec), 7-Zip, `pyzipper`.

---

## Bài 14 — Zambia C4 — csg_ctf

### (a) Đề bài & metadata
- **Tên:** csg_ctf — **Quốc gia/mã:** Zambia / C4 — **Category:** reverse / crypto — **Độ khó:** Trung bình.
- **Thư mục:** `2025-Cyber-SEA-Game/Zambia_C4_csg_ctf/`
- **File đề:** `C4_csg_ctf.HTA` (116673 byte, md5 `c327318de9a061955668cba97356b17a`) — một "HTML Application" dạng crackme kiểm tra mật khẩu bằng JavaScript (MD5).
- **Flag:** `CSG_FLAG{001112233446cDdefL}` *(đã kiểm chứng toàn bộ MD5 + ráp mật khẩu.)*

### (b) Kiến thức nền
- **HTA (HTML Application):** File `.hta` chạy bằng `mshta.exe` trên Windows — về cơ bản là một
  trang HTML có quyền cao hơn trang web thường (truy cập hệ thống), nhúng JavaScript/VBScript.
  Ở đây nó là một "crackme": nhập mật khẩu, JS kiểm tra đúng/sai. **Phân tích tĩnh = đọc mã JS
  trong file**, không cần chạy (an toàn).
- **MD5 crackme:** JS tính MD5 của (các phần) mật khẩu rồi so với hash đã nhúng. Vì MD5 một
  chiều, cách giải là **brute-force** (thử hết khi không gian nhỏ) hoặc dùng **hashcat**.
- **Phân rã mật khẩu theo mảng vị trí:** Mật khẩu bị tách thành 3 phần h1/h2/h3 theo một mảng
  chỉ số (`nl`), rồi mỗi phần được MD5 riêng → thu hẹp không gian brute-force từng phần thay vì
  cả mật khẩu.
- **Obfuscation nhẹ (string reverse + replace):** Hash mục tiêu được "che" bằng cách thay vài
  ký tự rồi **đảo ngược chuỗi**. Hàm `dfgtrfd45TYHtredfgr45treRRGTEDFR(string)` nghe đáng sợ
  nhưng thực chất chỉ là `string.split("").reverse().join("")` = **đảo chuỗi**.
- **hashcat mask attack (`-a 3`):** Thử mọi tổ hợp theo "mặt nạ"; `?1?1?1?1?1?1` với charset
  `-1 ?u?l?d` = 6 ký tự, mỗi ký tự là chữ hoa/thường/số.

### (c) Trinh sát ban đầu
```bash
grep -oE "ko = \"[0-9a-f]+\"|ka = \"[^\"]+\"|kq = \"[^\"]+\"|nl = \[[^]]*\]" C4_csg_ctf.HTA
# hoặc mở file, đọc hàm checkPW / co / ca / cq
```
Các biến khóa trong JS:
```javascript
nl = [0,6,17,14,1,18,16,7,11,13,8,12,2,3,0,15,4,0,9,5,0,0,10,0,0]
ko = "58b4cb64f141e5c914640c5c8cc8e5d5"   // h1: 8 chữ số
ka = "8a1828526galf607b8257cb552b0e6c8"   // h2: 4 ký tự alphanum
kq = "z99za5c140689zc2d2a1052c8z5e4b9d"   // h3: 6 ký tự alphanum
```
Hàm kiểm tra (rút gọn):
```javascript
co(o){ return o === reverse( ko.replace(/4/g,'a').replace(/d/g,'3').replace(/e/g,'7') ); }
ca(a){ return a === reverse( ka.replace(/f/g,'3').replace(/l/g,'d').replace(/g/g,'9') ); }
cq(q){ return q === reverse( kq.replace(/2/g,'f').replace(/b/g,'7').replace(/z/g,'3') ); }
```

### (d) Phân tích từng bước + reasoning "tại sao"
1. **Gỡ lớp obfuscation** để lấy **MD5 đích** của h1/h2/h3: áp các `replace` rồi **đảo ngược**
   chuỗi. Kết quả (đã kiểm chứng):
   - h1: `53578cc8c5c0a6a19c571a1fa6bcab85`
   - h2: `8c6e0b255bc7528b7063da96258281a8`
   - h3: `d974e538cf501afdfc3986041c5a3993`
   *Tại sao phải replace trước rồi reverse?* Vì đó đúng là thứ tự JS làm khi so sánh; ta chỉ
   tái hiện lại để biết hash thật cần crack.
2. **Crack từng phần** (không gian nhỏ):
   - h1 = 8 **chữ số** → `20231114` (nhìn như một ngày: 2023-11-14).
   - h2 = 4 **alphanum** → `fL46`.
   - h3 = 6 **alphanum** → `Dec0d3` (dùng hashcat mask).
3. **Ráp mật khẩu** theo mảng `nl` (mỗi ô lấy 1 ký tự từ h1/h2/h3 theo đúng chỉ số).

### (e) Lời giải / exploit đầy đủ
`solve.py` (chỉ tính MD5 — **không chạy** HTA):
```python
import hashlib, itertools

TARGET_H1 = "53578cc8c5c0a6a19c571a1fa6bcab85"  # 8 chữ số
TARGET_H2 = "8c6e0b255bc7528b7063da96258281a8"  # 4 alphanum
TARGET_H3 = "d974e538cf501afdfc3986041c5a3993"  # 6 alphanum (hashcat)
md5 = lambda s: hashlib.md5(s.encode()).hexdigest()

def crack(target, charset, length):             # brute-force
    for combo in itertools.product(charset, repeat=length):
        c = ''.join(combo)
        if md5(c) == target: return c

h2 = crack(TARGET_H2, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 4)  # fL46
h1 = crack(TARGET_H1, "0123456789", 8)          # 20231114
h3 = "Dec0d3"                                    # từ hashcat (6 alphanum)
assert md5(h3) == TARGET_H3

def reconstruct(h1,h2,h3):                       # ráp theo mảng nl
    return ''.join([h1[1],h3[3],h1[4],h1[5],h1[6],h1[0],h1[2],h1[3],
                    h3[5],h1[7],h2[2],h2[3],h3[2],h3[0],h3[4],h3[1],
                    h2[0],h2[1]])
print("CSG_FLAG{%s}" % reconstruct(h1,h2,h3))
```
Crack h3 bằng hashcat:
```bash
echo d974e538cf501afdfc3986041c5a3993 > hash.txt
hashcat -m 0 -a 3 hash.txt ?1?1?1?1?1?1 -1 ?u?l?d   # -> Dec0d3
```

**Kiểm chứng (đã chạy):**
```
h1: md5(20231114) = 53578cc8c5c0a6a19c571a1fa6bcab85   OK
h2: md5(fL46)     = 8c6e0b255bc7528b7063da96258281a8   OK
h3: md5(Dec0d3)   = d974e538cf501afdfc3986041c5a3993   OK
password: 001112233446cDdefL
```

### (f) Flag & ý nghĩa
```
CSG_FLAG{001112233446cDdefL}
```
Mật khẩu `001112233446cDdefL` được ráp từ 3 phần: `20231114` (ngày), `fL46`, `Dec0d3`
("Decode"). Các phần tự chúng mang nghĩa nhưng mật khẩu cuối là sự hoán vị theo mảng `nl`.

### (g) Cạm bẫy & cách khác
- **Cạm bẫy 1:** Bỏ qua lớp "replace + reverse" → so sai hash, không crack ra gì.
- **Cạm bẫy 2:** Brute-force cả mật khẩu 18 ký tự → bất khả thi. Phải tách h1/h2/h3.
- **Cạm bẫy 3:** h1 là 8 **chữ số** (10^8) — Python brute được nhưng hơi lâu; có thể đoán theo
  dạng ngày hoặc dùng hashcat `?d?d?d?d?d?d?d?d`.
- **Cạm bẫy 4:** Nhầm thứ tự ráp theo `nl` (một số vị trí trùng, một số là 0) → sai mật khẩu.
- **Cách khác:** Crack cả 3 hash bằng hashcat với mask tương ứng, rồi ráp bằng script.

### (h) Tham khảo
- HTA / `mshta.exe`; JavaScript MD5 implementation.
- hashcat mask attack (`-a 3`), charset tùy biến.
- Python `hashlib.md5`, `itertools.product`.

### (i) Đọc tĩnh HTA/JS + trace logic ráp mật khẩu từng bước

Phân tích **thật** trên `C4_csg_ctf.HTA` (116.673 byte) — đây là **file text**, nên đọc trực
tiếp mã nguồn, **không chạy `mshta.exe`**.

**1) HTA là gì (nền tảng).** `.hta` = HTML Application, chạy bởi `mshta.exe` của Windows. Khác
trang web: HTA chạy với quyền của người dùng (không sandbox), có thể trộn `<SCRIPT
Language="VBScript">` và `<script language="JavaScript">`. File này dùng `<HTA:APPLICATION>` để
tạo cửa sổ không viền, và `charset=shift_jis` (gợi ý tác giả người Nhật). Mọi logic kiểm tra mật
khẩu nằm trong JavaScript → ta chỉ cần **đọc JS**.

**2) Biến khóa (grep thật từ file):**
```javascript
var nl = [0, 6, 17, 14, 1, 18, 16, 7, 11, 13, 8, 12, 2, 3, 0, 15, 4, 0, 9, 5, 0, 0, 10, 0, 0];
ko = "58b4cb64f141e5c914640c5c8cc8e5d5";   // liên quan h1
ka = "8a1828526galf607b8257cb552b0e6c8";   // liên quan h2  (chú ý có 'g','l' không phải hex!)
kq = "z99za5c140689zc2d2a1052c8z5e4b9d";   // liên quan h3  (có 'z')
var m = window.host;   // host = FnBJT9OVUieRCjeTgMPMBe4U.hs  -> m() chính là hàm MD5
```
`m()` được gán bằng `FnBJT9OVUieRCjeTgMPMBe4U.hs` — một **cài đặt MD5 đầy đủ** trong file (nhận
ra nhờ các hằng số kinh điển `0xd76aa478, 0xe8c7b756, ...` và bước `h0=0x67452301`,
`h1=0xEFCDAB89`...). Vậy `m(x)` = MD5(x) dạng hex.

**3) Hàm kiểm tra (trích thật):**
```javascript
function checkPW(pass) {
  var pwbody = (" " + pass).split("");          // pwbody[0]=" ", pwbody[1..]=ký tự mật khẩu
  var h1="", h2="", h3="";
  for (var i = 0; i < 24;) {
    h1 += pwbody[nl[++i]];                        // rải ký tự vào h1/h2/h3 theo mảng nl
    h2 += pwbody[nl[++i]];
    h3 += pwbody[nl[++i]];
  }
  if ( co(m(h1.trim())) && ca(m(h2.trim())) && cq(m(h3.trim())) ) { /* đúng */ }
}
function co(o){ return o === reverse( ko.replace(/4/g,'a').replace(/d/g,'3').replace(/e/g,'7') ); }
function ca(a){ return a === reverse( ka.replace(/f/g,'3').replace(/l/g,'d').replace(/g/g,'9') ); }
function cq(q){ return q === reverse( kq.replace(/2/g,'f').replace(/b/g,'7').replace(/z/g,'3') ); }
// reverse = dfgtrfd45TYHtredfgr45treRRGTEDFR = string.split("").reverse().join("")
```
*Tại sao `ka`/`kq` có ký tự không-hex (`g,l,z`):* vì chúng là hash đích đã bị "bẩn hóa"; hàm
`replace` sẽ **đổi lại** (`f→3, l→d, g→9` cho `ka`; `2→f, b→7, z→3` cho `kq`) rồi **đảo chuỗi**
để ra MD5 hex thật.

**4) Gỡ obfuscation → MD5 đích (tính thật):**
```
co: reverse(ko.replace(4->a,d->3,e->7)) = 53578cc8c5c0a6a19c571a1fa6bcab85   (= md5("20231114"))
ca: reverse(ka.replace(f->3,l->d,g->9)) = 8c6e0b255bc7528b7063da96258281a8   (= md5("fL46"))
cq: reverse(kq.replace(2->f,b->7,z->3)) = d974e538cf501afdfc3986041c5a3993   (= md5("Dec0d3"))
```
Cả 3 đã **xác nhận khớp** bằng `hashlib.md5` (chạy thật, chỉ băm chuỗi).

**5) Trace mảng `nl` — forward (HTA ráp h1/h2/h3 TỪ mật khẩu).** Vòng lặp `++i` tiền tố, dùng
`nl[1..24]`; giá trị `0` trỏ tới `pwbody[0]=" "` (bị `trim()` bỏ). Với mật khẩu `p[0..17]`:
```
h1 (i=1,4,7,10,13,16,19,22) = p5 p0 p6 p7 p2 p3 p4 p9        (8 ký tự -> "8 chữ số")
h2 (i=2,5,8,11,14,17,20,23) = p16 p17 p10 p11 (+space bỏ)    (4 ký tự)
h3 (i=3,6,9,12,15,18,21,24) = p13 p15 p12 p1 p14 p8 (+space) (6 ký tự)
```

**6) Trace ngược (solver dựng lại mật khẩu TỪ h1/h2/h3) — khớp `solve.py`:**
```
p0 =h1[1]  p1 =h3[3]  p2 =h1[4]  p3 =h1[5]  p4 =h1[6]  p5 =h1[0]
p6 =h1[2]  p7 =h1[3]  p8 =h3[5]  p9 =h1[7]  p10=h2[2]  p11=h2[3]
p12=h3[2]  p13=h3[0]  p14=h3[4]  p15=h3[1]  p16=h2[0]  p17=h2[1]
```
Thay `h1="20231114"`, `h2="fL46"`, `h3="Dec0d3"`:
```
0 0 1 1 1 2 2 3 3 4 4 6 c D d e f L   ->  001112233446cDdefL
```
(Mình đã **tự trace vòng lặp forward** rồi lấy nghịch đảo, và nó trùng khít mảng reconstruct
trong `solve.py` — xác nhận logic đúng.)

**7) Crack 3 thành phần (không gian nhỏ):** h2 (4 alphanum, ~1.5×10⁷) và h1 (8 **chữ số**, 10⁸)
brute bằng Python; h3 (6 alphanum, ~5.7×10¹⁰) dùng hashcat:
```bash
hashcat -m 0 -a 3 hash.txt ?1?1?1?1?1?1 -1 ?u?l?d   # -> Dec0d3
```
Ghép theo bước (6) → `CSG_FLAG{001112233446cDdefL}`. Toàn bộ **không chạy HTA** — chỉ đọc JS và
băm chuỗi.

---

## Kết thúc

Toàn bộ 14 challenge của **Cyber SEA Game 2025** đã được phân tích lại và kiểm chứng:
flag đúng, giá trị khóa/magic bytes/hash khớp file thật. Các điểm đính chính (Angola,
DR Congo, France, Germany, Switzerland) đã nêu rõ trong từng bài và ở mục
[Danh sách đính chính](#danh-sách-đính-chính). Mọi phân tích file thực thi đều là **tĩnh**.

> *Tài liệu này nhằm mục đích giáo dục. Các kỹ thuật tấn công (poisoning, packer, C2…)
> chỉ nên dùng trong môi trường được phép (CTF, lab của chính bạn).*

---

# Phụ lục B — Đào sâu kỹ thuật (worked examples từng bài)

> Phần này bổ sung **ví dụ số cụ thể từng bước** và lý thuyết mở rộng cho người mới,
> để bạn tự tay làm lại được chứ không chỉ "đọc hiểu". Mỗi mục gắn với một bài ở trên.

## B.1 — Angola: tự tay bóc 2 lớp base64 và hiểu `U+HHHH`

**Ví dụ thu nhỏ của double base64.** Giả sử thông điệp thật là chuỗi `"U+0040"` (tức ký
tự `@`). Mã hóa lớp 1:
```
"U+0040"  --base64-->  "VSswMDQw"
```
Mã hóa lớp 2 (base64 của kết quả trên):
```
"VSswMDQw" --base64--> "VlNzd01EUXc="
```
Vậy file đề chứa thứ giống `VlNzd01EUXc=`. Khi giải:
```python
import base64
base64.b64decode("VlNzd01EUXc=")          # -> b'VSswMDQw'  (vẫn giống base64!)
base64.b64decode(b'VSswMDQw')             # -> b'U+0040'    (ra "U+HHHH")
```
**Dấu hiệu nhận biết lớp kép:** decode một lần ra chuỗi mà **mọi ký tự vẫn thuộc bảng
base64** (`A–Z a–z 0–9 + / =`) và độ dài là bội số của 4 → thử decode tiếp.

**Hiểu `U+0040`:** `0x40` = 64 thập phân = mã ASCII của `@`. Trong Python,
`chr(0x40)` → `'@'`. Nếu cả văn bản là `U+0040 U+0065 U+0063 U+0068 U+006F...`:
```python
import re
cps = re.findall(r"U\+([0-9A-Fa-f]{4})", "U+0040U+0065U+0063U+0068U+006F")
"".join(chr(int(c,16)) for c in cps)       # -> '@echo'  (bắt đầu batch!)
```
Đây đúng là vài byte đầu của `@echo off`.

**Vì sao `%BeoPl:~14,1%` = một ký tự:** với `BeoPl=clpadkuxztisfnerygwobmhqvj`, đếm từ 0:
vị trí 0=`c`, 1=`l`, 2=`p`, ... vị trí 14=`e`. Nên `%BeoPl:~14,1%` → `e`. Một dòng gồm
nhiều lookup như vậy chính là cách "đánh vần" từng chữ của lệnh/thông điệp để giấu.

**Kiểm tra lại kết quả (sanity check):** sau khi mô phỏng, output phải là câu tiếng Anh
có nghĩa ("...here is the password F1r3NIc3$4Lyfe"). Nếu ra chuỗi rác → nhiều khả năng
bạn quên xử lý `%%...%%` (dấu `%` nhân đôi) hoặc chưa phân giải các dòng `set`.

## B.2 — Australia: đọc hiểu luật PAM từng cột

Một dòng cấu hình PAM gồm 3 phần: **type**, **control**, **module [args]**. Ví dụ:
```
auth   sufficient            pam_succeed_if.so   use_uid user = user
└type┘ └──control──┘         └─────module─────┘  └────args────┘
```
- **type = auth:** đây là bước xác thực (chứng minh danh tính).
- **control = sufficient:** nếu module này trả "thành công" thì **dừng và cho qua ngay**
  (không cần các dòng sau, không hỏi mật khẩu).
- **module pam_succeed_if.so với `use_uid user = user`:** thành công nếu UID hiện tại là
  của `user`.

Dòng còn lại:
```
auth [success=ignore default=1] pam_succeed_if.so user = shutdown
```
- **control dạng ngoặc `[success=ignore default=1]`:** điều khiển "nhảy" tinh vi — nếu điều
  kiện (`user = shutdown`, tức đang `su` sang `shutdown`) đúng thì `success=ignore` (bỏ qua,
  đi tiếp tới dòng `sufficient`); nếu sai thì `default=1` (nhảy qua 1 dòng, tức bỏ qua dòng
  `sufficient` kế tiếp).

**Kết hợp:** khi `user` chạy `su shutdown`: dòng 1 khớp → đi tiếp → dòng 2 (`sufficient`,
UID = user) khớp → **cho qua, miễn mật khẩu**. Đây chính là "cửa hậu" đã cài.

**Vì sao SUID trên `shutdown.sh` quan trọng:** `chmod u+s` khiến script chạy với quyền chủ
sở hữu. Nhưng ở đây con đường tắt máy dựa chính vào **sudoers NOPASSWD** cho `poweroff`,
nên dù không có SUID thì `sudo poweroff -i` vẫn chạy được từ user `shutdown`.

## B.3 — C6 (Baudot): giải mã tay một nhóm 5 bit

Giả sử sau khi map `.`=1, `-`=0 ta có 5 bit đầu là `01110`. Tra bảng ITA2 LETTERS:
`0b01110` = 14 thập phân → ký tự `C`. Nhóm tiếp `00101` = 5 → `S`? (tùy bảng). Điểm cốt
lõi: **mỗi 5 bit = đúng 1 ký tự**, không cần dấu phân cách — khác hẳn Morse.

**Vì sao phải thử 4 biến thể:** có 2 lựa chọn cho ánh xạ bit (`.`=1 hay `.`=0) × 2 lựa
chọn cho thứ tự bit trong nhóm (xuôi hay đảo) = 4. Một bảng mẹo chấm điểm: biến thể nào cho
ra **nhiều từ Thụy Điển hợp lệ** (ADAM, BERTIL, CAESAR...) nhất thì đúng. Ví dụ nếu một
biến thể giải ra `CAESAR SIGURD GUSTAV` (3 từ hợp lệ) còn biến thể khác ra `XQJ ZWV` (0 từ)
→ chọn biến thể đầu.

**Hai lớp mã liên tiếp:** đây là điểm hay của bài — lớp 1 (Baudot) cho ra **tên**, lớp 2
(bảng chính tả) biến mỗi tên thành **1 chữ cái**. Ví dụ chuỗi Baudot giải ra
`CAESAR SIGURD GUSTAV` → lấy chữ đầu → `CSG` → chính là tiền tố flag!

## B.4 — China: số học XOR trên byte có dấu

Ciphertext in ra số âm vì dùng **bù hai 8-bit**. Quy tắc đổi: nếu số `n < 0` thì byte thật
là `n + 256`. Ví dụ `-48 + 256 = 208 = 0xD0`.

**XOR tay một byte:** lấy `data=0xD0 (11010000)`, `key=0x81 (10000001)`:
```
  1 1 0 1 0 0 0 0   (0xD0)
⊕ 1 0 0 0 0 0 0 1   (0x81)
-----------------
  0 1 0 1 0 0 0 1   = 0x51 = 'Q'
```
`'Q'` là một ký tự base64 hợp lệ (chữ hoa) — dấu hiệu ta đang đi đúng. Làm vậy cho cả 40
cặp byte → ra chuỗi base64 → `base64.b64decode` → flag.

**Vì sao chắc "nửa sau là khóa":** kiểm bằng cặp mẫu. base64("Great Scott!") =
`R3JlYXQgU2NvdHQh`. Nếu XOR 16 byte đầu ciphertext mẫu với 16 byte sau mà ra đúng chuỗi
base64 này → mô hình đúng. Đây là **known-plaintext attack**: dùng dữ liệu biết trước để
xác nhận giả thuyết trước khi áp cho ẩn số.

---

## B.5 — DR Congo: tính khóa Vigenère tay và hiểu "tableau"

Vigenère dùng một "bảng" (tableau) 26×26, nhưng thực chất chỉ là phép cộng/trừ theo modulo
26 trên vị trí chữ cái (A=0, B=1, ..., Z=25).

**Tìm khóa từ cặp biết trước** `CSG_FLAG` ↔ `OST_RLNS`. Bỏ qua ký tự `_` (không phải chữ):
```
C(2)  -> O(14) : key = (14 - 2)  mod 26 = 12 = 'M'
S(18) -> S(18) : key = (18 - 18) mod 26 = 0  = 'A'
G(6)  -> T(19) : key = (19 - 6)  mod 26 = 13 = 'N'
F(5)  -> R(17) : key = (17 - 5)  mod 26 = 12 = 'M'
L(11) -> L(11) : key = 0  = 'A'
A(0)  -> N(13) : key = 13 = 'N'
G(6)  -> S(18) : key = 12 = 'M'
```
Dòng khóa: `M A N M A N M` → lặp `MAN`. Vậy **khóa = "MAN"** (3 chữ).

**Giải mã** dùng `P = (C - K) mod 26`. Ví dụ ký tự `Y` (24) với khóa `M`(12):
`(24-12) mod 26 = 12 = 'M'`? Không — tùy vị trí khóa. Điểm cần nhớ: **chỉ chữ cái mới dịch
và mới "tiêu tốn" một bước khóa**; dấu `_ { } ! = -` giữ nguyên và **không** làm nhảy khóa.
Đây chính là lý do khi ghép tile sai thứ tự, phần đuôi giải ra sai (lệch pha khóa).

**Kiểm chứng ngược (rất hữu ích):** mã hóa flag đã biết bằng khóa `MAN` rồi so với
ciphertext ghép. Nếu khớp phần đầu nhưng lệch phần cuối → biết ngay các **mảnh cuối bị sắp
sai** (chính là lỗi trong README gốc, đã nêu ở Bài 5).

## B.6 — France: hiểu "secret sharing" ảnh và vì sao phải kết hợp

Một QR đen/trắng có thể được tách thành 2–4 "share". Cách đơn giản nhất (XOR share): chọn
share ngẫu nhiên `S1`, rồi `S2 = QR ⊕ S1`. Mỗi share trông như nhiễu; chỉ khi `S1 ⊕ S2`
mới hiện lại `QR`. Với 4 ảnh, tác giả có thể dùng biến thể (mỗi pixel quyết định bởi tổ hợp
4 share).

**Vì sao thử median/min/max/std:** ta không biết công thức tổ hợp chính xác, nên thử nhiều
"toán tử" thống kê trên chồng 4 ảnh:
- `min`: điểm tối nhất trong 4 ảnh (làm nổi vùng đen chung).
- `max`: điểm sáng nhất (nổi vùng trắng chung).
- `median`: trung vị (khử nhiễu muối tiêu).
- `std`: độ lệch chuẩn (nổi vùng mà 4 ảnh "bất đồng" — thường là mép mã).
- `xor`: nổi khác biệt bit.
Chỉ cần **một** biến thể cho QR đủ sạch để `QRCodeDetector` giải được là xong.

**Về SSE-C — vì sao GET trần thất bại:** S3 lưu object đã mã hóa bằng khóa của khách. Khi
GET, S3 cần 3 header: thuật toán (`AES256`), khóa (base64), và MD5 của khóa. Thiếu → lỗi
`InvalidRequest`. Proxy `fetch.php` phía server đã nhúng sẵn 3 header này nên lấy được nội
dung — đó là "đường chính chủ" của đề.

## B.7 — Germany: bóc header RTP và nhận diện Morse trên spectrogram

**Header RTP 12 byte đầu (bit-field):**
```
byte0: V(2bit) P(1) X(1) CC(4)     -> V phải = 2 (10 nhị phân)
byte1: M(1) PT(7)                  -> PT = payload type (0 = PCMU)
byte2-3: sequence number (16 bit)
byte4-7: timestamp (32 bit)
byte8-11: SSRC (32 bit)            -> định danh nguồn
payload: từ byte 12 trở đi         -> 1 byte/mẫu với µ-law
```
Kiểm `pt = byte1 & 0x7F` (bỏ bit M). Nếu `pt == 0` → PCMU → lấy `payload[12:]`.

**µ-law → PCM:** µ-law nén mỗi mẫu thành 1 byte theo thang logarit (nghe rõ ở âm nhỏ). Giải
bằng `audioop.ulaw2lin(data, 2)` cho ra mẫu 16-bit. 8000 mẫu = 1 giây âm thanh.

**Đọc Morse trên spectrogram:** mở WAV trong Sonic Visualiser, bật lớp Spectrogram. Một
**tone liên tục ngắn** = dấu chấm `.`; **tone dài** (khoảng gấp 3) = gạch `-`; khoảng lặng
ngắn ngăn chấm/gạch, khoảng lặng dài ngăn chữ. Ghi lại rồi tra bảng Morse:
```
-.--  = Y        ----- = 0        ..- = U        .- = A        .-. = R        . = E
-..   = D        .-.. = L?        ...                         -> "Y0UARE..."
```
Ghép: `Y0UAREDECODEDV01P`.

## B.8 — Greece: vì sao RVA ≠ offset và cách `pefile` quy đổi

Trên đĩa, PE chia thành **section** (`.text`, `.data`, `.rdata`...). Mỗi section có:
- `VirtualAddress` (RVA — nơi nó sẽ nằm khi nạp vào RAM),
- `PointerToRawData` (offset trong file trên đĩa),
- và hai kích thước (virtual/raw) thường **khác nhau** do alignment (căn lề 0x200/0x1000).

Vì vậy **RVA 0xF370** không phải vị trí byte thứ 0xF370 trong file. Công thức quy đổi:
```
offset = RVA - section.VirtualAddress + section.PointerToRawData
```
`pefile.get_offset_from_rva(0xF370)` làm đúng phép này. Nếu bạn đọc nhầm tại offset = RVA
thô → lấy sai dữ liệu → AES decrypt ra rác (không `MZ`).

**Vì sao verify `MZ` + `PE\0\0` là đủ tin:** xác suất một khối giải mã sai mà ngẫu nhiên
bắt đầu bằng `4D 5A` rồi lại có `50 45 00 00` đúng tại offset `e_lfanew` là cực thấp. Khớp
cả hai → gần như chắc chắn khóa/chế độ AES đúng.

## B.9 — R6: bóc tay 1 lớp Matryoshka bằng CyberChef

Giả sử lớp hiện tại là:
```php
eval(hex2bin("62617365363425f6465636f6465282..."))
```
Các bước "đảo" trong CyberChef (hoặc tay):
1. Lấy chuỗi hex trong `hex2bin("...")`. **From Hex** → ra text, ví dụ
   `base64_decode("aGV4Mm...")`.
2. Lấy chuỗi base64 trong đó. **From Base64** → ra `hex2bin("677a...")`.
3. **From Hex** → ra `gzinflate("...")`.
4. Lấy dữ liệu nén, **Raw Inflate** → ra lớp PHP kế tiếp.
5. Lặp lại tới khi thấy `CSG_FLAG`.

**Tuyệt đối không** dán nguyên `eval(...)` vào `php` CLI để chạy. Thay `eval` bằng `echo`
hoặc dùng CyberChef (chỉ biến đổi dữ liệu, không thực thi) để an toàn.

**Phân tích cú lừa `substr($s,0,27)`:** đếm ký tự chuỗi
`print("I have a flag!\n")` — đúng 27 ký tự (kể cả dấu ngoặc và `\n` tính là 2 ký tự nguồn
`\` và `n`). Nên `eval` chỉ chạy phần in "I have a flag!", bỏ hết phần sau — nơi (trong
comment) chứa flag. Bài dạy: **đọc dữ liệu, đừng tin output**.

---

## B.10 — Saudi: phẫu thuật PE tay bằng hex và căn `e_lfanew`

File hỏng (24 byte đầu):
```
offset 0x00: 00 04 99 01 40 01 b1 a3 00 00   <- 10 byte rác (bỏ đi)
offset 0x0A: 5a 5a 90 00 03 00 00 00 04 00   <- "ZZ.." (5a 5a)
offset 0x14: 00 00 ff ff
```
Sau khi **bỏ 10 byte** (offset 0x0A trở thành 0x00):
```
offset 0x00: 5a 5a 90 00 03 00 00 00 04 00 00 00 ff ff ...   = "ZZ.."
```
**Sửa byte 0** `5a`→`4d`:
```
offset 0x00: 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff ...   = "MZ.."  ✓
```
**Kiểm `e_lfanew`:** đọc 4 byte little-endian tại offset `0x3C` của file đã khôi phục. Kết
quả (đã xác nhận) = `0x00000100` → NT header ở offset `0x100`, nơi có `50 45 00 00` = `PE\0\0`.
Vậy PE hợp lệ.

**Vì sao `%sing` → `finding`:** trong C, `printf("...%sing...", "find")` thay `%s` bằng
`"find"` rồi phần chữ `ing` đi liền sau → `finding`. Đây là mẹo nhỏ của tác giả để flag
không xuất hiện trọn vẹn dưới dạng chuỗi thô trong binary (nên `strings` thường không thấy
nguyên `finding`).

## B.11 — Sweden: chạy tay vài bước RC4 (KSA)

RC4 khởi tạo mảng `S = [0,1,2,...,255]` rồi xáo theo khóa (KSA). Minh họa 2 bước đầu với
khóa `K = "RC4JsonMarshalLocalC2"` (byte đầu `'R'=0x52=82`):
```
i=0: j = (0 + S[0] + K[0])   & 255 = (0 + 0 + 82) & 255 = 82
     swap S[0],S[82]   -> S[0]=82, S[82]=0
i=1: j = (82 + S[1] + K[1])  & 255 = (82 + 1 + 67) & 255 = 150   ('C'=67)
     swap S[1],S[150]
...  (lặp 256 lần)
```
Sau KSA, PRGA sinh keystream và XOR với ciphertext. Vì RC4 **đối xứng** (XOR), cùng một hàm
`rc4()` vừa mã hóa vừa giải mã.

**Kết quả thực tế là JSON:**
```json
{"tasks":[{"task":"print_flag","flag":"CSG_FLAG{go_rev_startingpoint}"}]}
```
Vì server thật trả JSON cho client, nên plaintext cũng là JSON — một chi tiết "sát thực tế"
của bài mô phỏng C2. (Tên khóa `RC4JsonMarshalLocalC2` còn gợi ý: RC4 + JSON Marshal + Local
C2 — tóm tắt luôn cơ chế.)

## B.12 — Switzerland: hiểu offset trường NTLMSSP Type 3

Mỗi "security buffer" trong NTLMSSP là cấu trúc 8 byte: `Len(2) MaxLen(2) Offset(4)` — trỏ
tới dữ liệu thật ở nơi khác trong blob. Bảng offset (tính từ đầu `NTLMSSP\x00`):
```
+12: LM response fields
+20: NT response fields        <- NTLMv2 response (cái ta cần)
+28: DomainName fields         <- "WINDOMAIN"
+36: UserName fields           <- "bob"
+44: Workstation fields
```
Đọc NT response: lấy `Len` và `Offset` tại +20, rồi cắt `blob[Offset : Offset+Len]`. Chuỗi
này (ví dụ dài 326 byte = 652 hex) gồm:
```
[0:16]  = NTProofStr          -> 32 hex  (4837e8d2...)
[16:]   = blob NTLMv2         -> 620 hex  (0101000000000000...)
```
**Server challenge** nằm ở Type 2, tại **byte 24–32** (8 byte) kể từ `NTLMSSP\x00`.

**Vì sao ghép thành `-m 5600`:** hashcat NetNTLMv2 cần đúng 5 phần
`user::DOMAIN:serverchallenge:NTProofStr:blob`. Dạng flag của bài **copy y hệt** cấu trúc
này — nên "flag" chính là một hash có thể crack ra mật khẩu `bob`. Tên miền
`win10-2.windomain.local` và service `cifs/dcc02` giải ra từ blob khớp với `strings` ta thấy
(`WINDOMAIN.LOCAL`, `dcc02`).

## B.13 — Tanzania: phân biệt ZipCrypto vs AES và cách carve

**Nhận biết ZIP AES:** trong local file header, trường "compression method" = `0x63` (99)
cho biết dùng mã hóa AES (WinZip). `unzip` cổ điển không hỗ trợ → báo lỗi
`unsupported`/`need PK compat v5.1`. Dùng 7-Zip hoặc `pyzipper`:
```python
import pyzipper
with pyzipper.AESZipFile("embedded.zip") as z:
    z.pwd = b"WATPHO-RECLINING-BUDDHA"
    print(z.read("flag.txt").decode())
```

**Carve chính xác:** JPEG hợp lệ có thể chứa chuỗi `PK` ngẫu nhiên bên trong dữ liệu ảnh,
nên tìm `PK\x03\x04` (đủ 4 byte chữ ký local file header) thay vì chỉ `PK`. Lấy từ vị trí
đó tới hết file. Có thể kiểm bằng cách thử mở `embedded.zip` — nếu `zipfile` đọc được danh
sách tên file thì carve đúng.

**Về mật khẩu nhiều mảnh:** `P1/P2/P3` thường nằm ở các vùng metadata khác nhau (EXIF
Comment, XMP, hoặc chèn giữa dữ liệu). `exiftool -a -u -g1 S3.jpg` liệt kê mọi tag, kể cả
tag lạ — nơi giấu các mảnh.

## B.14 — Zambia: vì sao tách h1/h2/h3 làm brute-force khả thi

**Chi phí brute-force theo không gian:**
- Cả mật khẩu 18 ký tự alphanum: `62^18` ≈ `10^32` tổ hợp → **bất khả thi**.
- Tách riêng: h1 (8 **chữ số**) = `10^8` = 100 triệu (vài phút Python, hoặc tức thì với
  hashcat `?d?d?d?d?d?d?d?d`); h2 (4 alphanum) = `62^4` ≈ 14.7 triệu (nhanh); h3 (6 alphanum)
  = `62^6` ≈ 56.8 tỉ (cần hashcat GPU, mask `?1?1?1?1?1?1`).
→ Đây là bài học: **nếu mỗi phần được hash riêng, hãy crack riêng** — giảm độ phức tạp từ
tích xuống tổng.

**Gỡ obfuscation — tái hiện đúng thứ tự JS:** JS làm `reverse(replace(k, ...))`. Để lấy hash
đích, ta làm **đúng thứ tự đó**:
```python
ko = "58b4cb64f141e5c914640c5c8cc8e5d5"
target_h1 = ko.replace('4','a').replace('d','3').replace('e','7')[::-1]
# -> "53578cc8c5c0a6a19c571a1fa6bcab85"  (đã xác nhận = md5("20231114"))
```
*(Lưu ý thứ tự replace: `4`→`a` trước, rồi `d`→`3`, rồi `e`→`7`. Làm sai thứ tự có thể cho
kết quả khác nếu các ký tự chồng lấn.)*

**Ráp theo mảng `nl`:** `reconstruct` lấy từng ký tự: `h1[1], h3[3], h1[4], ...`. Với
`h1="20231114"`, `h1[1]='0'`, `h1[4]='1'`... Ghép đủ 18 vị trí → `001112233446cDdefL`. Kiểm
nhanh: md5 của từng phần phải khớp 3 hash đích (đã xác nhận toàn bộ "OK" khi chạy).

---

## Phụ lục C — Bảng tra cứu nhanh công cụ theo category

| Category | Công cụ hay dùng | Dùng để |
|---|---|---|
| Encoding/crypto | CyberChef, Python (`base64`, `hashlib`), dcode.fr | decode nhiều lớp, XOR, Vigenère, băm |
| Reverse (PE) | Ghidra, IDA, x64dbg, `pefile`, `strings`, `xxd` | dịch ngược, sửa header, trích hằng số |
| Reverse (Go) | Ghidra + GoReSym/redress | khôi phục symbol `main.*` |
| Reverse (web/PHP) | php CLI (thay `eval`→`echo`), CyberChef | bóc obfuscation an toàn |
| Forensics (file) | `binwalk`, `foremost`, `exiftool`, 7-Zip, `pyzipper` | carve, đọc metadata, giải ZIP AES |
| Forensics (network) | Wireshark, `tshark`, `scapy`, `pcredz` | mổ pcap, rút NTLM/RTP |
| Audio stego | Sonic Visualiser, Audacity, `audioop` | spectrogram, giải µ-law, đọc Morse |
| Cracking | hashcat, John the Ripper | brute MD5/NetNTLMv2 |

*(Hết tài liệu.)*

---

# Phụ lục D — Lý thuyết nền chuyên sâu (dùng chung nhiều bài)

> Phần này giải thích **cơ chế bên trong** của các kỹ thuật lặp lại xuyên suốt giải, viết
> cho người mới nhưng đủ sâu để hiểu "tại sao nó chạy". Các bài ở trên tham chiếu tới đây.

## D.1 — Cấu trúc file PE (Windows exe/dll) mổ xẻ chi tiết

Dùng cho: **Greece** (packer), **Saudi Arabia** (corrupted), **Sweden** (nếu build PE).

Một file PE gồm các phần nối tiếp:

1. **DOS header (64 byte):** bắt đầu bằng `MZ` (0x4D 0x5A). Đây là di sản tương thích ngược:
   nếu chạy trên DOS cũ, phần "DOS stub" sẽ in "This program cannot be run in DOS mode". Trường
   quan trọng nhất: `e_lfanew` tại offset `0x3C` (4 byte little-endian) = offset tới NT header.
2. **DOS stub:** đoạn mã DOS nhỏ (thường in thông báo trên).
3. **NT Headers:** bắt đầu bằng chữ ký `PE\0\0` (0x50 45 00 00). Gồm:
   - **File Header (COFF):** số section, machine type (0x8664 = x64), timestamp...
   - **Optional Header:** `AddressOfEntryPoint` (RVA điểm bắt đầu chạy), `ImageBase`,
     `SectionAlignment` (thường 0x1000), `FileAlignment` (thường 0x200), bảng Data Directory
     (import, export, resource...).
4. **Section Table:** mỗi section mô tả `.text` (mã), `.data` (dữ liệu ghi được), `.rdata`
   (dữ liệu chỉ đọc), `.rsrc` (tài nguyên)... Mỗi mục có `VirtualAddress` (RVA) và
   `PointerToRawData` (offset file) — **hai con số này khác nhau**, gây ra chuyện RVA ≠ offset.
5. **Dữ liệu section:** nội dung thật.

**Little-endian là gì:** x86/x64 lưu số nhiều byte theo thứ tự byte thấp trước. Ví dụ
`e_lfanew = 0x00000100` được lưu trên đĩa là `00 01 00 00`. Khi đọc, phải đảo lại:
`int.from_bytes(b, "little")`.

**Vì sao packer hay dùng PE:** packer giấu một PE khác (DLL payload) bên trong `.data`/`.rsrc`
dưới dạng mã hóa. Khi phân tích tĩnh, ta tìm vùng blob + hàm giải mã, tự decrypt → thu được PE
con. Kiểm `MZ`/`PE\0\0` để chắc chắn.

## D.2 — AES và chế độ ECB: vì sao giải mã CTF thường dễ

Dùng cho: **Greece** (AES-128-ECB), **France/Tanzania** (AES-256 ở S3/ZIP).

**AES (Advanced Encryption Standard):** mã khối, khối 128 bit (16 byte). Khóa 128/192/256 bit.
Mã hóa gồm nhiều "vòng" (10/12/14 vòng) với các bước SubBytes, ShiftRows, MixColumns,
AddRoundKey — nhưng với CTF ta **không cần tự cài AES**, chỉ gọi thư viện.

**Chế độ (mode) — điểm mấu chốt:**
- **ECB (Electronic Codebook):** chia plaintext thành khối 16 byte, mã hóa **độc lập** từng
  khối bằng cùng khóa. *Ưu điểm cho CTF:* **không cần IV** (vector khởi tạo), giải mã chỉ cần
  khóa. *Nhược điểm bảo mật:* khối plaintext giống nhau → khối ciphertext giống nhau (lộ mẫu,
  ví dụ "ảnh con chim cánh cụt ECB" nổi tiếng).
- **CBC:** mỗi khối XOR với ciphertext khối trước + cần **IV**. Giải mã cần cả khóa và IV.
- **CTR/GCM:** biến mã khối thành mã dòng; GCM còn có xác thực (tag).

**Padding:** nếu plaintext không chia hết 16 byte, dùng PKCS#7 (đệm thêm byte). Khi giải mã PE
nhúng, thường kích thước đã là bội số 16 nên không vướng padding.

**Trong Python (pycryptodome):**
```python
from Crypto.Cipher import AES
dec = AES.new(key16, AES.MODE_ECB).decrypt(ciphertext)   # ECB: không IV
```

## D.3 — RC4 đầy đủ: KSA + PRGA và tính đối xứng

Dùng cho: **Sweden** (Fake C2).

RC4 là mã dòng: sinh ra một **keystream** giả ngẫu nhiên dài bằng dữ liệu, rồi XOR.

**Pha 1 — KSA (Key Scheduling Algorithm):** khởi tạo và xáo mảng `S` 256 phần tử theo khóa:
```python
S = list(range(256))          # S = [0,1,...,255]
j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) & 0xFF
    S[i], S[j] = S[j], S[i]    # hoán đổi
```

**Pha 2 — PRGA (Pseudo-Random Generation Algorithm):** sinh keystream, XOR với dữ liệu:
```python
i = j = 0
for b in data:
    i = (i + 1) & 0xFF
    j = (j + S[i]) & 0xFF
    S[i], S[j] = S[j], S[i]
    k = S[(S[i] + S[j]) & 0xFF]   # 1 byte keystream
    out.append(b ^ k)
```

**Tính đối xứng — vì sao mã hóa = giải mã:** vì `C = P ⊕ K` và `P = C ⊕ K` với cùng keystream
`K`. Cùng khóa → cùng `S` → cùng `K`. Nên chỉ cần **một** hàm `rc4()` cho cả hai chiều. Đó là
lý do ở bài Sweden ta chỉ cần khóa + ciphertext, chạy `rc4(ct, key)` là ra plaintext.

**Điểm yếu RC4 (biết thêm):** vài byte keystream đầu bị lệch thống kê (tấn công WEP). Nhưng
trong CTF kiểu này, RC4 chỉ là "khóa đối xứng tiện dụng".

## D.4 — Base64 mổ theo bit

Dùng cho: **Angola** (double base64), **China** (base64 lớp trong), **France** (ảnh base64).

Base64 biến **3 byte (24 bit)** thành **4 ký tự (mỗi ký tự 6 bit)**. Bảng 64 ký tự:
`A-Z`(0–25), `a-z`(26–51), `0-9`(52–61), `+`(62), `/`(63).

**Ví dụ mã hóa "Man":**
```
'M'=77=01001101  'a'=97=01100001  'n'=110=01101110
Ghép 24 bit:  010011 010110 000101 101110
Mỗi 6 bit:    19     22     5      46
Tra bảng:     T      W      F      u
-> "TWFu"
```
Giải mã làm ngược lại. **Dấu `=`**: nếu đầu vào không chia hết 3 byte, kết quả được đệm `=`
(1 hoặc 2 dấu) để đủ 4 ký tự.

**Vì sao "double base64" nhận ra được:** output base64 chỉ gồm ký tự trong bảng trên + `=`,
và độ dài là bội số 4. Nếu decode một lần mà kết quả **vẫn** thỏa hai điều đó → nhiều khả năng
còn một lớp base64 nữa. (Cảnh giác dương tính giả: một số chuỗi text thường cũng "trông giống"
base64; nên thử decode và xem kết quả có ý nghĩa không.)

---

## D.5 — Kinh tế học crack hash: MD5, không gian tìm kiếm, hashcat

Dùng cho: **Zambia** (MD5 crackme), **Switzerland** (NetNTLMv2).

**Hàm băm (hash):** biến dữ liệu bất kỳ thành chuỗi độ dài cố định (MD5 → 128 bit = 32 hex).
Tính chất: một chiều (khó đảo), kháng va chạm (khó tìm 2 đầu vào cùng hash — MD5 đã yếu điểm
này). Trong crackme, ta **không đảo** hash mà **thử đầu vào** (brute-force/dictionary) rồi so.

**Không gian tìm kiếm = (số ký tự khả dĩ)^(độ dài):**
| Thành phần | Charset | Độ dài | Không gian | Khả thi? |
|---|---|---|---|---|
| chữ số | 10 | 8 | 10^8 = 100 triệu | Python vài phút / hashcat tức thì |
| alphanum | 62 | 4 | ~1.5×10^7 | nhanh |
| alphanum | 62 | 6 | ~5.7×10^10 | cần GPU (hashcat) |
| alphanum | 62 | 18 | ~10^32 | **bất khả thi** |

→ Bài học lớn: nếu đề hash **từng phần riêng**, hãy crack **từng phần** (cộng chi phí) thay vì
cả chuỗi (nhân chi phí). Đây là lý do Zambia tách h1/h2/h3.

**hashcat modes gặp trong giải:**
- `-m 0` = MD5 thô (Zambia).
- `-m 5600` = NetNTLMv2 (Switzerland).
- `-a 3` = mask attack (thử theo khuôn): `?d`=chữ số, `?l`=thường, `?u`=hoa, `?a`=tất cả,
  `?1`=charset tùy biến (định nghĩa bằng `-1`). Ví dụ `?1?1?1?1?1?1 -1 ?u?l?d` = 6 ký tự mỗi
  cái là hoa/thường/số.
- `-a 0` = dictionary (dùng wordlist như `rockyou.txt`) — hiệu quả cho mật khẩu người thật.

## D.6 — Luồng xác thực NTLM và vì sao "nghe lén" là có thật

Dùng cho: **Switzerland** (Betrayer).

**Bối cảnh tấn công:** Trong mạng Windows, khi máy A không phân giải được tên máy B qua DNS,
nó **phát broadcast** hỏi qua LLMNR (UDP 5355) hoặc NBT-NS (UDP 137). Kẻ tấn công (chạy
Responder) **trả lời giả**: "B chính là tao". Máy A tin, kết nối SMB tới kẻ tấn công và bắt đầu
**chứng thực NTLM** — gửi đi bằng chứng mật khẩu.

**NTLMv2 — 3 bước thách-đáp (challenge-response):**
1. **NEGOTIATE (Type 1):** A → kẻ tấn công: "tôi muốn đăng nhập, hỗ trợ NTLM".
2. **CHALLENGE (Type 2):** kẻ tấn công → A: gửi **server challenge** (8 byte ngẫu nhiên).
3. **AUTHENTICATE (Type 3):** A → kẻ tấn công: gửi **NTLMv2 response** =
   HMAC-MD5 phức tạp của (hash mật khẩu, server challenge, client challenge, timestamp,
   target info). Kèm username/domain.

**Vì sao crack được offline:** kẻ tấn công có server challenge (do mình gửi) + NTLMv2 response.
Với một mật khẩu đoán `P`: tính NTLM hash của `P`, rồi tái tạo NTLMv2 response theo đúng công
thức; nếu trùng response bắt được → `P` đúng. hashcat `-m 5600` làm việc này trên GPU.

**NTProofStr vs blob:** NTLMv2 response = `NTProofStr(16 byte) || blob`. `NTProofStr` là HMAC
cuối cùng; `blob` chứa các "nguyên liệu" (timestamp, client challenge, target info) cần để tái
tạo. Cả hai cần cho crack.

**Phòng thủ (biết thêm):** tắt LLMNR/NBT-NS, bật SMB signing, dùng mật khẩu dài — khiến crack
offline bất khả thi.

## D.7 — Steganography & file carving: chữ ký định dạng

Dùng cho: **DR Congo**, **Tanzania** (JPEG+ZIP), và chung cho forensics.

**Nguyên lý "dữ liệu nối đuôi":** nhiều định dạng có **marker kết thúc** rõ ràng; trình đọc
dừng ở đó và bỏ qua phần sau. Nên có thể "dán" file khác vào đuôi mà vẫn mở được bình thường:
- JPEG: bắt đầu `FF D8 FF`, kết thúc `FF D9`.
- PNG: bắt đầu `89 50 4E 47 0D 0A 1A 0A`, kết thúc chunk `IEND`.
- ZIP: local header `50 4B 03 04` (`PK\x03\x04`); end-of-central-directory `50 4B 05 06`.
- GZIP: `1F 8B`. PDF: `%PDF` ... `%%EOF`.

**Carving:** quét file tìm chữ ký của định dạng nhúng rồi cắt ra. `binwalk` tự nhận diện hàng
chục chữ ký; `foremost`/`scalpel` carve theo header/footer; hoặc tay:
```python
data = open("img.jpg","rb").read()
i = data.find(b"PK\x03\x04")       # tìm ZIP nhúng
open("out.zip","wb").write(data[i:])
```

**Nơi giấu khác:** EXIF/XMP (metadata ảnh), LSB (bit thấp của pixel — cần `zsteg`/`stegsolve`),
phổ âm thanh (spectrogram — bài Germany). Checklist forensics ảnh: `file` → `strings` →
`exiftool` → `binwalk` → (nếu nghi LSB) `zsteg`/`stegsolve`.

## D.8 — Mật mã cổ điển: Caesar, Vigenère, và cách tấn công

Dùng cho: **DR Congo** (Vigenère), và nền tảng crypto cổ điển.

**Caesar:** dịch mọi chữ cái một lượng cố định `k`. `C=(P+k) mod 26`. Chỉ 25 khóa → thử hết
("brute 25") là ra. ROT13 là Caesar với k=13.

**Vigenère:** dùng **từ khóa** nhiều chữ, mỗi chữ của khóa là một lượng dịch khác nhau, lặp
tuần hoàn. `C[i]=(P[i]+K[i mod m]) mod 26` với `m`=độ dài khóa. Mạnh hơn Caesar vì cùng một chữ
plaintext có thể ra nhiều ciphertext khác nhau (tùy vị trí).

**Tấn công Vigenère:**
1. **Known-plaintext (dễ nhất, dùng ở bài này):** biết một đoạn plaintext (ví dụ `CSG_FLAG`)
   và ciphertext tương ứng → tính khóa trực tiếp `K[i]=(C[i]-P[i]) mod 26`.
2. **Kasiski / Friedman:** đoán độ dài khóa `m` bằng khoảng cách lặp của các cụm giống nhau,
   hoặc chỉ số trùng hợp (Index of Coincidence).
3. **Phân tích tần suất theo cột:** chia ciphertext thành `m` nhóm (mỗi nhóm cùng một chữ
   khóa), rồi mỗi nhóm giải như Caesar bằng tần suất chữ cái.

Công cụ: dcode.fr (Vigenère automatic/known-plaintext), CyberChef (Vigenère Decode).

---

## Phụ lục E — Checklist giải nhanh theo loại đề (rút kinh nghiệm từ giải này)

**Gặp file text lạ (chỉ `.`/`-`, hoặc base64, hoặc `U+`):**
1. `.`/`-` đều, không khoảng cách → thử Baudot/ITA2 trước Morse (bài C6).
2. Toàn ký tự base64, dài, bội số 4 → decode; nếu vẫn base64 → decode tiếp (bài Angola).
3. Toàn `U+HHHH` → đổi codepoint sang ký tự (bài Angola).

**Gặp ảnh (JPEG/PNG):**
1. `file` → `strings` → `exiftool` → `binwalk` (bài DR Congo, Tanzania).
2. ZIP nhúng? carve `PK\x03\x04`. ZIP có mật khẩu? tìm hint trong metadata.
3. ZIP báo "unsupported" → là AES ZIP → dùng 7-Zip/pyzipper (bài Tanzania).

**Gặp exe/binary:**
1. `file` nhận ra PE? Nếu "data" → header hỏng, so magic `MZ` (bài Saudi).
2. Go binary? tìm `main.*`, trích global key/ciphertext (bài Sweden).
3. Packer? tìm blob + hàm giải mã, tự decrypt, verify `MZ`/`PE\0\0` (bài Greece).
4. **Không chạy binary lạ** — ưu tiên phân tích tĩnh.

**Gặp pcap:**
1. Protocol Hierarchy để biết có gì (SIP/RTP? SMB/NTLMSSP? NBNS?).
2. VoIP → xác định codec từ SDP, ráp RTP, giải audio, xem spectrogram (bài Germany).
3. NBNS+SMB+NTLMSSP → NTLMv2 capture, rút 5 trường cho `-m 5600` (bài Switzerland).

**Gặp web/script (HTML/HTA/PHP):**
1. Đọc source, tìm hàm kiểm tra (crackme) hoặc `eval` lồng nhau.
2. Obfuscation → bóc tĩnh (thay `eval`→`echo`, hoặc CyberChef) — không chạy (bài R6).
3. MD5 crackme → tách phần, brute/hashcat (bài Zambia).

*(Hết Phụ lục.)*

---

# Phụ lục F — Đọc code solver từng dòng (các script phức tạp)

> Hai script khó nhất của giải được giải thích **từng dòng** ở đây. Hiểu được chúng là hiểu
> được bản chất parse nhị phân (NTLM) và brute biến thể (ITA2).

## F.1 — `analyze_pcap.py` (Switzerland): parse NTLMSSP từ gói SMB

Đoạn lõi trích NTLMv2 từ payload nhị phân:

```python
signature = b"NTLMSSP\x00"          # (1) mọi bản tin NTLM bắt đầu bằng chuỗi này
i = payload.find(signature)         # (2) tìm vị trí bắt đầu khối NTLM trong gói SMB
```
- **(1)** `NTLMSSP\0` là "magic" 8 byte của khối NTLM, luôn đứng đầu Type 1/2/3.
- **(2)** `payload` là phần dữ liệu TCP của gói SMB; `find` cho offset `i` của khối NTLM.

```python
mtype = int.from_bytes(payload[i+8:i+12], "little")   # (3) MessageType ngay sau magic
```
- **(3)** 4 byte tại `i+8` là **MessageType** (little-endian): 1=NEGOTIATE, 2=CHALLENGE,
  3=AUTHENTICATE. Đây là cách phân loại bản tin.

```python
if mtype == 2:                                        # (4) CHALLENGE từ "server"
    server_challenge = payload[i+24:i+32].hex()       # (5) 8 byte server challenge
```
- **(4)(5)** Trong Type 2, **server challenge** nằm cố định ở byte 24–32 (kể từ magic). Đây
  là 16 hex đầu trong flag.

```python
elif mtype == 3:                                      # (6) AUTHENTICATE từ "client"
    def get_field(off):                               # (7) đọc một "security buffer"
        flen = int.from_bytes(payload[i+off:i+off+2], "little")      # Len (2 byte)
        foff = int.from_bytes(payload[i+off+4:i+off+8], "little")    # Offset (4 byte)
        return payload[i+foff : i+foff+flen]          # (8) cắt dữ liệu thật
    dom  = get_field(28)   # DomainName   (fields @ offset 28)
    user = get_field(36)   # UserName     (fields @ offset 36)
    ntresp = get_field(20) # NT response  (fields @ offset 20) <- NTLMv2
```
- **(6)** Type 3 chứa danh tính + bằng chứng.
- **(7)(8)** Mỗi trường trong NTLM là một "security buffer" 8 byte: `Len(2) MaxLen(2)
  Offset(4)`, trong đó `Offset` trỏ tới dữ liệu thật **ở nơi khác** trong khối. Hàm
  `get_field` đọc `Len` và `Offset` rồi cắt đúng đoạn. Bảng offset các trường (28=Domain,
  36=User, 20=NT response) là theo chuẩn MS-NLMP.

```python
    user   = ntresp... ; ntproof = ntresp.hex()[:32] ; blob = ntresp.hex()[32:]
```
- **NTLMv2 response** = `NTProofStr (16 byte = 32 hex)` + `blob (phần còn lại = 620 hex)`.
  Ghép 5 phần `user::domain:server_challenge:ntproof:blob` ra flag / dòng hashcat `-m 5600`.

**Vì sao dùng string decode `utf-16le`:** Windows lưu username/domain ở dạng UTF-16 little-
endian (mỗi ký tự 2 byte). `b.decode("utf-16le")` đổi `b'b\x00o\x00b\x00'` → `"bob"`.

## F.2 — `solve.py` (C6): chọn đúng 1 trong 4 biến thể ITA2

```python
def bits_from_stream(stream, dot_as, dash_as, reverse_chunk):
    b = stream.replace('.', dot_as).replace('-', dash_as)   # (1) . và - -> '0'/'1'
    if reverse_chunk:                                        # (2) đảo thứ tự 5 bit/nhóm
        return ''.join(b[k:k+5][::-1] for k in range(0, len(b)-len(b)%5, 5))
    return b[:(len(b)//5)*5]                                 # (3) cắt cho chia hết 5
```
- **(1)** `dot_as`/`dash_as` là `'1'`/`'0'` hoặc `'0'`/`'1'` tùy biến thể — vì ta không biết
  quy ước. **(2)** `reverse_chunk` xử lý nhập nhằng MSB/LSB-first. **(3)** bỏ bit dư cuối.

```python
def ita2_force_letters(bits):
    return ''.join(ITA2_LTRS.get(int(bits[i:i+5], 2), '')   # (4) mỗi 5 bit -> 1 ký tự
                   for i in range(0, len(bits), 5))
```
- **(4)** `int(bits[i:i+5], 2)` đổi nhóm 5 bit sang số 0–31, tra bảng LETTERS. "force
  letters" nghĩa là **ép** dùng bảng LETTERS (bỏ qua shift FIGS) — hợp lệ vì nội dung bài chỉ
  gồm chữ cái.

```python
def swedish_words_to_letters(text):
    words = [w for w in re.split(r'[^A-Za-zÅÄÖ]+', text) if w]   # (5) tách thành từ
    return ''.join(SWE[w.upper()] for w in words if w.upper() in SWE)  # (6) từ -> chữ đầu
```
- **(5)(6)** Cắt text ITA2 thành từ, mỗi từ hợp lệ (có trong bảng Thụy Điển) → lấy chữ cái
  tương ứng. Từ rác (không khớp bảng) bị bỏ.

```python
def choose_best(stream):
    variants = [('1','0',False),('1','0',True),('0','1',False),('0','1',True)]  # (7) 4 biến thể
    best, best_letters = -1, ''
    for da, ha, rev in variants:
        letters = swedish_words_to_letters(ita2_force_letters(bits_from_stream(stream,da,ha,rev)))
        if len(letters) > best:                 # (8) chấm điểm = số chữ hợp lệ
            best, best_letters = len(letters), letters
    return best_letters
```
- **(7)** 4 tổ hợp (dot=1/0 × đảo/không). **(8)** biến thể nào cho **nhiều chữ Thụy Điển hợp
  lệ nhất** → đúng. Đây là "tự chọn biến thể" — tránh phải thử tay.

```python
flag = (letters.replace('UNDERSCORE','_')
               .replace('OPENINGBRACE','{').replace('CLOSINGBRACE','}'))  # (9) chuẩn hóa token
```
- **(9)** Lớp cuối: đổi các token chữ (do bảng Thụy Điển ghép ra) thành ký hiệu thật.

**Tóm tắt luồng 3 lớp:** `.`/`-` → (ITA2 5-bit) → tên Thụy Điển → (bảng chính tả) → chữ cái →
(chuẩn hóa token) → flag. Mỗi lớp giải một kiểu mã khác nhau — đó là cái "khó dễ chịu" của bài.

## F.3 — `extract_decode.py` (France): vì sao sinh nhiều biến thể rồi auto-decode

```python
stack = np.stack(arrs, axis=0)                  # (1) chồng 4 ảnh thành mảng 3D
variants.append(np.median(stack, axis=0))       # (2) trung vị theo pixel
variants.append(np.max(stack, axis=0))          # (3) sáng nhất
variants.append(np.min(stack, axis=0))          # (4) tối nhất
xor_all = arrs[0]
for a in arrs[1:]: xor_all = np.bitwise_xor(xor_all, a)   # (5) XOR dồn 4 ảnh
```
- **(1)** `arrs` là 4 ảnh xám (2D); `stack` thành (4, H, W). **(2–5)** các toán tử tổ hợp
  khác nhau — mỗi toán tử "khử" nhiễu share theo một cách; chỉ cần 1 cái phục hồi QR.

```python
det = cv2.QRCodeDetector()
for p in variant_paths:
    data, pts, _ = det.detectAndDecode(cv2.imread(str(p)))   # (6) thử giải QR mọi biến thể
    if data: print("DECODED:", data)                         # (7) in URL khi thành công
```
- **(6)(7)** Brute toàn bộ biến thể qua detector; biến thể nào ra chuỗi khác rỗng → đó là QR
  đã phục hồi, `data` là URL S3. Cách "sinh nhiều + thử hết" tránh phải đoán đúng công thức
  tổ hợp ngay từ đầu.

---

*(Hết toàn bộ tài liệu. Tổng cộng 14 challenge + 5 phụ lục kỹ thuật.)*
