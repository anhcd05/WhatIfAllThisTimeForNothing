# HANDOUT — Bộ brute-force hash (C + Python)

Tài liệu dùng nhanh khi thi. Bộ công cụ tìm chuỗi gốc từ 1 giá trị hash (md4/md5/sha1/sha224/sha256/sha384/sha512), thuần C (không cần thư viện) + 1 bản Python.

---

## 0. Có gì trong bộ này

```
resources/
├─ HANDOUT.md                ← file này
├─ README_brute.md           ← mô tả bản đơn giản
├─ brute_md4.c ... brute_sha512.c   ← 7 file ĐƠN GIẢN (1 luồng, dễ đọc/sửa)
└─ optimized/
   ├─ README_fast.md
   ├─ fast_md4.c ... fast_sha512.c  ← 7 file TỐI ƯU (đa luồng OpenMP, nhanh)
   ├─ fast_crc32.c                  ← brute CRC32 (checksum)
   └─ brute_all.py                  ← Python, 1 file lo mọi thuật toán (+crc32, +ntlm)
```

**Nên dùng bản nào?**
- Cần **nhanh** → `optimized/fast_<algo>.c` (biên dịch kèm `-fopenmp`).
- Cần **đọc/sửa logic** → `brute_<algo>.c` (bản đơn giản).
- Cần **gõ 1 dòng ra ngay**, hoặc thuật toán lạ → `optimized/brute_all.py`.

---

## 1. Chuẩn bị (kiểm tra 1 lần trên máy thi)

```bash
gcc --version          # cần có GCC (MinGW-w64 / w64devkit / Strawberry trên Windows; có sẵn trên Kali)
python --version       # Windows thường là 'python'
python3 --version      # Kali/Linux là 'python3'
```

- **Windows không có gcc?** Cài MinGW-w64 / w64devkit (được phép — thuộc "libraries/dependencies/packages"),
  HOẶC biên dịch & chạy trên **Kali VM** (có sẵn gcc + python3).
- Dưới đây dùng `python`; trên Kali thay bằng `python3`.

---

## 2. Ba tham số cần sửa (GIỐNG NHAU ở mọi file)

Mở file, sửa khối CẤU HÌNH ở đầu:

```c
#define WANTED_HASH "d974e538cf501afdfc3986041c5a3993"   // hash cần tìm (chuỗi hex)
#define CHARSET     "ABCDEFabcdef0123456789"             // tập ký tự thử
#define LEN         6                                    // độ dài chuỗi
```
(Python cũng có đúng 3 dòng này, chỉ khác cú pháp: `WANTED_HASH = "..."`)

**Chọn CHARSET theo đề thường gặp:**
| Kiểu | CHARSET |
|---|---|
| Chữ số | `0123456789` |
| Hex thường | `0123456789abcdef` |
| Hex HOA | `0123456789ABCDEF` |
| Chữ thường | `abcdefghijklmnopqrstuvwxyz` |
| Chữ + số | `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789` |

---

## 3. Dùng bản C — biên dịch bằng GCC

> ⚠️ **Biên dịch NGAY trên máy thi, đừng mang `.exe` sẵn** (`-march=native` gắn với CPU máy biên dịch).

### Bản TỐI ƯU (nhanh — có OpenMP)  → thư mục `optimized/`
```bash
gcc -O3 -march=native -fopenmp fast_sha256.c -o fast_sha256
./fast_sha256
```
Biên dịch cả bộ một lần:
```bash
for a in md4 md5 sha1 sha224 sha256 sha384 sha512; do
  gcc -O3 -march=native -fopenmp fast_$a.c -o fast_$a
done
```

### Bản ĐƠN GIẢN (1 luồng) → thư mục `resources/`
```bash
gcc -O2 brute_sha256.c -o brute_sha256
./brute_sha256
```

**Ý nghĩa cờ gcc:** `-O3`/`-O2` = tối ưu; `-march=native` = dùng lệnh riêng của CPU máy này;
`-fopenmp` = bật đa luồng (BẮT BUỘC cho các file `fast_*`).

> Trên Windows, lệnh chạy có thể là `fast_sha256.exe` thay vì `./fast_sha256` — cả hai đều được trong Git Bash.

---

## 4. Dùng bản Python — chạy bằng python3

Một file lo mọi thuật toán (`optimized/brute_all.py`):

```bash
# Cách 1: sửa 3 dòng CẤU HÌNH trong file rồi chạy
python  brute_all.py          # Windows
python3 brute_all.py          # Kali/Linux

# Cách 2: truyền nhanh thuật toán + hash qua tham số (khỏi sửa file)
python brute_all.py sha256 0abefe1fb88827bb302fcbc086a416cb7d8f3536ed2150bf5dbefceace8d2335
python brute_all.py md5    d974e538cf501afdfc3986041c5a3993
```
(CHARSET và LEN vẫn lấy trong file — sửa 2 dòng đó nếu cần.)

**`brute_all.py` chạy được mọi thuật toán của hashlib** (khỏi viết thêm C):
`md5 sha1 sha224 sha256 sha384 sha512 sha3_224/256/384/512 blake2b blake2s ripemd160 sm3 shake_128/256`
+ 2 loại đặc biệt `crc32` và `ntlm`:
```bash
python brute_all.py sha3_256 <hash>
python brute_all.py ripemd160 <hash>
python brute_all.py crc32  c760632c
python brute_all.py ntlm   6ac60e98c312cfeea50bea7111b9a1f5
```
> `md4` KHÔNG có trong hashlib → dùng bản C `fast_md4.c`.
> `ntlm` ở đây dùng MD4 thuần Python nên **chậm** — crack NTLM thật sự nên dùng `hashcat -m 1000` (xem Phụ lục B).

---

## 5. GCC hay Python3? Khi nào dùng cái nào

| Tình huống | Dùng |
|---|---|
| Không gian lớn / cần nhanh nhất | **C `fast_*` + gcc -fopenmp** |
| Gõ 1 phát ra ngay, đổi algo liên tục | **Python `brute_all.py`** |
| Thuật toán C chưa có (vd ripemd, blake2...) | **Python** (hashlib hỗ trợ sẵn nhiều loại) |
| Máy không cài được gcc | **Python** |
| Muốn hiểu/sửa thuật toán | **C bản đơn giản** |

Tốc độ tham khảo (113M tổ hợp, máy ~12 nhân): C ~0.1–1s, Python ~5s. C nhanh hơn ~6–11×.

---

## 6. Ví dụ đầy đủ (1 bài thực tế)

Đề cho hash MD5 `d974e538cf501afdfc3986041c5a3993`, đoán 6 ký tự gồm chữ cái hex + số.

```bash
cd resources/optimized
# 1) sửa 3 dòng trong fast_md5.c:
#    WANTED_HASH "d974e538cf501afdfc3986041c5a3993"
#    CHARSET     "ABCDEFabcdef0123456789"
#    LEN         6
# 2) biên dịch + chạy:
gcc -O3 -march=native -fopenmp fast_md5.c -o fast_md5
./fast_md5
# -> FOUND: Dec0d3
```
Nếu không chắc độ dài: thử `LEN=4`, rồi `5`, rồi `6`... (mỗi lần tăng độ dài, số tổ hợp ×(số ký tự)).

**Ước lượng thời gian:** `thời_gian ≈ (số_ký_tự ^ LEN) / tốc_độ`.
Ví dụ charset 22, C md5 ~255 M/s: LEN=6 → 113M/255M ≈ 0.4s; LEN=7 → ×22 ≈ 10s; LEN=8 → ~3–4 phút.
Dài hơn nữa: thu hẹp charset, hoặc xem lại hướng giải (có thể không phải brute).

---

## 7. Lỗi hay gặp & cách xử lý

| Triệu chứng | Nguyên nhân / cách sửa |
|---|---|
| `gcc: command not found` | Chưa có GCC → cài MinGW-w64, hoặc compile trên Kali |
| `undefined reference to omp_*` / không nhanh | Thiếu `-fopenmp` khi biên dịch file `fast_*` |
| `#error "1-block: LEN phai <= 55"` | `LEN` vượt giới hạn 1 khối (SHA-512/384 là 111). Giảm LEN. |
| In `Khong tim thay` | Sai CHARSET/LEN, hoặc chuỗi không nằm trong không gian đã thử. Mở rộng charset/tăng LEN. |
| Python báo algo không dùng được (vd md4) | Bản Python thiếu thuật toán đó → dùng file C `fast_md4.c` |
| Hash hex sai độ dài | Mỗi byte = 2 ký tự hex: md5/md4=32, sha1=40, sha224=56, sha256=64, sha384=96, sha512=128 |

---

## 8. Giới hạn & nhắc luật

- **LEN tối đa (1 khối):** md4/md5/sha1/sha224/sha256 = **55**; sha384/sha512 = **111**.
- Flag giải theo mẫu `CSG_FLAG{...}` (nộp cả `CSG_FLAG{ }` trên CTFd) — khác với output của tool này (chỉ là chuỗi gốc).
- ⚠️ **Luật giải cấm Generative AI (Claude/ChatGPT...) trong lúc thi, màn hình bị giám sát.**
  Bộ script này hợp lệ vì là **"scripts created before the competition"** mang vào làm đồ nghề.
  **KHÔNG chạy AI trong lúc thi.**

---

## Phụ lục A — Giải thích các cờ GCC

Cú pháp chung: `gcc [cờ...] file.c -o tên_ra` — thứ tự cờ không quan trọng, đặt đâu cũng được.
Nếu chỉ `gcc file.c` (không `-o`) thì gcc tự đặt tên `a.exe` (Windows) / `a.out` (Linux).

| Cờ | Làm gì | Khi nào dùng |
|---|---|---|
| `-o tên` | Đặt **tên file chương trình** xuất ra | Luôn dùng (cho dễ gọi) |
| `-O0` | **Không** tối ưu (mặc định nếu không ghi `-O`) | Khi debug, muốn biên dịch nhanh |
| `-O2` | Tối ưu **cân bằng** (nhanh, ổn định) | Mặc định nên dùng cho mọi chương trình |
| `-O3` | Tối ưu **mạnh nhất** (inline nhiều, tự vector hóa) | Code tính toán nặng như brute-force |
| `-march=native` | Cho phép dùng **mọi tập lệnh CPU của MÁY NÀY** (AVX2, BMI2...) → nhanh hơn | Compile **trên chính máy sẽ chạy**. ⚠️ binary có thể KHÔNG chạy trên CPU khác → đừng mang `.exe` sang máy khác |
| `-fopenmp` | **Bật đa luồng OpenMP**: biến `#pragma omp` thành chạy nhiều nhân + link thư viện OpenMP | **BẮT BUỘC** cho các file `fast_*` (thiếu nó → pragma bị bỏ qua → chạy 1 luồng, chậm ~10×) |
| `-static` | **Gộp thư viện vào exe** → chạy độc lập, không cần `.dll` | ⚠️ **KHÔNG dùng chung với `-fopenmp`** trên MinGW (lỗi `undefined reference to dlopen`). Chỉ dùng cho bản **1 luồng** |
| `-Wall -Wextra` | Bật **cảnh báo** của compiler (bắt lỗi code sớm) | Khi tự viết/sửa code, muốn chắc ăn |
| `-g` | Kèm **thông tin debug** để chạy với `gdb` | Khi cần debug bằng gdb |
| `-mavx2` | Bật **riêng AVX2** (không gom hết như `-march=native`) | Khi muốn binary chạy được trên nhiều CPU miễn là có AVX2 |
| `-std=c11` | Chọn **chuẩn ngôn ngữ C** (C11) | Nếu gcc báo lỗi cú pháp do chuẩn quá cũ (hiếm) |

**Tóm tắt cho bộ này:**
- File `fast_*.c` (tối ưu): `gcc -O3 -march=native -fopenmp file.c -o ten`
  → `-O3` (tối ưu mạnh) + `-march=native` (tận dụng CPU) + `-fopenmp` (đa luồng).
- File `brute_*.c` (đơn giản): `gcc -O2 file.c -o ten` → không cần `-fopenmp` vì không có OpenMP.
- **Đóng gói exe trên Windows/MinGW** (⚠️ `-static` + `-fopenmp` KHÔNG build được — lỗi `dlopen`):
  - Chuẩn nhất: **không cần `-static`** — exe `fast_*` chỉ cần `libgomp-1.dll` trên PATH (đã có sẵn cùng gcc).
  - Copy exe sang máy khác (vẫn đa luồng): chép 3 DLL `libgomp-1.dll`, `libwinpthread-1.dll`, `libgcc_s_seh-1.dll` (trong `bin` của MinGW) đặt **cạnh exe**.
  - Muốn 1 file duy nhất, chấp nhận 1 luồng: `-static` **bỏ `-fopenmp`** → `gcc -O3 -mavx2 -static file.c -o ten`.

**Ghi nhớ:** `-O3` làm chương trình **chạy** nhanh (không phải **biên dịch** nhanh). Brute-force cần tốc độ chạy → luôn bật.

---

## Phụ lục B — Khi nào dùng john / hashcat (có sẵn trên Kali)

Bộ script này để brute **preimage của hash NHANH** (md/sha/crc/ntlm). Với **mật khẩu & hash CHẬM**
(bcrypt, shadow, zip, office, pdf...), dùng **john**/**hashcat** + **wordlist** — KHÔNG brute toàn charset.

Wordlist hay dùng: `/usr/share/wordlists/rockyou.txt` (nếu nén: `gunzip rockyou.txt.gz`).

**hashcat:** `hashcat -m <mode> -a 0 hash.txt rockyou.txt`  (`-a 0` = wordlist, `-a 3` = mask brute)

| Hash | hashcat `-m` | john `--format=` |
|---|---|---|
| MD5 | 0 | raw-md5 |
| SHA1 | 100 | raw-sha1 |
| SHA256 / SHA512 | 1400 / 1700 | raw-sha256 / raw-sha512 |
| NTLM | 1000 | nt |
| NetNTLMv2 | 5600 | netntlmv2 |
| bcrypt `$2*$` | 3200 | bcrypt |
| md5crypt `$1$` | 500 | md5crypt |
| sha512crypt `$6$` (shadow) | 1800 | sha512crypt |
| ZIP (PKZIP / WinZip-AES) | 17200 / 13600 | (dùng `zip2john`) |
| RAR5 / 7-Zip | 13000 / 11600 | (`rar2john` / `7z2john`) |
| Office 2013+ | 9600 | office2john |
| PDF | 10700… | pdf2john |

**Rút hash từ file bằng `*2john` rồi crack:**
```bash
zip2john secret.zip > h.txt && john h.txt --wordlist=/usr/share/wordlists/rockyou.txt
office2john report.docx > h.txt && hashcat -m 9600 h.txt /usr/share/wordlists/rockyou.txt
```
**Mask brute khi biết format (vd 6 ký tự hex thường):**
```bash
hashcat -m 0 -a 3 hash.txt '?h?h?h?h?h?h'    # ?d=số ?l=a-z ?u=A-Z ?h=0-9a-f ?a=tất cả
```
> Không có GPU: hashcat chạy CPU vẫn ổn với hash nhanh (md/sha/ntlm) + wordlist.
> bcrypt/argon2/scrypt chậm → chỉ wordlist + rule (`-r rules/best64.rule`), đừng brute toàn bộ.
