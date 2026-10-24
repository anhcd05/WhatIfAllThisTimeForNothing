# jpeg-zip-stego

- **Category:** Forensics / Steganography (JPEG + ZIP polyglot, ZIP AES-256)
- **File đề:** `challenges/jpeg-zip-stego/image.jpg` (155076 byte, MD5 `49eba91dabfe6a77727415320636186f`), `description.txt`, `solve.py`

> Phân tích TĨNH toàn bộ: chỉ đọc byte của ảnh (xxd/strings/parse header), KHÔNG mở/chạy file, KHÔNG giải nén payload không tin cậy vào thư mục làm việc.

## Tóm tắt đề
`description.txt`: "You have obtained a certain image. It appears to be a normal JPEG, but something seems to be hidden within it. Analyze the file and extract the hidden flag."

Bản chất: một file **JPEG hợp lệ** nhưng ở **đuôi file** có **một archive ZIP nối thêm** (append). Entry trong ZIP là `flag.txt`, được **mã hóa AES-256** (WinZip AE-1), cần mật khẩu. Mật khẩu được ghép từ **3 token giấu trong EXIF** của ảnh: `P1`, `P2`, `P3`. Giải nén đúng mật khẩu ra `flag.txt`.

## Phân tích (chi tiết: khóa/offset/hằng số thật)

### 1. Cấu trúc file (offset thật, đã verify tĩnh)
- SOI (bắt đầu JPEG): offset `0x00000000`, byte `FF D8 FF E0` (JFIF). Đúng JPEG.
- EOI (kết thúc JPEG `FF D9`): offset **154608** (`0x25BF0`).
- Chữ ký ZIP local file header `PK\x03\x04`: offset **154610** (`0x25BF2`) — tức **ngay sau `FF D9` 2 byte**. Đây là dấu hiệu kinh điển của JPEG+ZIP polyglot: dữ liệu sau EOI bị trình xem ảnh bỏ qua nhưng công cụ ZIP vẫn đọc được từ cuối file.
- EOCD (End Of Central Directory, `PK\x05\x06`): offset **155054** (`0x25D2E`).
- Tổng kích thước: 155076 byte → phần ZIP = `155076 - 154610 = 466` byte.

### 2. Header ZIP cho thấy AES-256 (phân tích byte thật)
Dump 64 byte tại offset `0x25BF2`:
```
50 4b 03 04 14 00 01 00 63 00 f5 53 21 5b ...
```
Giải nghĩa local file header:
- `version needed` = 20 (2.0)
- `general purpose flag` = `0x0001` → **bit 0 = 1 = entry được mã hóa**.
- `compression method` = **99** (`0x0063`) → đây là mã đặc biệt "AE-x" (AES), **không phải Store/Deflate**. Phương thức nén thật nằm trong extra field.
- `file name length` = 8, `file name` = **`flag.txt`**.
- `extra field length` = 11, extra = `01 99 07 00 01 00 41 45 03 08 00`.

Giải mã extra field AES (`header id 0x9901`):
- id = `0x9901` (AES), data size = 7.
- AES vendor version = **1** → **AE-1**.
- vendor id = `"AE"`.
- **AES strength byte = `0x03` → AES-256** (0x01=128, 0x02=192, 0x03=256).
- actual compression method = **8 (Deflate)**.

=> Kết luận chắc chắn: ZIP dùng **AES-256 (WinZip AE-1)**. Hệ quả: `unzip` cổ điển và `zipfile` chuẩn của Python **không giải được** — phải dùng **7-Zip** hoặc **pyzipper** (hỗ trợ WinZip AES).

### 3. Mật khẩu giấu trong EXIF (token thật)
`strings`/đọc vùng EXIF (APP1, `FF E1 ... Exif\0\0`, byte order `MM` = big-endian) lộ:
- Mô tả ảnh: `The grand Reclining Buddha at Wat Pho, Bangkok.`
- Token 1 (ASCII, tag ImageDescription): **`P1=WATPHO`** tại offset ~164.
- Chuỗi phụ: `Temple of the Reclining Buddha`
- Token 2 + Token 3 được nhét dưới dạng **UTF-16** trong UserComment/XP tag, byte xen `\x00`:
  - `P\x002\x00=\x00R\x00E\x00C\x00L\x00I\x00N\x00I\x00N\x00G` → **`P2=RECLINING`**
  - `P\x003\x00=\x00B\x00U\x00D\x00D\x00H\x00A` → **`P3=BUDDHA`**
- Hướng dẫn ghép (nhúng ngay trong EXIF): `Combine tokens in order: P1-P2-P3 (uppercase, hyphen-separated).` và `Find EXIF tokens P1, P2, P3.`

Ghép theo đúng quy tắc (viết hoa, nối bằng `-`):
```
WATPHO-RECLINING-BUDDHA
```
(Chủ đề: Wat Pho — chùa Phật nằm ở Bangkok.)

*Vì sao P2/P3 "mất tích" khi grep `P2=`/`P3=`?* Vì chúng được lưu dạng UTF-16 (có byte `\x00` xen giữa), `strings` mặc định (ASCII) không bắt liền chuỗi. Phải đọc raw byte hoặc `strings -e l` (little/big-endian) hoặc `exiftool`.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Nhận diện polyglot JPEG+ZIP:** đề nói "hidden within it" + có byte sau `FF D9`. Tìm magic `PK\x03\x04` để xác định điểm bắt đầu ZIP. *Vì sao đáng tin:* trình xem ảnh dừng ở EOI nên không ai thấy ZIP; công cụ ZIP đọc từ EOCD ở cuối file nên vẫn mở được dù có "rác" (ảnh) ở đầu.
- **Carve bằng magic signature:** cắt từ offset `PK\x03\x04` đến hết file, lưu thành `.zip`. *Vì sao không cần dd thủ công:* đọc nguyên file rồi `data[idx:]` là đủ và chính xác tuyệt đối.
- **Phân biệt AES vs ZipCrypto:** đọc `compression method = 99` + extra `0x9901` strength `0x03`. *Vì sao quan trọng:* chọn sai công cụ (`unzip`) sẽ báo "unsupported compression method" và ta dễ tưởng nhầm sai mật khẩu.
- **Ghép mật khẩu từ nhiều mảnh metadata:** token chia 3 phần buộc người chơi gom đủ P1/P2/P3 và tuân quy tắc hoa + nối `-`. *Vì sao:* tăng độ khó mà không cần brute-force.

## Lời giải chi tiết (bước + code/lệnh sạch, chạy lại được)

### Bước 0 — Trinh sát tĩnh (không chạy file)
```bash
file image.jpg                 # JPEG image data
binwalk image.jpg              # thấy "Zip archive data, ... name: flag.txt" ở cuối
exiftool image.jpg             # đọc ImageDescription / UserComment -> P1,P2,P3
# đọc raw token kể cả UTF-16:
strings -n 3 -e S image.jpg | grep -E 'P[123]='   # -e S: single-byte
strings -n 3 -e l image.jpg | grep -E 'P[123]='   # -e l: UTF-16LE (bắt P2/P3)
```

### Bước 1 — Xác định offset ZIP + xác nhận AES (thuần Python, chỉ đọc byte)
```python
import struct
d = open("image.jpg","rb").read()
idx = d.find(b"PK\x03\x04")
print("ZIP offset:", idx, hex(idx))          # 154610 / 0x25bf2
method = struct.unpack("<H", d[idx+8:idx+10])[0]
print("method:", method)                      # 99 => AES
nlen = struct.unpack("<H", d[idx+26:idx+28])[0]
name = d[idx+30:idx+30+nlen]; print("name:", name)   # b'flag.txt'
extra = d[idx+30+nlen:idx+30+nlen+11]
print("AES strength:", extra[8])              # 3 => AES-256
```

### Bước 2 — Carve ZIP ra file riêng (để ở thư mục cách ly)
```python
from pathlib import Path
d = Path("image.jpg").read_bytes()
idx = d.find(b"PK\x03\x04")
assert idx != -1, "No ZIP signature"
Path("embedded.zip").write_bytes(d[idx:])     # 466 byte
```

### Bước 3 — Giải nén AES-256 bằng 7-Zip (hoặc pyzipper)
```bash
7z x -y -pWATPHO-RECLINING-BUDDHA embedded.zip -o./out
cat ./out/flag.txt
```
Tương đương thuần Python (không cần 7z ngoài, đọc được WinZip AES):
```python
import pyzipper
with pyzipper.AESZipFile("embedded.zip") as z:
    z.setpassword(b"WATPHO-RECLINING-BUDDHA")
    print(z.read("flag.txt").decode().strip())
```

### Bước 4 — Đọc flag
`flag.txt` chứa flag dưới đây.

## Flag
```
flag{Y0u-Are-Found-Hidd3n-Fi1e}
```
(Nguyên văn từ nguồn; "You Are Found Hidden File".)

## Gặp lại thì xử lý thế nào (playbook)
- **Nhận diện:** ảnh "bình thường" nhưng đề nói giấu gì đó; `file` nói JPEG nhưng kích thước lớn bất thường; `binwalk`/`file` thấy ZIP/RAR/7z sau ảnh; EXIF có token lạ.
- **Quy trình chuẩn:**
  1. `exiftool` + `strings -e S` + `strings -e l` (bắt cả UTF-16) để gom hint (tên tác phẩm, token `P1/P2/P3`, chuỗi ALL-CAPS). Ghép mật khẩu theo đúng quy tắc hint (hoa/thường, dấu nối).
  2. Tìm magic để carve: `PK\x03\x04` (ZIP), `Rar!\x1a\x07` (RAR), `7z\xBC\xAF\x27\x1C` (7z), `\x89PNG` (PNG nối). Cắt từ offset đó tới hết file.
  3. Đọc local header: `compression method == 99` + extra `0x9901` ⇒ **AES**; strength byte `01/02/03` = 128/192/256. Khi đó **dùng 7-Zip/pyzipper**, KHÔNG `unzip`.
  4. Nếu là ZipCrypto (method 8, flag bit 0, không có 0x9901) và không biết pass → `zip2john embedded.zip > h; john h`.
  5. Giải nén vào thư mục cách ly riêng, đọc flag.
- **Bẫy hay gặp:** (1) `unzip` không mở được AES ZIP rồi tưởng sai pass; (2) bỏ sót P2/P3 vì chúng là UTF-16 trong EXIF; (3) carve sai offset (lấy nhầm `PK\x05\x06` hoặc `PK\x01\x02`) → ZIP hỏng, phải dùng `PK\x03\x04` đầu tiên; (4) ghép sai quy tắc (quên viết hoa / quên dấu `-`).
- **Công cụ:** `exiftool`, `strings -e`, `binwalk`, `7z`, `pyzipper`, `zip2john`+`john`, `foremost`.
- **Checklist ngắn:** exiftool+strings lấy P1/P2/P3 → ghép pass (UPPER, `-`) → tìm `PK\x03\x04` → carve → đọc header xác nhận AES-256 → 7z/pyzipper giải nén → đọc flag.
