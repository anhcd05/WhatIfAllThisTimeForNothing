# HƯỚNG DẪN: Đọc/Parse File Nhị Phân & Giải Mã (Reverse / Forensics)

**Cyber SEA Game 2026** — Bộ template + hướng dẫn cho mảng RE/Forensics.

Thư mục: `resources/templates/`
- `tmpl_fileparse.py` — đọc & phân tích file nhị phân (hexdump, magic, PE, ELF, XOR, trích blob).
- `tmpl_decrypt.py` — giải mã (XOR, RC4, AES, base64/32/16, ROT/Caesar, đảo byte).
- `GUIDE_fileparse_decrypt.md` — tài liệu này.

---

## 1. Khi nào dùng?

| Tình huống | Dùng gì |
|---|---|
| Có 1 file lạ, chưa biết là gì | `tmpl_fileparse.py` → `identify_magic`, `hexdump`, `scan_known_magics` |
| Nghi có file nhúng (zip/png/exe bên trong) | `scan_known_magics` + `carve_to_file` |
| Cần xem imports/sections/resource của .exe/.dll | `parse_pe`, `pe_get_section_data`, `pe_dump_resources` |
| Phân tích binary Linux | `parse_elf_struct` hoặc `parse_elf_pyelftools` |
| Chuỗi/flag bị XOR | `xor_brute_single`, `xor_known_plaintext`, `xor_repeating` |
| Dữ liệu mã hóa RC4/AES | `tmpl_decrypt.py` → `rc4`, `aes_decrypt` |
| Blob base64/base32/hex | `b64_decode`, `b32_decode`, `b16_decode` |
| Text bị ROT13/Caesar | `rot13`, `caesar_brute` |
| Dữ liệu sai thứ tự byte/endian | `reverse_bytes`, `swap_endian` |

Nguyên tắc chung: **quan sát trước (hexdump + magic + strings) → đoán cơ chế → thử giải mã**.

---

## 2. Cài đặt

```bash
pip install pefile pycryptodome pyelftools
```

- `pefile` — parse file PE (Windows).
- `pycryptodome` — RC4 (ARC4), AES (ECB/CBC/CTR). Import là `Crypto.Cipher`.
- `pyelftools` — parse ELF (tùy chọn; `tmpl_fileparse.py` đã có bản ELF thuần `struct`, không cài vẫn chạy được).

> Lưu ý: KHÔNG cài `pycrypto` (bản cũ, đã bỏ). Phải là `pycryptodome`.

---

## 3. Hai template làm gì?

### `tmpl_fileparse.py`
- **PHẦN 0** — `read_file`, `hexdump`, `carve`, `carve_to_file`.
- **PHẦN 1** — `unpack_int`, `unpack_many` (struct LE/BE), `demo_struct`.
- **PHẦN 2** — `identify_magic`, `find_all`, `scan_known_magics` (bảng `MAGIC_SIGNATURES`).
- **PHẦN 3** — `parse_pe`, `pe_rva_to_offset`, `pe_get_section_data`, `pe_dump_resources`.
- **PHẦN 4** — `parse_elf_struct` (ELF32/64, LE/BE), `parse_elf_pyelftools`.
- **PHẦN 5** — `extract_strings`, `extract_base64_blobs`, `extract_hex_blobs`, `xor_bytes`, `xor_brute_single`, `xor_find_key_from_known`.

### `tmpl_decrypt.py`
- **PHẦN 1 (XOR)** — `xor_bytes`, `xor_brute_single`, `xor_repeating`, `xor_known_plaintext`.
- **PHẦN 2 (RC4)** — `rc4` (thuần Python), `rc4_pycrypto`.
- **PHẦN 3 (AES)** — `aes_decrypt` (ECB/CBC/CTR + unpad), `aes_encrypt` (để tạo test).
- **PHẦN 4 (Encoding)** — `b64_decode`, `b32_decode`, `b16_decode`, `rot13`, `caesar_brute`.
- **PHẦN 5 (Biến đổi)** — `reverse_bytes`, `swap_endian`.

---

## 4. Cách dùng từng bước

### Chạy nhanh từ dòng lệnh
```bash
# Phân tích tổng quát 1 file (magic + hexdump + quét magic + PE/ELF):
python tmpl_fileparse.py challenge.bin

# Chạy self-test bộ giải mã (xác nhận môi trường OK):
python tmpl_decrypt.py
```

### Dùng như thư viện (khuyến nghị cho bài thật)
```python
from tmpl_fileparse import read_file, hexdump, carve_to_file, parse_pe, pe_get_section_data
from tmpl_decrypt import aes_decrypt, rc4, xor_known_plaintext, b64_decode

data = read_file("challenge.bin")
hexdump(data, 128)                 # nhìn 128 byte đầu
```

Trong cả 2 file, tìm các dấu **`# TODO`** ở cuối `main()` — đó là chỗ bạn điền lời giải thật
(đường dẫn file, key, mode, offset...).

---

## 5. Giải thích từng phần quan trọng

### struct & endian
`struct.unpack("<I", b)` đọc uint32 **little-endian**; `">I"` là **big-endian**.
Ký tự: `B/H/I/Q` = uint 1/2/4/8 byte; chữ thường `b/h/i/q` = có dấu; `<` LE, `>` BE.
`4s` = 4 byte dạng chuỗi. Dùng `unpack_many(data, off, "<4sHI")` để đọc 1 record nhiều trường.

### Magic bytes
So khớp vài byte đầu file với bảng chữ ký (`MZ`, `\x7fELF`, `PK\x03\x04`, `%PDF`...).
`scan_known_magics` quét **toàn file** để phát hiện dữ liệu nhúng/nối thêm.

### PE (pefile)
- `sections`: mỗi section có `VirtualAddress` (RVA), `PointerToRawData` (offset file), entropy.
  Entropy ~7.9+ ⇒ nghi nén/mã hóa.
- `imports`: hàm được gọi ⇒ gợi ý chức năng (ví dụ `CryptDecrypt`, `WinHttp*`).
- `RVA → offset`: `pe.get_offset_from_rva(rva)` để đọc byte tại 1 địa chỉ ảo.
- `.data/.rdata`: `pe_get_section_data(pe, ".rdata")` lấy vùng hay chứa chuỗi/khóa.
- Resource: payload hay bị giấu trong `.rsrc` ⇒ `pe_dump_resources`.

### ELF
`parse_elf_struct` đọc `e_ident` (class 32/64, endian), rồi ELF header và bảng section,
dùng section `.shstrtab` để lấy **tên** các section. Không cần cài thêm gì.

### XOR
- 1 byte: `xor_brute_single` thử 256 key, chấm điểm theo tỉ lệ ký tự in được.
- Nhiều byte (key lặp): `xor_repeating(data, b"KEY")`.
- Known-plaintext: `key = cipher XOR plaintext`. Nếu biết 1 đoạn plaintext (header file,
  tiền tố flag) đủ dài bằng chu kỳ key ⇒ giải được cả file.

### RC4 / AES
- RC4 đối xứng: dùng `rc4(data, key)` cho cả mã hóa lẫn giải mã.
- AES: chọn đúng **mode** (ECB/CBC/CTR), đúng **key length** (16/24/32), đúng **IV/nonce**,
  rồi **unpad** PKCS7 (ECB/CBC). `aes_decrypt` mặc định coi 16 byte đầu ciphertext là IV cho CBC.

---

## 6. Ví dụ: trích blob trong PE rồi AES-decrypt

Kịch bản điển hình: payload được nhét trong section `.rdata` của 1 file PE, mã hóa AES-CBC,
IV ghép ở đầu, key là chuỗi 16 byte đã tìm được (từ strings/disasm).

```python
from tmpl_fileparse import parse_pe, pe_get_section_data
from tmpl_decrypt import aes_decrypt

# 1) Parse PE và lấy dữ liệu section chứa payload
pe = parse_pe("sample.exe", verbose=False)
blob = pe_get_section_data(pe, ".rdata")        # hoặc ".data"

# 2) Cắt đúng đoạn ciphertext trong section (offset/độ dài tìm được khi quan sát)
#    (ví dụ payload bắt đầu tại 0x40, dài 0x80 byte trong section)
cipher = blob[0x40:0x40 + 0x80]                 # TODO: chỉnh offset/length cho đúng bài

# 3) Giải mã AES-CBC (IV nằm ở 16 byte đầu của cipher -> để iv=None)
key = b"0123456789abcdef"                        # TODO: thay bằng key thật (16/24/32 byte)
plain = aes_decrypt(cipher, key, mode="CBC", iv=None)
print(plain)
```

Nếu đề cho ciphertext **base64** thay vì nhúng nhị phân:
```python
from tmpl_decrypt import b64_decode, aes_decrypt
cipher = b64_decode("U2FsdGVkX1....")            # decode trước
print(aes_decrypt(cipher, b"<key>", "CBC"))
```

> Mẹo: nếu không chắc mode, thử lần lượt ECB → CBC → CTR và nhìn kết quả có ra text/flag không.

---

## 7. Cạm bẫy (đọc kỹ trước khi "bó tay")

- **Endian**: `01 02 03 04` là `0x04030201` (LE) hay `0x01020304` (BE). Thử cả hai (`<`/`>`).
- **Padding (PKCS7)**: ECB/CBC thường có padding ⇒ phải `unpad`. Nếu `unpad` lỗi ⇒ **sai key/IV**
  (hoặc dữ liệu vốn không có padding ⇒ đặt `unpad_result=False`). CTR/stream **không** padding.
- **Key length AES**: phải đúng 16/24/32 byte. Chuỗi thiếu/thừa 1 ký tự là sai ngay.
  Coi chừng ký tự ẩn (newline `\n`, null) dính vào key.
- **IV**: CBC bắt buộc IV 16 byte. IV hay nằm ở đầu ciphertext, hoặc là toàn `\x00`, hoặc cho riêng.
- **Nonce/counter CTR**: sai nonce ⇒ ra rác. Thử nonce rỗng (counter từ 0) trước.
- **base64 padding**: thiếu `=` ⇒ lỗi "Incorrect padding". `b64_decode` ở template đã tự vá.
  Phân biệt base64 chuẩn (`+ /`) và urlsafe (`- _`).
- **Signed vs unsigned**: khi so sánh/tính toán, byte trong Python là 0..255 (unsigned). Khi dùng
  struct, chọn đúng chữ hoa (unsigned) / thường (signed) kẻo lệch dấu.
- **Encode key/IV**: nếu đề cho key dạng **hex** thì phải `bytes.fromhex(...)`, đừng encode thẳng
  chuỗi hex thành ASCII.
- **`pycrypto` cũ**: phải cài `pycryptodome`, không phải `pycrypto`.
- **An toàn**: template chỉ **đọc bytes**, tuyệt đối không exec binary mẫu. Phân tích động chỉ
  làm trong **Kali VM/sandbox** cách ly, không trên host.

---

## 8. Tham khảo

- Python `struct`: https://docs.python.org/3/library/struct.html
- Python `base64`: https://docs.python.org/3/library/base64.html
- `pefile`: https://github.com/erocarrera/pefile
- `pycryptodome` (Crypto.Cipher): https://pycryptodome.readthedocs.io/
- `pyelftools`: https://github.com/eliben/pyelftools
- File signatures / magic numbers: https://en.wikipedia.org/wiki/List_of_file_signatures
- Định dạng PE: https://learn.microsoft.com/windows/win32/debug/pe-format
- Định dạng ELF (`man 5 elf`): https://man7.org/linux/man-pages/man5/elf.5.html
