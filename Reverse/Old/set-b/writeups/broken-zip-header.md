# broken-zip-header

- **Category:** Forensic
- **File đề:** `broken-zip-header/365a1c80b6ac1c5b908a3fa2526a3535320684e1.zip` (286403 bytes; git blob sha1 `dac8687892049da0b8fa1c3cb3d4fd963859487e`; tên file là sha1). Bên trong (sau khi sửa) là `important.bmp` (368502 bytes).

## Tóm tắt đề

Đề cho một file ZIP **không giải nén được vì header hỏng** ("Broken Head"). Cần sửa header để lấy ra `important.bmp`, rồi phân tích ảnh để tìm flag.

```
$ unzip 365a1c80b6ac1c5b908a3fa2526a3535320684e1.zip
file #1:  bad zipfile offset (local header sig):  0
```

## Phân tích (chi tiết)

**Cấu trúc ZIP (PKZIP).** Mỗi file có một **Local File Header** bắt đầu bằng magic `50 4B 03 04` (`PK\x03\x04`), gồm các trường theo thứ tự: version, flags, compression method, mod time, **CRC-32**, **compressed size**, **uncompressed size**, **filename length**, **extra length**, rồi tới **filename** và dữ liệu. Cuối file có Central Directory (`PK\x01\x02`) và End of Central Directory (`PK\x05\x06`). Sửa sai một trường độ dài (như *filename length*) khiến parser đọc lệch toàn bộ → hỏng.

Soi hex đầu file:

```
00000000: dead beef 1400 0000 0000 e951 4f4d fd1b  ...........QOM..
00000010: 97f7 225e 0400 769f 0500 551f 0000 696d  .."^..v...U...im
00000020: 706f 7274 616e 742e 626d 70...           important.bmp...
```

Phát hiện **hai lỗi cố ý**:

1. **4 byte đầu là `DE AD BE EF`** thay cho magic ZIP. Sửa `DEADBEEF` → `50 4B 03 04` (`PK\x03\x04`).
2. Sau khi sửa magic, `unzip` vẫn lỗi (`filename too long--truncating`, `mismatching filename`, `bad CRC`). Dùng `zipdetails -v` thấy **Filename Length = `1F55` (8021)** — sai, vì tên thật `important.bmp` chỉ 13 ký tự. Giá trị quá lớn khiến "tên file" nuốt cả dữ liệu. Phải sửa Filename Length (offset `0x1A`, little-endian byte `55 1F`) về **`0D 00` (= 13)**.

`zipdetails` còn cho biết: CRC = `F7971BFD`, Compressed Length `0x00045E22`, Uncompressed `0x00059F76` (= 368502), Compression Method = `Stored` (không nén). Sau 2 bước sửa, rút được `important.bmp`.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **Sửa magic bytes bằng hex editor (`vim`+`xxd`).** *Vì sao:* parser dựa vào `PK\x03\x04` để nhận diện Local Header; `DEADBEEF` làm nó không thấy signature.
2. **Sửa Filename Length theo little-endian.** *Vì sao:* trường độ dài sai làm parser đọc lệch toàn bộ phần sau; đưa về 13 để tên dừng đúng chỗ, dữ liệu BMP bắt đầu đúng vị trí.
3. **`zipdetails`/`zip -FF`/`7z`** để chẩn đoán và cứu. *Vì sao:* các công cụ này in/ép cấu trúc, giúp định vị trường hỏng và carve dữ liệu `Stored`.
4. **Phân tích BMP sau khi rút ra.** *Vì sao:* flag thường ẩn trong ảnh (append cuối file, LSB/bitplane, hoặc header bị sửa).

## Lời giải chi tiết (bước + code/lệnh sạch)

```bash
# Bước 1: sửa magic (vim + xxd)
vim 365a1c80b6ac1c5b908a3fa2526a3535320684e1.zip
#   :%!xxd
#   dòng offset 0: 'dead beef' -> '504b 0304'
#   :%!xxd -r
#   :wq

# Bước 2: sửa Filename Length tại offset 0x1A: byte '55 1F' -> '0D 00'  (little-endian = 13)
#   (dùng lại vim+xxd hoặc hex editor bất kỳ; cẩn thận little-endian)

# Bước 3: giải nén
unzip 365a1c80b6ac1c5b908a3fa2526a3535320684e1.zip
#   -> important.bmp
# Nếu còn kêu CRC/size: dùng   zip -FF broken.zip --out fixed.zip   hoặc 7z x -y

# Bước 4 (forensic BMP): soi flag
file important.bmp; xxd important.bmp | head        # kiểm header '42 4D' (BM)
strings -n 6 important.bmp | grep -i flag            # flag dạng text?
# so kích thước khai báo trong header vs kích thước thật -> dữ liệu thừa cuối file?
zsteg important.bmp 2>/dev/null                      # LSB/bitplane nếu có
```

## Flag

flag{...}  *(nguồn không nêu — writeup gốc dừng ở "Under Construction", chưa công bố flag; SOLUTIONS_VN.md xác nhận bài còn dở dang, chưa xác định flag. Cần hoàn tất bước phân tích `important.bmp` để lấy flag.)*

## Gặp lại thì xử lý thế nào (playbook)

1. ZIP không mở được → soi hex đầu file, kiểm **magic `50 4B 03 04`**; nếu bị thay (như `DEADBEEF`) thì sửa lại.
2. Dùng `zipdetails -v` để đọc từng trường; chú ý **Filename Length / Extra Length / CRC / size** bị bịa.
3. Nhớ **little-endian** khi sửa trường số (giá trị `0x1F55` nằm trong file là byte `55 1F`).
4. Khi CRC/size sai mà không cần đúng tuyệt đối: `zip -FF`, `7z`, hoặc carve trực tiếp dữ liệu `Stored` (không nén) từ offset đã biết.
5. Rút được ảnh/file → chạy forensic đầy đủ: `file`, `strings`, `binwalk`, so kích thước header vs thật, `zsteg`/`stegsolve` cho ảnh.
6. So sánh với các byte quen thuộc (magic, header BMP `42 4D`) để biết trường nào còn hỏng.
