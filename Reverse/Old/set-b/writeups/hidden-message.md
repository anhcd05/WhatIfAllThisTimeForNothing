# hidden-message

- **Category:** MISC
- **File đề:** không còn trong repo. ⚠️ README trong repo **rỗng** (0 byte) — không có lời giải sẵn; nội dung dưới đây là định hướng theo SOLUTIONS_VN.md.

## Tóm tắt đề

Repo không kèm mô tả. Tên bài gốc "hidden msg" gợi ý **steganography** — giấu thông điệp trong ảnh/âm thanh/văn bản. Nhiệm vụ: trích thông điệp ẩn để lấy flag.

## Phân tích (chi tiết)

"Hidden message" bao trùm nhiều kỹ thuật giấu tin; chiến lược là đi lần lượt từ dễ đến khó tùy loại file:

- **Ảnh (PNG/BMP/GIF):** LSB steganography (`zsteg`), bitplane/màu (`stegsolve`), dữ liệu append sau IEND (`binwalk`), chunk ẩn.
- **Ảnh JPG:** `steghide extract` (thường cần passphrase), `outguess`, metadata EXIF (`exiftool`).
- **Âm thanh (WAV/MP3):** spectrogram (Audacity/Sonic Visualiser), LSB audio, `steghide` cho WAV.
- **Văn bản:** **zero-width characters** (U+200B/U+200C/U+200D/U+FEFF) giấu bit, whitespace steganography (tab/space ở cuối dòng — `stegsnow`), viết hoa/thường mã hóa nhị phân, acrostic (chữ đầu dòng).
- **File bất kỳ:** `strings`, `binwalk -e`, `foremost`, so magic bytes.

Vì README rỗng và không có file, không thể khẳng định flag.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **`file` + `binwalk` + `strings` đầu tiên.** *Vì sao:* bắt nhanh dữ liệu append, file nhúng, flag dạng text — rẻ và hay trúng.
2. **`zsteg`/`stegsolve` cho ảnh lossless.** *Vì sao:* LSB/bitplane là kiểu giấu phổ biến nhất trong PNG/BMP.
3. **`steghide`/`exiftool` cho JPG.** *Vì sao:* JPG hay dùng steghide + EXIF comment.
4. **Soi zero-width/whitespace cho text.** *Vì sao:* thông điệp có thể giấu trong ký tự vô hình mà mắt không thấy.

## Lời giải chi tiết (bước + code/lệnh sạch)

```bash
file hidden.*            # xác định loại
strings -n 6 hidden.* | grep -i flag
binwalk -e hidden.*      # dữ liệu/file nhúng, append

# Ảnh PNG/BMP:
zsteg -a hidden.png
# (hoặc mở stegsolve xem từng bitplane)

# Ảnh JPG:
exiftool hidden.jpg
steghide extract -sf hidden.jpg          # thử passphrase rỗng / gợi ý trong đề

# Âm thanh:
# mở Audacity -> xem Spectrogram

# Văn bản (zero-width / whitespace):
python3 - <<'PY'
d = open('msg.txt','rb').read()
zw = [b for b in d if b in (0x0b,0x0c)]        # minh họa
# tìm U+200B/200C/200D/FEFF:
t = d.decode('utf-8','replace')
print([hex(ord(c)) for c in t if ord(c) in (0x200b,0x200c,0x200d,0xfeff)])
PY
stegsnow -C msg.txt                            # whitespace stego
```

## Flag

flag{...}  *(nguồn không nêu — README repo rỗng, không có file đề; SOLUTIONS_VN.md không ghi flag cho bài này.)*

## Gặp lại thì xử lý thế nào (playbook)

1. Luôn bắt đầu rẻ: `file` → `strings | grep flag` → `binwalk -e` → `exiftool`.
2. Theo loại file chọn tool: ảnh lossless → `zsteg`/`stegsolve`; JPG → `steghide`/`outguess`; audio → spectrogram; text → zero-width/whitespace/acrostic.
3. Tìm **passphrase** trong chính đề (tên file, mô tả, chuỗi khác) nếu `steghide` đòi.
4. Nhiều lớp: dữ liệu trích ra có thể lại là Base64/hex/zip → lặp lại quy trình.
5. Công cụ tổng hợp: `stegseek` (brute steghide), `aperisolve` (online), CyberChef cho decode text.
