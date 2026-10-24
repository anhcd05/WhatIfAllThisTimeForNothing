# whitespace-stegsnow

- **Category:** Steganography
- **File đề:** `stego_image.png` (ảnh con tàu) — không kèm trong repo, chỉ có solution. Trong ảnh nhúng file `song.txt`; trong `song.txt` lại giấu flag bằng khoảng trắng.

## Tóm tắt đề
Ảnh giấu một file text lời bài hát (`song.txt`) qua OpenStego; trong file text đó flag được giấu bằng **whitespace steganography (stegsnow)** — dùng tab (`0x09`) / space (`0x20`) thừa ở cuối dòng, vô hình với mắt người. Hai lớp: (1) trích `song.txt` khỏi ảnh; (2) `stegsnow` giải flag khỏi `song.txt`.

## Phân tích (chi tiết: dấu hiệu/byte thật)
- `exiftool stego_image.png` → trường **Software** (hoặc comment) gợi ý **stegsnow** → xác định bài whitespace stego.
- `song.txt` nhúng bằng **OpenStego, không cần mật khẩu**.
- Mở `song.txt` bằng hex editor thấy nhiều byte **`09` (tab)** và **`20` (space)** ở cuối dòng → chữ ký kinh điển của **snow/stegsnow**: mỗi bit của message map vào chuỗi space/tab cuối dòng.
- Tầng giấu kép: ảnh → text (OpenStego), text → flag (stegsnow).

## Kỹ thuật áp dụng (+ VÌ SAO)
- **ExifTool/strings:** VÌ SAO: trường Software nêu tên tool `stegsnow` → biết đây là whitespace stego ngay.
- **OpenStego Extract Data (no password):** VÌ SAO: lấy đúng `song.txt` ra trước — đây là lớp ngoài; làm sai thứ tự sẽ không có input cho stegsnow.
- **stegsnow decode:** VÌ SAO: trailing tab/space chính là payload; chỉ `stegsnow` (hoặc tool snow) đọc đúng ánh xạ bit.

## Lời giải chi tiết (bước + lệnh sạch)
1. Đọc metadata:
   ```bash
   exiftool stego_image.png       # Software/comment gợi ý: stegsnow
   ```
2. Trích `song.txt` khỏi ảnh (OpenStego, không mật khẩu):
   ```bash
   openstego extract -sf stego_image.png -xd ./out     # -> out/song.txt
   ```
3. Xác nhận trailing whitespace:
   ```bash
   cat -A out/song.txt | head        # thấy ^I (tab) và khoảng trắng lệch cột cuối dòng
   ```
4. Giải whitespace (không cần option):
   ```bash
   stegsnow out/song.txt             # -> in flag
   ```

## Flag
flag{Hurray_clap_your_hands}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** đề/metadata nhắc "snow"/"stegsnow"; một file text "trông bình thường" (lời bài hát, thơ) nhưng hex thấy `09`/`20` thừa cuối dòng; `cat -A` hiện `^I` và space trailing.
- **Quy trình:** (1) `exiftool`/`strings` ảnh lấy tên tool gợi ý; (2) trích file text nhúng (OpenStego/steghide/binwalk); (3) kiểm tra trailing whitespace; (4) `stegsnow [-p pass] file` (thử không password trước).
- **Công cụ:** exiftool, OpenStego, stegsnow (Kali), hex editor.
- **Bẫy:** editor/terminal tự trim trailing whitespace → KHÔNG chỉnh sửa file, thao tác trên bản gốc; có thể cần `-p` (bài này không cần); phải lấy đúng `song.txt` trước rồi mới stegsnow.
