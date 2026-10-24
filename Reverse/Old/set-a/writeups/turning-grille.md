# turning-grille

- **Category:** Cryptography
- **File đề:** `ctf/crypto/turning-grille/document.docx` — 79849 byte — MD5 `8878c3e74d2c352b809ea2a250b4130b` — SHA-1 `76920ca5cf98f83cf0b0179eb99515fc4bb2f674`. (Tên nội bộ bản nháp: "Grill_Cipher"; mô tả đề: "Flag được gói trong một tài liệu WORD, cần trích xuất các file và giải mã.")

## Tóm tắt đề
Flag nằm trong một file Word. Mở `document.docx` sẽ báo hỏng; dùng "Open and Repair" của Word sẽ thấy thông điệp gợi ý. Thực chất file chứa một thư mục lạ `CTF/` với nhiều lớp mã hóa chồng nhau, lớp cuối là một mật mã **lưới quay Fleissner (turning grille)**.

## Phân tích (chi tiết: offset, magic, khóa thật)
`.docx` là định dạng Office Open XML — bản chất là một **archive ZIP**. Đổi đuôi `.docx` → `.zip` rồi giải nén (hoặc mở trực tiếp bằng thư viện zip) sẽ thấy cấu trúc chuẩn `word/`, `[Content_Types].xml`, `_rels/`... **cộng thêm** một thư mục bất thường `CTF/` — dấu hiệu dữ liệu bị nhét thêm.

Nội dung thư mục `CTF/` (xác minh tĩnh bằng liệt kê entry ZIP):
```
CTF/Cipher
CTF/filter
CTF/How_to_decrypt_cipher.txt
CTF/XOR_it.txt
```

Nội dung 2 file hướng dẫn (đọc tĩnh):
- `CTF/How_to_decrypt_cipher.txt`: `This file is all bits inverted from the original.` → `Cipher` bị **đảo toàn bộ bit** (`b → 255 - b`, tương đương `b XOR 0xFF`).
- `CTF/XOR_it.txt`: `In order to decrypt filter, you need to XOR with it.\r\n` → **toàn bộ nội dung file này (53 byte) chính là khóa** để XOR giải `filter` (repeating-key XOR).

Kiểm chứng magic byte (phân tích tĩnh, KHÔNG chạy binary):
- `Cipher` 4 byte đầu raw = `00 27 00 1F`; sau khi đảo bit = `FF D8 FF E0` → **magic JPEG** (JFIF). JPEG này là ảnh nền `576x576` chứa các mảnh chữ.
- `filter` sau khi XOR với toàn bộ `XOR_it.txt` → 8 byte đầu = `89 50 4E 47 0D 0A 1A 0A` → **magic PNG**. PNG là ảnh `567x569` RGBA — chính là **tấm lưới đục lỗ (pierced sheet)**.

Khóa thật của bài gồm 3 lớp: (1) NOT toàn file cho `Cipher`; (2) repeating-key XOR với key = nội dung `XOR_it.txt` cho `filter`; (3) phép giải cuối là **overlay lưới PNG lên JPEG + xoay 4 góc 0°/90°/180°/270°**.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Trích xuất OOXML:** đổi `.docx` → `.zip`. *Vì sao:* docx là ZIP; file ẩn luôn nằm ngoài cây chuẩn (`word/`, `_rels/`), nên thư mục lạ `CTF/` lộ ngay.
- **Bit inversion (NOT):** `byte = 0xFF - byte`. *Vì sao:* file hướng dẫn nói rõ "all bits inverted"; đảo hai lần ra lại chính nó nên đây là phép thuận nghịch, khôi phục magic JPEG.
- **Repeating-key XOR:** `filter[i] ^= key[i % len(key)]`. *Vì sao:* XOR thuận nghịch; key ngắn hơn dữ liệu nên lặp bằng modulo. Kết quả ra magic PNG xác nhận đúng khóa.
- **Fleissner / turning grille:** đặt bìa đục lỗ lên nền chữ, xoay 4 góc đọc ký tự lộ qua lỗ. *Vì sao:* PNG giải ra đúng dạng "tấm lưới đục lỗ" kinh điển của grille cipher, còn JPEG là nền chứa chữ.
- **Công cụ:** trình giải nén, CyberChef hoặc PowerShell (NOT/XOR), trình xem/chỉnh ảnh để overlay + xoay.

## Lời giải chi tiết (bước + code/lệnh sạch)
1. Mở `document.docx`; nếu Word báo hỏng, chọn **Open and Repair** để đọc thông điệp gợi ý.
2. Copy ra `example.zip`, giải nén, vào thư mục `CTF/`.
3. **Khôi phục `Cipher` → JPEG** (đảo bit), PowerShell:
   ```powershell
   $b = [System.IO.File]::ReadAllBytes("CTF\Cipher")
   for ($i=0; $i -lt $b.Length; $i++) { $b[$i] = [System.Byte]::MaxValue - $b[$i] }  # 255 - b
   [System.IO.File]::WriteAllBytes("Cipher.jpg", $b)
   ```
   Kiểm tra `file Cipher.jpg` → `JPEG image data ... 576x576`.
4. **Khôi phục `filter` → PNG** (XOR repeating-key):
   ```powershell
   $A   = [System.IO.File]::ReadAllBytes("CTF\filter")
   $key = [System.IO.File]::ReadAllBytes("CTF\XOR_it.txt")   # toàn file = khóa
   for ($i=0; $i -lt $A.Length; $i++) { $A[$i] = $A[$i] -bxor $key[$i % $key.Length] }
   [System.IO.File]::WriteAllBytes("filter.png", $A)
   ```
   Kiểm tra `file filter.png` → `PNG image data, 567 x 569, 8-bit/color RGBA`.
5. Tương đương bằng Python (đọc thẳng trong ZIP, không cần giải nén ra đĩa):
   ```python
   import zipfile
   z = zipfile.ZipFile("document.docx")
   open("Cipher.jpg","wb").write(bytes(255-b for b in z.read("CTF/Cipher")))
   f, k = z.read("CTF/filter"), z.read("CTF/XOR_it.txt")
   open("filter.png","wb").write(bytes(f[i]^k[i%len(k)] for i in range(len(f))))
   ```
6. **Giải grille:** mở `filter.png` (tấm lưới), đặt chồng lên `Cipher.jpg`, xoay lưới qua 4 góc 0°/90°/180°/270°. Mỗi vị trí lỗ để lộ vài ký tự; đọc và ghép theo thứ tự xoay ra flag.

## Flag
```
flag{FleissnerGrill}
```
(Nguồn: `SOLUTIONS_VN.md` mục A1 và nháp `Grill_Cipher.md`. "Fleissner grille" là tên nhà phát minh kiểu lưới quay — chính kỹ thuật của bài.)

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** file Office báo "corrupted/Open and Repair"; `.docx/.xlsx/.pptx` có thư mục lạ khi mở như ZIP; file trung gian có hint "bits inverted" / "XOR it"; ảnh PNG dạng lưới có lỗ ⇒ grille cipher.
- **Quy trình:** Office → đổi đuôi ZIP → tìm file ngoài chuẩn OOXML → đọc file `how_to_*`/`README` để biết lớp mã hóa → khử từng lớp (NOT rồi `file` kiểm magic; XOR keystream lặp rồi `file` kiểm magic) → nhận "pierced sheet" → overlay + xoay 4 góc đọc.
- **Bẫy:** sai độ dài keystream XOR (phải `% len`); nhầm thứ tự xoay lưới → đọc thiếu/sai ký tự; luôn kiểm magic byte sau mỗi bước để biết đã giải đúng; thứ tự bắt buộc là **NOT trước (Cipher), XOR sau (filter)**.
- **Checklist:** docx→zip → tìm `CTF/` → NOT→JPEG(`FFD8`) → XOR→PNG(`89504E47`, lưới) → overlay+xoay → flag.
