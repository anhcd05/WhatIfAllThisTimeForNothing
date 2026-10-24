# fake-extension

- **Category:** MISC
- **File đề:** `fake-extension/2976ac4a36456915d06ad80bac402917.zip` (23685 bytes; git blob sha1 `117909cfb990c014c7c8a60ff1383ac2d221e3ec`). ⚠️ md5 **thật** của zip = `44b9e842fc87324c1f756c61835ee62a`, **khác** hash nhúng trong tên (`2976ac4a...`) → file trong repo đã bị đóng gói/nén lại so với bản gốc; hash trong tên chỉ là nhãn định danh, không phải md5 file hiện có.

## Tóm tắt đề

Tên bài gốc là *notepad?* (dấu `?` là một phần tên — "có thật là notepad?"). Giải nén zip ra một file trông như Notepad/.txt. Nhiệm vụ: nhận ra trò lừa đuôi file và lấy flag.

## Phân tích (chi tiết)

Windows mặc định **ẩn đuôi file quen thuộc** và hiển thị **icon theo đuôi**, nên người dùng dễ bị lừa bởi *đuôi giả*. Các kiểu thường gặp:

1. **Double extension** `abc.txt.exe` (Windows ẩn `.exe`, chỉ thấy `abc.txt`).
2. **RLO (U+202E)** lật đuôi để `...exe` hiển thị thành `...txt`.
3. **Gán icon** của Notepad/txt cho một file `.exe`/`.scr`.
4. File **thật sự là loại khác hẳn** với đuôi hiển thị — chỉ xác định đúng bằng **magic bytes** (lệnh `file`), không bằng đuôi.

Flag `DoNotTrustTheApparentExtension` ("đừng tin đuôi hiển thị") nói rõ bài học: file *trông như* txt/notepad nhưng bản chất (magic bytes) là loại khác. Giải bài = nhận diện trò lừa và lấy flag từ file "thật" bên trong. README gốc kèm `flag.png`; flag chính là thông điệp bài học.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **`file <tên>` kiểm magic bytes.** *Vì sao:* đuôi/icon có thể giả; chỉ magic bytes cho biết định dạng thật.
2. **`xxd | head` xem byte đầu.** *Vì sao:* xác nhận chữ ký (`MZ` = PE, `89 50 4E 47` = PNG, `25 50 44 46` = PDF...).
3. **`repr`/hex tên file** nếu nghi RLO. *Vì sao:* phát hiện U+202E lật đuôi.
4. **Phân tích tĩnh, KHÔNG chạy.** *Vì sao:* nếu file thật là `.exe`, chạy là rủi ro; chỉ `strings`/mở trong VM.

## Lời giải chi tiết (bước + code/lệnh sạch)

```bash
unzip 2976ac4a36456915d06ad80bac402917.zip
file *                                   # bản chất thật khác đuôi hiển thị
xxd <file> | head                        # soi magic bytes
# nếu tên có ký tự lạ (nghi RLO):
python3 -c "import os; print([repr(n) for n in os.listdir('.')])"

# tìm flag nếu ở dạng text trong file thật:
strings -n 6 <file> | grep -i flag
```

Nếu file thật là ảnh, mở bằng trình xem ảnh (hoặc đổi đuôi đúng); nếu là PE, **không chạy** — dùng `strings`/VM cách ly.

## Flag

flag{DoNotTrustTheApparentExtension}

## Gặp lại thì xử lý thế nào (playbook)

1. Gặp file "có vẻ hiền" (txt/notepad/ảnh) → **luôn** chạy `file` để xác định loại thật trước khi làm gì.
2. Soi magic bytes bằng `xxd`/`hexdump`; đối chiếu bảng chữ ký (`MZ`, `PK`, `%PDF`, `\x7fELF`, PNG/JPG...).
3. Tên file có ký tự lạ → in `repr`/hex để phát hiện **RLO (U+202E)** hoặc double extension.
4. Không chạy file khả nghi; dùng `strings`, `binwalk`, `TrID`, hoặc file manager Linux (không bị RLO đánh lừa như Windows Explorer).
5. Tham khảo: MITRE ATT&CK T1036.007 (Masquerading: Double File Extension).
