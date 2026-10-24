# layered-pdf

- **Category:** MISC
- **File đề:** `challenge.pdf` (một file PDF). ⚠️ File đề **thiếu trong repo** (README ghi "The file was missing"); lời giải dựa trên mô tả trong README và nguồn SOLUTIONS_VN.md.

## Tóm tắt đề

Một file PDF. Khi mở lên thấy **2 dòng flag** nhưng bị **khối đen** (black block) che. Flag chia **3 phần**, mỗi phần giấu ở một "lớp" khác nhau của PDF.

## Phân tích (chi tiết)

PDF là định dạng **nhiều lớp**: text, ảnh (image XObject), vector, annotation, và **metadata** (XMP / Document Info: Title, Author, Keywords...). Lỗi rò rỉ kinh điển là **redaction (bôi đen) sai cách**: người làm chỉ *vẽ hình chữ nhật đen đè lên* mà **không xóa** dữ liệu bên dưới → text/ảnh gốc vẫn còn, chỉ cần copy hoặc trích xuất là lộ.

Bài này cố tình chia flag làm 3 phần ở 3 lớp để kiểm tra đủ kỹ năng:

- **Phần 1 (`flag{dog_...`)** là một **ảnh** đè lên khối đen. Không copy text được, nhưng chuột phải → "Save image as" → mở ảnh ra là thấy phần `dog`. (README cho biết phần 1 có dạng `flag{dog_*****_*****}`.)
- **Phần 2 (`..._monkey_...`)** là **text thật** nằm dưới khối đen (redaction giả). Bôi đen vùng đó + Ctrl+C → dán ra là có `monkey`. (README: phần 2 dạng `flag{*****_monkey_*****}`.)
- **Phần 3 (`...grandpa}`)** nằm trong **metadata** của PDF → chạy `exiftool challenge.pdf` sẽ lộ `grandpa`.

Ghép 3 phần: `flag{dog_monkey_grandpa}`.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **Trích ảnh ("Save image as" / `pdfimages`).** *Vì sao:* phần 1 là ảnh đè, không nằm trong luồng text → phải lấy ảnh ra xem.
2. **Bôi đen + copy text.** *Vì sao:* redaction giả không xóa text; text thật vẫn chọn-copy được dù bị khối đen che.
3. **Đọc metadata (`exiftool`/`pdfinfo`).** *Vì sao:* nhiều bí mật nằm ở trường Title/Author/Keywords/XMP mà người xem bình thường không để ý.
4. **Phân tích tĩnh.** *Vì sao:* PDF chỉ cần đọc/trích xuất; không thực thi gì.

## Lời giải chi tiết (bước + code/lệnh sạch)

```bash
# Phần 1: trong trình đọc PDF -> chuột phải vùng flag bị che -> "Save image as"
#         -> mở ảnh -> đọc "dog"
# Hoặc trích toàn bộ ảnh nhúng:
pdfimages -all challenge.pdf out_      # xem các out_*.png/jpg

# Phần 2: bôi đen dòng 2 (vùng khối đen) -> Ctrl+C -> dán -> "monkey"
# Hoặc trích toàn bộ text:
pdftotext challenge.pdf -               # text ẩn dưới khối đen sẽ hiện ra

# Phần 3: đọc metadata
exiftool challenge.pdf                   # trường metadata -> "grandpa"
pdfinfo challenge.pdf                     # (phương án khác đọc Document Info)
```

Trích "mọi thứ" khi cần soi kỹ: `mutool extract challenge.pdf`, `qpdf --qdf challenge.pdf out.pdf` (xem object thô), `binwalk`/`foremost` để carve ảnh.

## Flag

flag{dog_monkey_grandpa}

## Gặp lại thì xử lý thế nào (playbook)

1. PDF có vùng bị "bôi đen" → **luôn** thử bôi-đen-copy text (redaction giả) và "Save image as".
2. Trích toàn bộ: `pdftotext` (text), `pdfimages -all` (ảnh), `exiftool`/`pdfinfo` (metadata), `mutool extract`.
3. Xem object thô bằng `qpdf --qdf` hoặc mở bằng editor để tìm stream/annotation ẩn.
4. Nếu flag chia nhiều phần → kiểm **mọi lớp**: text, ảnh, metadata, annotation, layer (OCG), form field, attachment nhúng.
5. Bài học: redaction đúng cách phải **xóa dữ liệu**, không chỉ vẽ đè; khi gặp tài liệu "đã bôi đen" hãy nghi ngờ.
