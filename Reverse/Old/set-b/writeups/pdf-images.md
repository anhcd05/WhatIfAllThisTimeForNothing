# pdf-images

- **Category:** Forensic
- **File đề:** một file PDF (không còn trong repo). ⚠️ README trong repo **rỗng** — không có lời giải sẵn; nội dung dưới đây là định hướng phân tích tĩnh theo SOLUTIONS_VN.md.

## Tóm tắt đề

Repo không kèm mô tả. Tên bài gốc "PDF-JPGS" gợi ý **nhiều ảnh JPG nhúng trong một PDF**. Nhiệm vụ: tách các ảnh ra, một ảnh (hoặc tổ hợp nhiều mảnh ảnh) chứa flag.

## Phân tích (chi tiết)

PDF có thể nhúng ảnh dưới dạng **Image XObject** (thường JPEG = DCTDecode, hoặc PNG/Flate). Các kịch bản hay gặp ở bài dạng này:

- Một ảnh JPG trong số nhiều ảnh **chứa trực tiếp flag** (text trong ảnh, hoặc stego).
- Flag bị **cắt thành nhiều mảnh JPG**, phải tách hết rồi **ghép lại** theo đúng thứ tự/vị trí.
- Ảnh bị **đặt chồng/ẩn** dưới ảnh khác (chỉ lộ khi trích riêng từng XObject).
- Flag nằm trong **metadata** của PDF hoặc của chính ảnh JPG (EXIF).

Hướng chuẩn: dùng `pdfimages -all` để trích **đúng ảnh gốc** (không re-render), kết hợp `binwalk`/`foremost` để carve nếu có ảnh nhúng bất thường, rồi soi từng ảnh.

Vì README rỗng và không có file, không thể khẳng định flag.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **`pdfimages -all`.** *Vì sao:* trích ảnh **nguyên bản** theo từng XObject, giữ đúng dữ liệu JPG (quan trọng cho stego/EXIF).
2. **`binwalk`/`foremost` carve.** *Vì sao:* bắt các ảnh nhúng mà parser PDF có thể bỏ sót, hoặc dữ liệu append.
3. **`exiftool` trên PDF và từng ảnh.** *Vì sao:* flag có thể ở metadata PDF/EXIF ảnh.
4. **`montage`/xem thủ công để ghép mảnh.** *Vì sao:* nếu flag bị chia nhỏ, cần ráp lại theo thứ tự.

## Lời giải chi tiết (bước + code/lệnh sạch)

```bash
mkdir out
pdfimages -all challenge.pdf out/img          # trích mọi ảnh gốc
ls out/                                        # xem số lượng/loại ảnh

# soi từng ảnh:
exiftool out/*.jpg | grep -i -E 'flag|comment'
strings -n 6 out/*.jpg | grep -i flag

# carve thêm nếu nghi còn ảnh ẩn / dữ liệu append:
binwalk -e challenge.pdf
foremost -t jpg -i challenge.pdf -o carved

# nếu flag bị chia mảnh, ghép để xem tổng thể:
montage out/img-*.jpg -tile 4x -geometry +2+2 mosaic.png
```

## Flag

flag{...}  *(nguồn không nêu — README repo rỗng, không có file đề; SOLUTIONS_VN.md không ghi flag cho bài này.)*

## Gặp lại thì xử lý thế nào (playbook)

1. PDF + nhắc tới ảnh → `pdfimages -all` để tách ảnh gốc, rồi `ls` xem có bao nhiêu/loại gì.
2. Soi từng ảnh: mở xem mắt thường, `exiftool` (EXIF/comment), `strings`, `zsteg`/`stegsolve` nếu nghi stego.
3. Nếu thiếu mảnh hoặc ảnh lạ → `binwalk -e`, `foremost` để carve; `qpdf --qdf` xem object thô.
4. Flag chia mảnh → ghép (`montage`), hoặc xem thứ tự XObject trong PDF để ráp đúng.
5. Đừng quên metadata của **chính PDF** (`exiftool challenge.pdf`, `pdfinfo`).
