# number-canvas

- **Category:** Crypto
- **File đề:** `number-canvas/README.md` (chứa một blob Base64 lớn) và ảnh gợi ý `the_sword.png`.

## Tóm tắt đề

Đề nói ngắn gọn: "Try to get flag from this text" và cho một **blob Base64 dài nhiều dòng**. Kèm ảnh `the_sword.png` (thanh kiếm) làm gợi ý chủ đề. Nhiệm vụ: lấy flag ẩn trong đoạn text.

## Phân tích (chi tiết)

Giải Base64 (chú ý blob có xuống dòng `\r\n` được mã hóa thành `DQo` ở giữa) ra một **khối chữ số** nhiều dòng, mỗi dòng 80 ký tự, chỉ gồm các chữ số:

```
35733732373237757212257523535715172332517113715717557232235232357275733232123577
77321723315255277552522755177555571575512337235215122237253751777257331115217373
...
```

Nhìn text thô không ra gì. Quan sát thống kê ký tự: tuyệt đại đa số là **1–7**, còn **0 và 8** xuất hiện **thưa thớt** và có xu hướng **tụ lại thành cụm** ở một vùng của khối. Đây là dấu hiệu kinh điển của **steganography thị giác (ASCII-art stego)**: người ta "vẽ" chữ bằng một tập ký tự đặc biệt (ở đây là `0` và `8`) trên nền các ký tự khác, khi tô sáng đúng tập ký tự thì mắt người đọc ra hình, còn máy thì không.

Khối số là lưới đều (mỗi dòng 80 cột). Khi thay mọi ký tự **không phải** `0`/`8` bằng khoảng trắng, các ký tự `0`/`8` còn lại xếp thành hình chữ **"PLUCK"**. Hợp với tên bài *The_Sword* và ảnh thanh kiếm: "pluck the sword" = rút kiếm.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **Base64 decode.** *Vì sao:* blob là Base64 (có `=` đệm, ký tự `A-Za-z0-9+/`); phải decode mới ra khối số.
2. **Giữ đúng độ rộng dòng (80 cột).** *Vì sao:* stego hình chỉ hiện đúng khi các ký tự nằm đúng lưới; blob đã mã hóa cả `\r\n` nên khi decode phải tôn trọng ngắt dòng gốc.
3. **Highlight tập ký tự hiếm (`0`,`8`), xóa phần còn lại.** *Vì sao:* "mực vẽ" là các ký tự thưa; thay nền bằng khoảng trắng để tăng tương phản cho mắt người → đọc ra chữ.
4. **Đây là stego thị giác, không phải mật mã.** *Vì sao:* khối số không có cấu trúc toán học để giải; đừng sa đà brute cipher.

## Lời giải chi tiết (bước + code/lệnh sạch)

```python
import base64

blob = """<dán nguyên blob Base64 trong README, giữ các dòng>"""
data = base64.b64decode(blob).decode()      # khối số, các dòng cách nhau \r\n

# "Vẽ" chữ: giữ 0/8, thay mọi ký tự khác bằng khoảng trắng
for line in data.replace('\r', '').split('\n'):
    print(''.join(c if c in '08' else ' ' for c in line))
# Màn hình hiện hình chữ:  P L U C K
```

Nếu khối số bị nối thành một dòng dài (mất ngắt dòng), phải **cắt lại theo đúng độ rộng 80 cột** rồi mới in, nếu không hình sẽ méo:

```python
s = data.replace('\r', '').replace('\n', '')
W = 80
for i in range(0, len(s), W):
    row = s[i:i+W]
    print(''.join(c if c in '08' else ' ' for c in row))
```

Có thể thay bằng cách render ra ảnh (mỗi ký tự 1 pixel, `0`/`8` = đen, còn lại = trắng) rồi xem — cùng kết quả. Ảnh `the_sword.png` trong đề là minh họa chữ "PLUCK".

## Flag

flag{PLUCK}

## Gặp lại thì xử lý thế nào (playbook)

1. Blob Base64 → decode → nếu ra **khối số/khối ký tự đều nhau** thì nghĩ tới **stego thị giác**, không phải cipher.
2. Thống kê tần suất ký tự: ký tự **hiếm** và **tụ cụm** thường là "mực" vẽ chữ.
3. Giữ nguyên độ rộng dòng (hoặc tìm độ rộng đúng: thử các ước của tổng độ dài, hoặc độ rộng khiến hình cân đối như 80).
4. Highlight tập ký tự hiếm, xóa nền → đọc chữ. Có thể dùng `tr`, `sed`, Python, hoặc render thành ảnh.
5. Biến thể hay gặp: chữ hiện khi highlight ký tự theo **chẵn/lẻ**, theo **một giá trị cụ thể**, hoặc khi **thu nhỏ font**/xem từ xa. Thử vài tập ký tự khác nhau nếu `0/8` không ra.
6. Công cụ nhanh: CyberChef `From Base64`, rồi dùng tính năng highlight hoặc tự viết filter.
