# reversed-name

- **Category:** MISC
- **File đề:** `reversed-name/7904ba4cdb3b1cb4c6a9f767c9ef065c.exe` (191927 bytes; git blob sha1 `4adbe37f7a7ea6f4613a9fd32cc44d9812d4dc21`; md5 nhúng trong tên: `7904ba4cdb3b1cb4c6a9f767c9ef065c`).

## Tóm tắt đề

Chạy file trên Windows thì nó "nhả" ra một loạt **file 0 byte** với tên gồm bảng chữ cái bị **xáo trộn**. Đề nhấn mạnh: xem danh sách bằng `dir /O:D` (sắp theo **thời gian tạo**). Flag là ký tự "còn thiếu" đọc theo thứ tự thời gian.

## Phân tích (chi tiết)

**Nền tảng — RLO.** *RLO* = **Right-to-Left Override**, ký tự điều khiển Unicode **U+202E**. Nó ra lệnh cho trình hiển thị: "từ đây vẽ văn bản phải→trái". Đây là thủ thuật lừa người dùng kinh điển (ví dụ `photo_gnp.exe` chèn RLO hiển thị thành `photo_exe.png`). Windows Explorer/`cmd` đều tôn trọng U+202E khi in tên file, nên tên "nhìn thấy" khác với byte thật trên đĩa.

Danh sách 19 file 0 byte (trích từ đề, đã sắp theo thời gian `dir /O:D`):

```
10:00 PM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcde?_{}zyxwvutsrqponmlkjihgf
11:00 PM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk?_{}zyxwvutsrqponml
12:00 AM  ABCDEFGHIJKLMNOPQRSTUVWXYZ?_{}zyxwvutsrqponmlkjihgfedcba
01:00 AM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef?_{}zyxwvutsrqponmlkjihg
02:00 AM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{?_{
03:00 AM  ABCDEFGHIJKLMNOPQ?_{}zyxwvutsrqponmlkjihgfedcbaZYXWVUTSR
04:00 AM  ABCDEFGHIJK?_{}zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONML
05:00 AM  ABCDEFGHIJKLMN?_{}zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPO
06:00 AM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}?_
07:00 AM  ABC?_{}zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFED
08:00 AM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh?_{}zyxwvutsrqponmlkji
09:00 AM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr?_{}zyxwvuts
10:00 AM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq?_{}zyxwvutsr
11:00 AM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst?_{}zyxwvu
12:00 PM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno?_{}zyxwvutsrqp
01:00 PM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs?_{}zyxwvut
02:00 PM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}?_
03:00 PM  ABCDEFGHIJKLMNOPQRST?_{}zyxwvutsrqponmlkjihgfedcbaZYXWVU
04:00 PM  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz?_{}
```

**Reasoning.** "Bảng gốc" = `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_{}`. Ở mỗi tên, cụm `?_` đánh dấu vị trí ký tự RLO được chèn (RLO làm phần sau nó bị đảo → nửa cuối `...zyxwvutsrqp...` là bảng chữ cái ngược). Quy tắc của đề: **ký tự của flag = ký tự đứng ngay sau ký tự trước `?_`, trong bảng gốc**.

- Dòng 1 (10:00 PM): `...abcde?_...` → trước `?_` là `e` → ký tự sau `e` là `f` → #1 = **f**.
- Dòng 2 (11:00 PM): `...hijk?_...` → trước là `k` → sau `k` là `l` → #2 = **l**.
- Lặp theo đúng thứ tự thời gian → ghép thành `flag{RLO_Disrupt_U}`.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **Nhận diện RLO (U+202E).** *Vì sao:* tên file bị "xáo" thực chất do ký tự BiDi đảo chiều hiển thị; hiểu điều này mới giải được.
2. **Sắp theo thời gian tạo (`dir /O:D`).** *Vì sao:* thứ tự ký tự flag mã hóa qua **thời gian**, không qua tên; sort theo tên sẽ sai.
3. **Lập bảng gốc + lấy "ký tự kế tiếp".** *Vì sao:* mỗi file mã hóa đúng **một** ký tự flag qua vị trí cụm `?_`.
4. **Phân tích tĩnh, không chạy exe.** *Vì sao:* chỉ cần danh sách tên (đã có); chạy exe lạ là rủi ro không cần thiết.

## Lời giải chi tiết (bước + code/lệnh sạch)

```python
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_{}"
names = [  # theo thứ tự thời gian từ 'dir /O:D'
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcde?_{}zyxwvutsrqponmlkjihgf",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk?_{}zyxwvutsrqponml",
  # ... (19 dòng, đúng thứ tự trên)
]
flag = ""
for n in names:
    i = n.index("?_")                           # vị trí cụm đánh dấu
    prev = n[i-1]                               # ký tự ngay trước '?_'
    flag += alphabet[alphabet.index(prev)+1]    # ký tự kế tiếp trong bảng gốc
print(flag)                                     # -> RLO_Disrupt_U
```

Trên Linux, để thấy chính xác U+202E trong tên file (vì hiển thị khác Windows), dùng `os.listdir()` rồi in `repr(name)`, hoặc `ls | xxd`.

## Flag

flag{RLO_Disrupt_U}

## Gặp lại thì xử lý thế nào (playbook)

1. Tên file/chuỗi "lộn xộn" có cụm bất thường (`?`, ký tự không in được) → nghi **Unicode BiDi control** (U+202E RLO, U+202D LRO, U+202C PDF).
2. Luôn kiểm bằng **hex/`repr`** để thấy byte thật, đừng tin hiển thị của Explorer/`cmd`.
3. Nếu bài gắn thông tin vào **metadata thời gian** → sắp theo thời gian (`dir /O:D`, `ls -ltr`, `stat`).
4. Tìm quy luật mã hóa 1-ký-tự-mỗi-file (vị trí marker, độ dài, offset) rồi script hóa.
5. Không cần chạy binary nếu dữ liệu đã có trong mô tả — ưu tiên tĩnh; nếu buộc phải chạy thì dùng VM cách ly.
