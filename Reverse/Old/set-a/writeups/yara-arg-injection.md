# yara-arg-injection

- **Category:** Web (Argument/Option Injection)
- **File đề:** Đề online, **có kèm source code web app** (distributed source). PDF trích đoạn xử lý chính (các dòng ~75–85). Flag nằm trong file `./flag/flag_is_in_this_file.txt` trên server.

## Tóm tắt đề
Web app có 2 chức năng: (1) upload một **file rule YARA**; (2) quét file flag bằng rule vừa upload và trả kết quả. Nếu rule khớp, app chỉ trả về **tên rule** chứ **không** trả nội dung file. Có giới hạn truy cập và kích thước nên **không thể brute từng ký tự**. Phải đọc source tìm lỗ hổng.

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
**Đoạn xử lý chính (Python):**
```python
if is_outside_jail(fpath):
    return make_error_result("You shouldn't try to access to outside of app dir!")

arg = 'yara %s -w ./flag/flag_is_in_this_file.txt' % (fpath)
yara_args = shlex.split(arg)

if not exist_file(yara_args[1]):
    return make_error_result("'%s' doesn't exist" % fpath)

proc = subprocess.run(yara_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
result = proc.stdout.decode('utf8')
```

Nhận xét load-bearing:
- App ghép `fpath` (do ta kiểm soát, lấy từ POST) vào chuỗi: `yara <fpath> -w ./flag/flag_is_in_this_file.txt`, rồi `shlex.split()` và chạy `subprocess.run` ở **dạng list** (không qua shell).
- Vì **không qua shell**, command injection kiểu `;`/`|` **không** hoạt động. Nhưng `fpath` được chèn nguyên vào danh sách tham số → ta có thể **chèn thêm option cho chính lệnh `yara`** = **argument injection**.
- Ràng buộc: `exist_file(yara_args[1])` yêu cầu **token thứ 2 (index 1)** — tức tham số đầu tiên sau `yara` — phải là file rule tồn tại. Và `is_outside_jail(fpath)` chặn đường dẫn ra ngoài thư mục app.

**Lỗ hổng:** YARA có option **`-s` / `--print-strings`**: **in ra chuỗi đã khớp** trong file. Bình thường app chỉ trả tên rule, nhưng nếu ép `yara` chạy với `-s`, nó in ra **đoạn chuỗi trong file flag mà rule khớp** → lộ nội dung flag. Biến `yara -s` thành một **oracle đọc dữ liệu trực tiếp**, bỏ qua giới hạn brute.

CLI: `yara [OPTION]... RULES_FILE... FILE`. Mục tiêu dựng `fpath` sao cho `shlex.split` ra:
```
['yara', '<rule_file>', '-s', '-w', './flag/flag_is_in_this_file.txt']
```
trong đó `<rule_file>` (token index 1) vẫn là file rule hợp lệ để qua `exist_file`.

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **Argument/Option Injection vào `yara`** (không phải command injection). `shlex.split()` chặn shell metachar nhưng không chặn việc thêm tham số dòng lệnh.
- **Lạm dụng `-s`/`--print-strings`** làm kênh đọc dữ liệu: rule match → `-s` in đoạn khớp = flag.
- **VÌ SAO nhận ra:** source cho thấy `fpath` nối thẳng vào arg rồi `shlex.split()` → "shell injection fail, nhưng arg injection OK". Ảnh usage của yara khoanh đỏ `-s, --print-strings  print matching strings` → chính là kênh rò nội dung.
- **Công cụ:** chính form upload/POST + kiến thức CLI yara.

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. **Viết rule YARA khớp định dạng flag** (để `-s` có chuỗi mà in ra):
   ```
   rule findflag
   {
       strings:
           $a = /flag\{[^}]*\}/
       condition:
           $a
   }
   ```
   (Nếu regex đầy đủ không match hết do giới hạn, bắt đầu từ rule match tiền tố `flag{` rồi tận dụng `-s` in ra phần thực tế đã match.)

2. **Upload rule** qua form. App chạy `yara <rule> -w ./flag/flag_is_in_this_file.txt` và chỉ trả tên rule (`findflag`) nếu khớp — chưa lộ nội dung.

3. **Chèn option `-s`** qua `fpath`. Đặt đường dẫn rule hợp lệ trước (để `yara_args[1]` qua `exist_file`), rồi thêm token `-s`. Phần `fpath` ta điều khiển có dạng:
   ```
   <đường_dẫn_file_rule_đã_upload> -s
   ```
   → `shlex.split` cho `['yara', '<rule_file>', '-s', '-w', './flag/flag_is_in_this_file.txt']`.

4. **Chạy** → `yara -s` in ra **đoạn chuỗi đã khớp** trong `flag_is_in_this_file.txt` = nội dung flag, trả về trong `result`.

## Flag
flag{...}

*(Nguồn không nêu: PDF/`SOLUTIONS_VN.md` bài #37 — flag chỉ lộ trên server qua option `-s`, không in trong writeup đề. Flag thật có wrapper `flag{...}`.)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu argument injection:** app ghép input vào **danh sách tham số của một CLI** rồi gọi `subprocess`/exec dạng list (không shell), hoặc tách bằng `shlex.split()`. Shell metachar vô dụng, nhưng **thêm option/flag thì được**.
- **Tư duy khai thác:** mở `--help` của chương trình đích, tìm option biến nó thành kênh đọc/ghi file hoặc rò dữ liệu: `yara -s` (in chuỗi khớp); `tar --to-command`/`--checkpoint-action`; `curl -o/-K`; `ffmpeg` protocol; `-o/--output` ghi đè; `-i/--include` đọc file.
- **Dùng tool làm oracle:** khi chỉ nhận match/no-match hoặc tên rule, tìm cờ in thêm chi tiết (`-s`); với blind có thể dùng rule regex thu hẹp dần, nhưng `-s` biến nó thành đọc trực tiếp.
- **Bẫy:** ràng buộc kiểm tra tham số (`yara_args[1]` phải tồn tại, `is_outside_jail`) → sắp xếp thứ tự token để vừa hợp lệ vừa chèn được; `shlex.split` xử lý nháy/space → quote hợp lý.
- **Checklist:** [ ] input đi vào arg của CLI (shlex/list)? [ ] đọc `--help` tìm option nguy hiểm [ ] chèn flag giữ các ràng buộc pass [ ] biến tool thành kênh đọc (yara `-s`) [ ] lấy output.
