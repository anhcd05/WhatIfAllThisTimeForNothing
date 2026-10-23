# 01. Quy trình reverse tổng quát

> Tóm tắt từ note của anh (24/08/2026), viết lại gọn kèm liên kết sang bộ thuật toán. Mục tiêu: **biết mình đang ở bước nào** và **bước kế tiếp nhanh nhất là gì**.

## 1. Bức tranh chung

Reverse CTF xoay quanh 6 thành phần; độ khó nằm ở chỗ tác giả "làm khó" thành phần nào:

| Thành phần | Câu hỏi | Tác giả hay làm khó bằng |
|---|---|---|
| **Convert to readable code** | Có đọc được code không? | VM tự chế, packer, ngôn ngữ lạ, anti-decompile |
| **Input** | Chương trình nhận gì? | Nhiều đường nhập, input phải tính ra |
| **Output expectation** | Đúng/sai được định nghĩa thế nào? | Giấu nhánh in flag, bắt chạy runtime, phải brute force |
| **Related artifact** | Biến/dữ liệu/tệp nào tham gia? | Biến bị biến đổi, TLS callback đổi giá trị, decompile sót |
| **Check progress** | Quá trình kiểm tra phức tạp ra sao? | Obfuscate, code khổng lồ, decoy, toán nặng, anti-debug |
| **Forensic flavour** | Có phải điều tra trước khi reverse? | Nhiều tệp phải forensic rồi mới reverse |

## 2. Workflow chuẩn

1. **Nhận diện file** (loại, ngôn ngữ, có pack không): `file`, DIE, `strings`, capa/FLOSS. Chưa decompile vội.
2. **Convert to readable code**: ném vào IDA/Ghidra; ngôn ngữ lạ thì tự code mẫu rồi compile ném vào để học pattern (xem mục 4).
3. **Đảm bảo decompile đủ**: không còn hàm/nhánh bị bỏ sót (pycdc, pylingual hay thiếu). Thiếu mà bước sau cần mảnh đó thì phải quay lại.
4. **Tìm đoạn check flag và output mong đợi** – việc quan trọng nhất. Nếu có hàm in flag độc lập với input, **patch để chạy thẳng tới đó**.
5. **Tìm related artifact**: các biến/tệp/dữ liệu ảnh hưởng tới output (kể cả TLS callback, constructor, hàm khởi tạo).
6. **Review code check** (static trước, debug sau): đọc một lượt toàn bộ thông tin liên quan rồi mới debug khi đọc không nổi.
7. **Viết lại thuật toán** (Python/C) khi đọc chay quá tải; kiểm tra từng đoạn bằng giá trị thật.
8. **Tìm cách đảo**: đảo trực tiếp, brute force, z3/angr, tra cứu trên mạng (khi có Internet).
9. Lấy flag.

> Nguyên tắc: **static nhiều nhất có thể**, debug khi bất khả kháng; luôn tự hỏi *"có đảo ngược từ kết quả mong muốn về input được không, hay phải brute force?"*

## 3. Những lối đi tắt

- Hàm in flag không phụ thuộc input → patch nhảy tới.
- Check bằng so sánh với mảng hằng → lấy mảng, **đảo thuật toán** hoặc dump runtime ngay trước `strcmp/memcmp`.
- Biết ngôn ngữ/trình biên dịch → lọc bỏ code của runtime, chỉ đọc phần do tác giả viết (xem mục 4).
- Hằng số đặc trưng → tra thuật toán trong [00-nhan-dien-nhanh.md](00-nhan-dien-nhanh.md), có khi tìm được cả mã nguồn gốc.

## 4. Học pattern bằng cách tự compile (nền tảng của cả bộ ghi chú này)

Khi gặp ngôn ngữ/trình biên dịch/thuật toán mới:

1. Tự viết chương trình nhỏ tương đương, **compile bằng đúng công cụ** (hoặc gần đúng).
2. Ném vào IDA/Ghidra, xem nó trông thế nào ở `-O0`/`-O2`/MSVC.
3. Đối chiếu với binary đề → khoanh vùng **code do tác giả viết** (quan trọng) và **code do trình biên dịch sinh** (bỏ qua).

Các trang thuật toán trong thư mục này làm đúng việc đó cho ~25 thuật toán phổ biến.

## 5. Các dạng đặc biệt

| Dạng | Điểm mấu chốt |
|---|---|
| **VM tự chế** | Xác định số instruction, cấu trúc (opcode, toán hạng), nơi đọc bytecode; **dịch bytecode thành chuỗi lệnh đọc được**, rồi giải bài toán thuật toán. Khó ở việc trích code từ tệp VM |
| **Custom packer** | Xác định thuật toán pack để trích mã sau giải; hoặc debug qua packer rồi dump |
| **Code lớn/ obfuscate** | Tách block, giải từng block; tìm opaque predicate/constant folding; chỉ reverse các path chắc chắn tới flag |
| **Code từ thư viện có sẵn** | Trích hằng → tra GitHub; tạo **file chữ ký** (FLIRT/sig) để IDA nhận hàm thư viện |
| **Symbolic execution** | `z3` và `angr` cho các case check dạng ràng buộc (sẽ có template ở phần sau) |

## 6. Khi nào debug

- Đã đọc static một lượt, hiểu pattern chạy từ đầu tới cuối.
- Code static không đủ thông tin (key sinh runtime, self-modifying).
- Cần dump dữ liệu giải mã tại thời điểm chạy.

Ngược lại, nếu phải debug ngay từ đầu vì đọc không nổi: nghĩ lại bước 2–3 (có thể decompile chưa đủ).
