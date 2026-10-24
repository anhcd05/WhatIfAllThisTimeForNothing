# Bộ brute-force hash thuần C (không phụ thuộc thư viện)

Mỗi thuật toán 1 file độc lập, **cùng một template**. Phần `main()` (vòng brute) giống hệt nhau ở mọi file; chỉ khác phần cài thuật toán và `DIGEST_LEN`.

## Đi thi chỉ sửa 3 dòng
Mở file tương ứng, sửa khối `CẤU HÌNH` ở đầu:
```c
#define WANTED_HASH "..."                      // hash cần tìm (chuỗi hex)
#define CHARSET     "ABCDEFabcdef0123456789"   // tập ký tự thử
#define LEN         6                          // độ dài chuỗi
```
Rồi biên dịch và chạy.

## Danh sách file

| File | Thuật toán | Digest (byte) | Hash hex dài | LEN tối đa* |
|---|---|---|---|---|
| `brute_md4.c`    | MD4     | 16 | 32  | 55  |
| `brute_md5.c`    | MD5     | 16 | 32  | 55  |
| `brute_sha1.c`   | SHA-1   | 20 | 40  | 55  |
| `brute_sha224.c` | SHA-224 | 28 | 56  | 55  |
| `brute_sha256.c` | SHA-256 | 32 | 64  | 55  |
| `brute_sha384.c` | SHA-384 | 48 | 96  | 111 |
| `brute_sha512.c` | SHA-512 | 64 | 128 | 111 |

*Các bản này băm **1 block** cho gọn (đủ cho brute chuỗi ngắn). Đặt `LEN` quá giới hạn sẽ báo lỗi biên dịch (`#error`) chứ không cho ra kết quả sai.

## Biên dịch & chạy
Một file:
```bash
gcc -O2 brute_sha256.c -o brute_sha256
./brute_sha256
```
Tất cả:
```bash
for a in md4 md5 sha1 sha224 sha256 sha384 sha512; do gcc -O2 brute_$a.c -o brute_$a; done
```

## Kiểm chứng
`WANTED_HASH` mặc định trong mỗi file là hash của chuỗi `"Dec0d3"` bằng đúng thuật toán đó, nên chạy thử sẽ ra:
```
FOUND: Dec0d3
```
Thấy dòng này tức là bản cài đặt chạy đúng. Sau đó thay `WANTED_HASH` bằng hash đề bài là dùng được.

## Tăng tốc
- Các bản này **1 luồng** cho dễ đọc/sửa. Muốn nhanh hơn: thêm `#pragma omp parallel for` vào vòng ngoài rồi biên dịch với `-fopenmp` (xem `../md5_brute.c` — bản MD5 đa luồng mẫu).
- Không gian lớn / hash chuẩn: dùng **hashcat** (GPU) sẽ nhanh hơn mọi code CPU:
  ```bash
  hashcat -a 3 -m <mode> <hash> -1 ABCDEFabcdef0123456789 ?1?1?1?1?1?1
  ```
  (mode: MD5=0, SHA1=100, SHA256=1400, SHA512=1700, SHA224=1300, SHA384=10800, MD4=900)

## Khi nào mới tự viết C thế này?
- Khi **không được dùng thư viện/không có hashcat**, hoặc để học.
- Khi hash là **tổ hợp lạ/không chuẩn** mà công cụ sẵn không biểu diễn được
  (vd `md5(sha1(x) + salt)`, charset/biến đổi kỳ quặc). Lúc đó bạn ghép các hàm `hash()` này lại là xong.
- Hash chuẩn + không gian lớn → cứ hashcat/John cho nhanh, khỏi tự viết.
