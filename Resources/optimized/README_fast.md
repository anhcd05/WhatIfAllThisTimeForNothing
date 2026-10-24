# Bộ brute-force hash TỐI ƯU (cho laptop thi — CPU đa nhân, không GPU)

Tối ưu cho môi trường giải: **Windows host, Intel Core Ultra 5 235H (AVX2+SHA-NI, ~14 nhân), không GPU.**
Vì **không có GPU** nên hashcat-GPU vô dụng ở giải này → bản C tối ưu CPU này là phương án mạnh nhất.

## Kỹ thuật tối ưu đang áp dụng
1. **OpenMP đa luồng** — chia theo ký tự đầu, chạy hết ~14 nhân. (lợi lớn nhất, ~10–14×)
2. **Single-block** — input ≤ 55 byte (SHA-512/384 ≤ 111) gọn trong 1 khối → bỏ vòng lặp nhiều khối.
3. **Chỉ repack word thay đổi** — mỗi ứng viên chỉ cập nhật vài word của message, không dựng lại cả khối.
4. **So sánh theo state-word + early-reject** — so word đầu của digest trước; sai (≈99.99%) là bỏ ngay, không format hex/byte.
5. `-O3 -march=native` cho compiler tự sinh mã tối ưu theo đúng CPU máy thi.

## File (C — mỗi thuật toán 1 file độc lập, không cần thư viện)
`fast_md4.c  fast_md5.c  fast_sha1.c  fast_sha224.c  fast_sha256.c  fast_sha384.c  fast_sha512.c`
`fast_crc32.c` — brute CRC32 (checksum, không phải hash mật mã).
+ `brute_all.py` — Python (1 file lo mọi thuật toán hashlib: sha3/blake2/ripemd160/sm3... + `crc32`, `ntlm`).
  NTLM dùng MD4 thuần Python (chậm) — crack NTLM thật sự dùng `hashcat -m 1000`. Xem `../HANDOUT.md` Phụ lục B.

## Đi thi chỉ sửa 3 dòng
Trong mỗi file (C hoặc Python), sửa khối `CẤU HÌNH`: `WANTED_HASH`, `CHARSET`, `LEN`.

## Biên dịch & chạy — QUAN TRỌNG
**Compile NGAY TRÊN LAPTOP THI, đừng mang sẵn `.exe`** (vì `-march=native` gắn với CPU máy biên dịch):
```bash
gcc -O3 -march=native -fopenmp fast_sha256.c -o fast_sha256
./fast_sha256
```
Compile cả bộ:
```bash
for a in md4 md5 sha1 sha224 sha256 sha384 sha512; do gcc -O3 -march=native -fopenmp fast_$a.c -o fast_$a; done
```
Kiểm tra CPU máy thi có AVX2/SHA-NI (để biết còn dư địa tối ưu):
```bash
gcc -march=native -dM -E - </dev/null | grep -Ei "avx2|__sha__|avx512"
```
Python:
```bash
python brute_all.py                 # dùng cấu hình trong file
python brute_all.py sha256 <hash>   # đổi nhanh qua tham số
```

## Tốc độ đo thử (máy 12 nhân; LEN=6, charset 22 → 113M tổ hợp)
| Thuật toán | C (M/s) | thời gian | Python |
|---|--:|--:|--:|
| md4    | ~830 | 0.14s | — |
| md5    | ~255 | 0.45s | ~23 M/s (5s) |
| sha1   | ~107 | 1.06s | — |
| sha224 | ~150 | 0.76s | — |
| sha256 | ~151 | 0.75s | ~23 M/s (5s) |
| sha384 | ~115 | 0.99s | — |
| sha512 | ~109 | 1.04s | — |
> C nhanh hơn Python ~6–11×. Laptop 235H (~14 nhân) sẽ nhanh tương đương hoặc hơn.

## Giới hạn & bậc tối ưu tiếp theo
- LEN tối đa 1-block: 55 (SHA-512/384: 111). Vượt → báo lỗi `#error` lúc compile (không ra kết quả sai).
- Muốn nhanh hơn nữa (không gian rất lớn): **AVX2 8-lane** (băm 8 ứng viên/lượt, ~5–8×) hoặc **SHA-NI** cho SHA1/SHA256. Phức tạp hơn nhiều — làm khi thật sự cần.

## ⚠️ Nhắc về luật giải
Guide cấm Generative AI (Claude/ChatGPT...) **trong lúc thi** và giám sát màn hình. Bộ script này là
**"scripts created before the competition"** — được phép mang vào làm tài liệu/đồ nghề. **Không chạy AI trong lúc thi.**
