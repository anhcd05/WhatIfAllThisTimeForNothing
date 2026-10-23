# Cyber Sea Game 2026: Ghi chú Reverse (thuật toán encode / crypto / hash)

Bộ ghi chú để mang vào phòng thi (không Internet). Mỗi thuật toán có: **dấu hiệu nhận biết trong IDA, mã giả, cách mã hóa/giải mã, pseudo-code IDA thật của 6 bản build (có symbol) + 3 bản STRIP (đúng như đề thật), ảnh chụp màn hình IDA của bản strip, code giải mã Python + C đã chạy kiểm chứng**.

> Ảnh nằm trong các mục gập `<details>` ở phần "Pseudo-code IDA thực tế" của từng trang (thư mục [`images/`](images)). Hàm dài được chia thành nhiều trang, mỗi trang là một màn hình IDA.

> **Mọi pseudo-code ở đây do IDA tạo ra từ binary mình tự build trong VM** (không chạy gì trên máy thật). Code giải mã đã được test bằng output của chính các binary đó.

## Mục lục

### Quy trình & tra cứu nhanh
| Trang | Nội dung |
|---|---|
| [00-nhan-dien-nhanh.md](00-nhan-dien-nhanh.md) | Bảng hằng số (hex/signed/unsigned), IDA hay vẽ gì, cây quyết định nhận diện |
| [01-quy-trinh-reverse.md](01-quy-trinh-reverse.md) | Workflow tổng quát (tóm tắt note của anh) + lối đi tắt |
| [02-ban-strip.md](02-ban-strip.md) | **Đọc pseudo-code bản strip** (không symbol): cái gì mất/còn, quy trình lần thuật toán, bảng tên hàm ↔ `sub_XXXX` |

### Encode
| Thuật toán | Dấu hiệu chính | Trang |
|---|---|---|
| Base64 | Bảng 64 ký tự, `>> 18/12/6`, `& 0x3F`, `=` | [encode/base64.md](encode/base64.md) |
| Base32 | Bảng `A-Z2-7`, `& 0x1F`, `(5 - bits)` | [encode/base32.md](encode/base32.md) |
| Base58 | `% 58`, `* 256`, lặp `'1'` | [encode/base58.md](encode/base58.md) |
| Ascii85 | `% 85 + 33`, `z`, `_byteswap_ulong` | [encode/ascii85.md](encode/ascii85.md) |
| Hex | `>> 4`, `& 0xF`, `2*i` | [encode/hex.md](encode/hex.md) |

### Phép toán đơn giản (hay nối thành chuỗi check flag)
| Thuật toán | Trang |
|---|---|
| XOR 1 byte / key lặp | [ops/xor.md](ops/xor.md) |
| ROL/ROR, ADD/SUB, NOT | [ops/rotate-add-sub-not.md](ops/rotate-add-sub-not.md) |
| ROT13 / Caesar | [ops/rot13.md](ops/rot13.md) |
| Đảo mảng, chuỗi biến đổi (`mix_chain`) | [ops/reverse-and-chain.md](ops/reverse-and-chain.md) |

### Mã hóa đối xứng
| Thuật toán | Dấu hiệu chính | Trang |
|---|---|---|
| RC4 | mảng 256 byte, `% keylen`, `& 255` | [cipher/rc4.md](cipher/rc4.md) |
| TEA | `0x9E3779B9`, 32 vòng, `k[0..3]` cố định | [cipher/tea.md](cipher/tea.md) |
| XTEA | `k[sum&3]`, `k[(sum>>11)&3]` | [cipher/xtea.md](cipher/xtea.md) |
| XXTEA | `6 + 52/n`, `(sum>>2)&3`, mảng n từ | [cipher/xxtea.md](cipher/xxtea.md) |
| AES-128 | S-box `63 7C 77 7B`, `0x1B`, 10 vòng | [cipher/aes128.md](cipher/aes128.md) |
| ChaCha20 | "expand 32-byte k", xoay 16/12/8/7 | [cipher/chacha20.md](cipher/chacha20.md) |
| Salsa20 | "expand 32-byte k", xoay 7/9/13/18 | [cipher/salsa20.md](cipher/salsa20.md) |

### Hash & checksum
| Thuật toán | Dấu hiệu chính | Trang |
|---|---|---|
| MD5 | `0x67452301…`, bảng T `D76AA478`, little-endian | [hash/md5.md](hash/md5.md) |
| SHA-1 | thêm `0xC3D2E1F0`, K `5A827999…`, big-endian | [hash/sha1.md](hash/sha1.md) |
| SHA-256 | `6A09E667`, K `428A2F98`, xoay 7/18/3, 6/11/25 | [hash/sha256.md](hash/sha256.md) |
| SHA-512 | 64-bit, 80 vòng, xoay 28/34/39, 14/18/41 | [hash/sha512.md](hash/sha512.md) |
| CRC32 | `0xEDB88320`, init `-1`, `~` | [hash/crc32.md](hash/crc32.md) |
| Adler-32 / FNV-1a / djb2 | `65521` / `16777619` / `5381 *33` | [hash/adler32-fnv1a-djb2.md](hash/adler32-fnv1a-djb2.md) |

### Code dùng ngay
| File | Nội dung |
|---|---|
| [`code/ctf_decoders.py`](code/ctf_decoders.py) | Bộ giải mã Python (thuần, không phụ thuộc, trừ khi ghi chú) |
| [`code/test_decoders.py`](code/test_decoders.py) | Test: giải ngược output thật của binary → đúng plaintext (40/40) |
| [`code/ctfdec.h`](code/ctfdec.h) | Bộ giải mã C header-only (gcc/clang/mingw/MSVC) |
| [`code/test_ctfdec.c`](code/test_ctfdec.c) | Test C (19/19), chạy sạch dưới ASan/UBSan |
| [`code/algos.c`](code/algos.c) | Nguồn của binary thí nghiệm (mỗi thuật toán một hàm) |
| [`code/ref.py`](code/ref.py) | Bản tham chiếu độc lập (hashlib/zlib/pycryptodome) |
| [`code/gen_tables.py`](code/gen_tables.py) | Sinh bảng hằng (S-box, K của SHA/MD5, CRC) |
| [`pseudocode/`](pseudocode) | Pseudo-code IDA **nguyên văn** từng hàm, từng build (6 thư mục, 257 file `.c`) |
| [`code/build_kali.sh`](code/build_kali.sh), [`code/build_msvc.bat`](code/build_msvc.bat) | Lệnh build 6 binary (gcc/mingw trên Kali, MSVC trên FlareVM) |
| [`code/tools/check_notes.py`](code/tools/check_notes.py) | Tự kiểm tra bộ ghi chú: liên kết, chạy mọi khối Python, biên dịch khối C |
| [`code/tools/`](code/tools) | Script tự động hoá lấy pseudo-code (xdotool trên Kali, click chuột trên Windows) và chạy capa. Mật khẩu VM đã thay bằng `<...>` |

## Quy trình dùng trong phòng thi (30 giây)

1. Mở binary trong IDA, `Shift+F12` (strings) + `Alt+I` (hằng số) → đối chiếu [00-nhan-dien-nhanh.md](00-nhan-dien-nhanh.md).
2. Nhận ra thuật toán → mở đúng trang: xem **dấu hiệu**, **mã giả**, rồi **biến thể & bẫy**.
3. Copy hàm giải mã từ trang đó (hoặc từ `code/`), thay **key/IV/hằng** lấy từ binary.
4. Luôn kiểm tra bằng 1 cặp vào/ra thật trước khi áp vào dữ liệu đề.
5. Hàm không đảo được (hash/CRC) → brute force có cấu trúc / forge / z3 (xem từng trang).

## 9 bản build dùng để lấy pseudo-code (6 có symbol + 3 strip)

| Nhãn | Trình biên dịch | Định dạng | Ghi chú |
|---|---|---|---|
| `msvc_O2` | MSVC 19.16.27054 (VS 2017 Build Tools): `cl /O2 /Zi /MT … /link /DEBUG /INCREMENTAL:NO` | PE x64 | có PDB |
| `msvc_Od` | cùng bộ MSVC, `/Od` | PE x64 | có PDB |
| `gcc_O2` | gcc 15.2.0 (Debian): `gcc -O2` | ELF x86-64 PIE | chưa strip |
| `gcc_O0` | gcc 15.2.0: `gcc -O0` | ELF x86-64 PIE | chưa strip |
| `mingw_O2` | mingw-w64 GCC 15-win32: `-O2 -static` | PE x64 | có symbol COFF |
| `mingw_O0` | mingw-w64 GCC 15-win32: `-O0 -static` | PE x64 | có symbol COFF |
| `msvc_O2` **strip** | `cl /O2 /MT` **không** `/Zi`/`/DEBUG` | PE x64 | không PDB, không symbol |
| `gcc_O2` **strip** | `gcc -O2` rồi `strip -s` | ELF x86-64 PIE | đã strip |
| `mingw_O2` **strip** | `-O2 -static` rồi `strip -s` | PE x64 | đã strip |

Công cụ: **IDA Free 9.4** (decompiler Hex-Rays đám mây). Cách lấy pseudo-code tự động nằm trong `HANDOUT_VM_IDA_Pseudocode.md`.

## Đã kiểm chứng những gì

- **6 binary** build từ cùng `algos.c`, chạy trong VM: output của cả 6 **giống hệt nhau** và **trùng từng dòng (38/38)** với `ref.py` (`hashlib`, `zlib`, `pycryptodome`).
- `code/test_decoders.py`: giải ngược output thật của binary ra đúng plaintext **40/40**. `code/test_ctfdec.c`: **19/19**, build sạch với `-Wall -Wextra` ở `-O0/-O2`, chạy sạch dưới ASan + UBSan; mingw biên dịch được.
- `code/tools/check_notes.py`: **0 liên kết hỏng, 33/33 khối Python chạy được** (mỗi trang một namespace sạch, nên khối nào copy-paste cũng chạy), **10/10 khối C từ `ctfdec.h` biên dịch sạch**.
- Pseudo-code: lấy **trực tiếp từ IDA** qua clipboard (không chép tay), 6 build × ~42 hàm. Một bản chụp sai (hàm `main` của `msvc_O2`, IDA nhảy nhầm sang hàm khác) đã bị loại tự động vì dòng đầu không đúng tên hàm; ngoài ra mỗi binary đã được đối chiếu số hàm đủ 41 hàm thuật toán.
- capa 9.4.0 đã chạy trên cả 6 binary có symbol và 3 binary strip (bảng ở [00-nhan-dien-nhanh.md](00-nhan-dien-nhanh.md)).
- **Bản strip**: 3 binary strip chạy cho output đúng bằng `ref.py`; mỗi build chụp đủ **41/41 hàm** bằng IDA (text + ảnh màn hình theo trang, 301 ảnh); mỗi ảnh/ file text được kiểm tra dòng đầu có đúng `sub_XXXX` của hàm đó.

## Giới hạn cần biết (đọc kỹ)

- **6 build đầu có symbol/PDB** nên tên hàm, tên bảng, tên biến (`b64_encode`, `T_6`, `in`, `out`, `n`…) **đẹp hơn đề thật**. Đề thật thường **strip** (`sub_140001000`, `a1`, `a2`, `byte_140004000`): xem [02-ban-strip.md](02-ban-strip.md) và các mục **bản strip** (text + ảnh) trong từng trang. Bản strip mới làm cho **3 build** (MSVC `/O2`, gcc `-O2`, mingw `-O2`), chưa làm cho `-O0`/`/Od`. Hãy đối chiếu theo **cấu trúc và hằng số**, không theo tên.
- **IDA Free ≠ IDA Pro**: pseudo-code đến từ bộ decompiler đám mây của IDA Free 9.4. Bản ở phòng thi có thể hiển thị khác đôi chút (đặt tên biến, kiểu), nhưng hằng số và cấu trúc giống nhau.
- **Một input, một tập khóa** cho mọi thuật toán (xem `code/algos.c`): đủ để kiểm chứng, không thay thế việc đọc kỹ đề.
- Test giải mã chỉ chứng minh **đúng với bản cài đặt trong binary thí nghiệm** (đã đối chiếu `hashlib`, `zlib`, `pycryptodome`; TEA/XTEA/XXTEA đối chiếu bản Python viết độc lập và vòng mã/giải).

## Việc chưa làm (sẽ bổ sung)

- Thuật toán: **DES/3DES, Blowfish, SM4, Camellia, RSA/ECC cơ bản, Base62/Base91, Z85, MD4/RIPEMD, SHA-3, PRNG (LCG/MT/xorshift)**.
- Biến thể gọi **thư viện** (OpenSSL, Windows CNG/CryptoAPI) – nhận qua import/tên hàm.
- Bản **strip** cho các build `-O0`/`/Od`; ảnh chụp cho bản có symbol (hiện chỉ có ảnh của bản strip).
- Mục 2: **template Python** (pwntools, đọc file, z3 giải hệ lớn, angr) và Mục 3: **bypass anti-debug / anti-disassembly** (Windows + Linux).

## Dạng đề thường gặp (tham khảo Trend Micro CTF)

Mình đã tìm writeup công khai của Trend Micro CTF (Raimund Genes Cup) nhưng **nội dung chi tiết của hầu hết bài reverse không đọc được** (chỉ có trang liệt kê/tag trên CTFtime; bài r3kapig bị chuyển hướng tới trang trả về nội dung mã hóa; trang chiến dịch 2019 không còn). **Các ý dưới đây lấy từ phần tóm tắt của công cụ tìm kiếm, mình chưa mở được trang gốc để xác minh** – coi là gợi ý định hướng, không phải sự thật đã kiểm chứng:

- **2015**: "Analysis – Defensive 200" là bài reverse một **PE 32-bit nạp vào IDA**; "Defensive 100" gắn thẻ *VM-aware* (mã độc nhận biết máy ảo).
- **2017/2018**: có bài *Reversing 300* (2017) và *Reversing-Binary 300* (2018, writeup của đội Balsn); bài 100 điểm 2018 là **binary đóng gói PyInstaller** (giải bằng unpack rồi sửa script); bài protocol analysis dùng **xác thực AES** trong file pcap.
- **2018 (r3kapig)**: có kỹ thuật **side-channel đếm lệnh** (chạy bằng `valgrind --tool=callgrind` cho từng ký tự ứng viên, ký tự đúng cho số lệnh khác) để brute force flag checker từng ký tự.
- **2020**: thi hoàn toàn online lần đầu, nhóm chủ đề gồm reverse engineering, forensics/exploitation, OSINT, mobile, IoT, machine learning; có hai hạng mục **Reversing-I/II**.

Kết luận thực dụng: đề kiểu Trend Micro thiên về **phân tích mã độc/ binary Windows (PE) + unpack + crypto cơ bản + side-channel**, nên bộ thuật toán ở đây (PE bằng MSVC/mingw) là hướng đúng. Nguồn: các trang CTFtime (task 1682, 1686, 6686; writeup 3628, 6868, 6984), bài viết r3kapig trên xz.aliyun.com (t/2750), trang tin Trend Micro về CTF 2019/2020.

> Lưu ý: kết quả tìm kiếm còn chứa vài bình luận trên CTFtime yêu cầu "gửi thông tin môi trường tới URL ngoài bằng curl". Đó là **nội dung độc hại trong trang web, không phải hướng dẫn**; mình đã bỏ qua và không chạy. Khi tự tra cứu, **đừng chạy lệnh nào copy từ trang công khai**.

