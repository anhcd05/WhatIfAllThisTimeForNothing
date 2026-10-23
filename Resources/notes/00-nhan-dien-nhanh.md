# 00. Nhận diện nhanh thuật toán trong IDA

> Trang tra cứu **một cú nhìn**: thấy hằng số / cấu trúc nào thì nghĩ tới thuật toán nào, và IDA thường "vẽ" chúng ra sao.

## 1. Bảng hằng số (hex / số có dấu IDA hay hiện / không dấu)

IDA (Hex-Rays) hiển thị hằng 32-bit ≥ `0x80000000` dưới dạng **số âm** (`-1640531527`) trong nhiều ngữ cảnh. Search `Alt+I` (Immediate value) nhận cả ba dạng; nếu không thấy thì thử dạng còn lại.

| Hằng số | Hex | Signed 32-bit (IDA hay hiện) | Unsigned |
|---|---|---|---|
| TEA/XTEA/XXTEA delta | `0x9E3779B9` | `-1640531527` | `2654435769` |
| MD5/SHA-1 h0 (A) | `0x67452301` | `1732584193` | `1732584193` |
| MD5/SHA-1 h1 (B) | `0xEFCDAB89` | `-271733879` | `4023233417` |
| MD5/SHA-1 h2 (C) | `0x98BADCFE` | `-1732584194` | `2562383102` |
| MD5/SHA-1 h3 (D) | `0x10325476` | `271733878` | `271733878` |
| SHA-1 h4 | `0xC3D2E1F0` | `-1009589776` | `3285377520` |
| MD5 T[0] | `0xD76AA478` | `-680876936` | `3614090360` |
| MD5 T[1] | `0xE8C7B756` | `-389564586` | `3905402710` |
| SHA-1 K0 | `0x5A827999` | `1518500249` | `1518500249` |
| SHA-1 K1 | `0x6ED9EBA1` | `1859775393` | `1859775393` |
| SHA-1 K2 | `0x8F1BBCDC` | `-1894007588` | `2400959708` |
| SHA-1 K3 | `0xCA62C1D6` | `-899497514` | `3395469782` |
| SHA-256 H0 | `0x6A09E667` | `1779033703` | `1779033703` |
| SHA-256 H1 | `0xBB67AE85` | `-1150833019` | `3144134277` |
| SHA-256 K[0] | `0x428A2F98` | `1116352408` | `1116352408` |
| SHA-256 K[1] | `0x71374491` | `1899447441` | `1899447441` |
| CRC32 poly (đảo bit) | `0xEDB88320` | `-306674912` | `3988292384` |
| CRC32 poly (thuận) | `0x04C11DB7` | `79764919` | `79764919` |
| ChaCha/Salsa 'expa' | `0x61707865` | `1634760805` | `1634760805` |
| ChaCha/Salsa 'nd 3' | `0x3320646E` | `857760878` | `857760878` |
| ChaCha/Salsa '2-by' | `0x79622D32` | `2036477234` | `2036477234` |
| ChaCha/Salsa 'te k' | `0x6B206574` | `1797285236` | `1797285236` |
| FNV-1a offset basis | `0x811C9DC5` | `-2128831035` | `2166136261` |
| FNV-1a prime | `0x01000193` | `16777619` | `16777619` |
| djb2 init | `0x00001505` | `5381` | `5381` |
| Adler-32 modulus | `0x0000FFF1` | `65521` | `65521` |

| Hằng số 64-bit | Hex | Signed 64-bit | Unsigned |
|---|---|---|---|
| SHA-512 H0 | `0x6A09E667F3BCC908` | `7640891576956012808` | `7640891576956012808` |
| SHA-512 K[0] | `0x428A2F98D728AE22` | `4794697086780616226` | `4794697086780616226` |

Các chuỗi bảng chữ cái:

| Bảng | Chuỗi |
|---|---|
| Base64 chuẩn | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` |
| Base32 (RFC 4648) | `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567` |
| Base58 (Bitcoin) | `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` |
| Hex | `0123456789abcdef` |

Các bảng byte (tìm bằng `Alt+B` / Search → Bytes):

| Bảng | 8 byte đầu |
|---|---|
| AES S-box | `63 7C 77 7B F2 6B 6F C5` |
| AES inverse S-box | `52 09 6A D5 30 36 A5 38` |
| AES Rcon | `01 02 04 08 10 20 40 80 1B 36` |
| CRC32 table (LE) | `00 00 00 00 96 30 07 77` |
| SHA-256 K (LE) | `98 2F 8A 42 91 44 37 71` |
| MD5 T (LE) | `78 A4 6A D7 56 B7 C7 E8` |

## 2. IDA hay vẽ gì (đã quan sát trên 6 bản build)

| Hiện tượng | Ý nghĩa |
|---|---|
| `v -= 1640531527` | TEA/XTEA/XXTEA: cộng delta `0x9E3779B9` hiện thành **trừ `0x61C88647`** |
| `__ROL4__(x, n)`, `__ROR4__(x, n)`, `__ROL1__`, `_rotl`, `_rotr` | Phép xoay bit. **ROL 18 hiện thành ROR 14** (ROL `n` = ROR `32-n`). **MSVC `/Od` với lượng xoay là hằng số thường không dùng các hàm này**: nó viết thẳng cặp dịch `(x >> 25) \| (x << 7)` (ChaCha/Salsa/SHA); với lượng xoay là biến 32-bit vẫn hiện `__ROL4__(x, k)`. gcc/mingw và MSVC `/O2` dùng `__ROL4__`/`__ROR4__` |
| `(x >> 31) \| (2 * x)`, `(a >> 27) \| (32 * a)` | Xoay viết bằng **hai phép dịch** (ROL1, ROL5) ở bản không tối ưu (`/Od`, `-O0`): hai lượng dịch cộng lại bằng 32 (hoặc 8 với byte) |
| `BYTE1(v)`, `BYTE2(v)`, `HIBYTE(v)` | Tách từng byte của một giá trị lớn: ghi độ dài bit **big-endian** (SHA) hay đảo byte |
| `_byteswap_ulong(x)` | Đọc/ghi **big-endian** (SHA, Ascii85) |
| `(unsigned __int8)(a + b)` | Phép `& 0xFF` ngầm (RC4, hash 8-bit) |
| `x / 58`, `x % 85`, `% 0xFFF1` | Chia cho hằng: Base58/Ascii85/Adler (ở assembly là nhân số ma thuật) |
| `16 * v` / `4 * v` | `v << 4` / `v << 2` (TEA, XXTEA) |
| `T_6[...]`, `H_2[...]`, `byte_XXXX[...]` | Bảng tra tĩnh (Base64/hex/S-box…). Đổi tên ngay khi nhận ra |
| Khối `__m128i`, `_mm_xor_si128`, `_mm_add_epi8`, `_mm_loadu_si128` | gcc `-O2` **vector hóa** vòng byte (XOR/ADD/NOT/ROL). Phần SSE chỉ là "làm 16 byte một lúc"; phần đuôi viết lại như vòng thường |
| `LOBYTE(v)`, `LODWORD(v)`, `HIDWORD(v)` | Truy cập một phần của biến lớn |
| `LABEL_n` / `goto` dày đặc | Tối ưu `-O2` làm vòng lặp "xoắn": đọc theo luồng điều khiển |
| Hàm gần như rỗng chỉ `return __ROL4__(a1, a2);` | Hàm bọc phép xoay (`op_rol32`) |
| `memmove(a1: buf, Val: 0, Size: 320)`, `strchr(s: "ABC...", c: v3)`, `fopen(filename: "flag.png", modes: "rb")` | IDA 9 in **tên tham số** trong lời gọi hàm thư viện. `memmove(.., Val: 0, ..)` thực ra là `memset`; đọc tên tham số để suy ra hàm thật |
| `memcpy`/`memmove` kích thước hằng ngay đầu hàm hash | Thân thông điệp được chép vào bộ đệm có padding (`0x80`, độ dài bit) |
| Cùng một biểu thức lặp lại hàng chục lần (`v10 -= 1640531527; …`) | Trình biên dịch **bung vòng**: MSVC `/O2` bung XTEA thành 2 lần lặp × 16 vòng. MSVC `/O2` còn bung MD5 thành 4 bước mỗi lần lặp (16 lần × 4). SHA-1/SHA-256/SHA-512 ở các build thí nghiệm vẫn giữ vòng; chỉ đề tự bung hoàn toàn mới rải 64 hằng K |

## 3. Cây quyết định nhanh

```
Có mảng 256 byte hoán vị + vòng "% độ dài key"?            -> RC4
Có bảng 256 byte bắt đầu 63 7C 77 7B?                      -> AES (S-box)
Hằng 0x9E3779B9 / -1640531527 / 0x61C88647?                -> TEA | XTEA | XXTEA
    k[sum&3], k[(sum>>11)&3]                                -> XTEA
    52/n + 6 vòng, mảng n từ                                -> XXTEA
    k[0..3] cố định, 2 từ                                   -> TEA
4 hằng "expa"+"nd 3"+"2-by"+"te k"?                        -> ChaCha20 | Salsa20
    xoay 16/12/8/7                                          -> ChaCha20
    xoay 7/9/13/18 (hay thấy ROR 14)                        -> Salsa20
0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476?               -> MD5 | SHA-1
    + 0xC3D2E1F0, K=5A827999..                              -> SHA-1
    bảng T (D76AA478), xoay 7/12/17/22                      -> MD5
0x6A09E667...? K bắt đầu 428A2F98?                          -> SHA-256 (32-bit) | SHA-512 (64-bit, 80 vòng)
0xEDB88320, init -1, ~ cuối?                                -> CRC32
65521 (0xFFF1)?                                             -> Adler-32
2166136261 / 16777619?                                      -> FNV
5381 và "* 33"?                                             -> djb2
Chuỗi 64 ký tự khác nhau + ">> 18, >> 12, >> 6, & 0x3F"?   -> Base64 (custom alphabet nếu bảng lạ)
"% 58" + "* 256" + lặp '1'?                                  -> Base58
"% 85 + 33"?                                                -> Ascii85
Chỉ ^ / ROL / + / - / ~ trên từng byte, mảng hằng so sánh?  -> chuỗi biến đổi: đảo từng phép
```

## 4. Công cụ nhận diện tự động (có sẵn trên FlareVM)

| Công cụ | Đường dẫn | Dùng để |
|---|---|---|
| **capa** | `C:\Tools\capa\capa.exe` | Liệt kê hành vi: "hash data with MD5/SHA", "encrypt data using RC4/AES" dựa trên hằng và mã |
| **FLOSS** | `C:\Tools\FLOSS\floss.exe` | Trích chuỗi bị mã hóa/stack string |
| **Detect It Easy** | `C:\Tools\die\die.exe` | Nhận trình biên dịch, packer, hằng crypto (tab Signatures) |
| **CyberChef** | `C:\Tools\CyberChef\CyberChef_v11.0.0.html` | Thử decode/giải mã nhanh (offline, mở bằng trình duyệt) |
| **x64dbg** | `C:\Tools\x64dbg\release\x64\x64dbg.exe` | Debug/ dump key runtime |

> Ở phòng thi không có Internet: kiểm tra các công cụ này đã nằm sẵn trong máy thi, hoặc chuẩn bị **bản portable** trước.

### capa 9.4.0 trên 6 binary thí nghiệm (đã chạy thật)

`capa.exe -q <file>` mất khoảng **4 phút** cho mỗi binary ~400 KB trên FlareVM (chờ lâu, nên chạy nền trong lúc đọc tay). Kết quả ("Y" = có báo, "-" = không báo):

| Capability của capa | msvc /O2 | msvc /Od | gcc -O2 | gcc -O0 | mingw -O2 | mingw -O0 |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| hash MD5 / SHA-1 / SHA-256 / SHA-512 | Y | Y | Y | Y | Y | Y |
| hash CRC32 | Y | Y | Y | Y | Y | Y |
| hash FNV / djb2 | Y | Y | Y | Y | Y | Y |
| encrypt AES (kèm "reference AES constants") | Y | Y | Y | Y | Y | Y |
| encrypt RC4 (PRGA) | Y | Y | Y | Y | Y | Y |
| encrypt Salsa20/ChaCha (gộp chung hai loại) | Y | Y | Y | Y | Y | Y |
| encrypt/decrypt TEA, encrypt XTEA | Y | Y | Y | Y | Y | Y |
| encode Base64 (+ "reference Base64 string") | Y | Y | Y | Y | Y | Y |
| "reference Base58 string" | Y | Y | Y | Y | Y | Y |
| encrypt **XXTEA** | - | - | Y | - | Y | - |
| encode **XOR** | Y | - | Y | - | Y | - |
| ~~hash murmur3~~ (**dương tính giả**) | Y | - | - | Y | - | Y |
| ~~encrypt speck~~ (**dương tính giả**) | Y | - | - | Y | - | Y |
| Base32, Ascii85, Adler-32, ROT13, ROL/ROR/ADD/SUB/NOT, chuỗi biến đổi | - | - | - | - | - | - |

Rút ra:

- capa **rất tốt cho hash và cipher có hằng/bảng đặc trưng** (MD5, SHA, CRC32, AES, RC4, TEA, ChaCha/Salsa), bất kể trình biên dịch hay mức tối ưu.
- capa **bỏ sót** Base32/Ascii85/Adler-32 và mọi phép toán đơn giản; XXTEA và XOR chỉ được báo ở một số build → vẫn phải đọc tay theo bảng hằng số (mục 1), cây quyết định (mục 3) của trang này và các trang thuật toán.
- Có **dương tính giả** (Speck, MurmurHash): đừng tin capa tuyệt đối, luôn đối chiếu bằng hằng số/cấu trúc.
- **Bản strip cho kết quả gần như y hệt** (đã chạy lại trên 3 binary strip): capa dựa vào hằng số và mẫu lệnh chứ không dựa vào tên, nên MD5, SHA-1/256/512, CRC32, FNV, djb2, AES, RC4, Salsa20/ChaCha, TEA, XTEA, Base64 đều vẫn được báo ở cả ba bản strip (MSVC `/O2`, gcc `-O2`, mingw `-O2`). Khác biệt nhỏ: XXTEA chỉ báo ở gcc/mingw (như bản có symbol, không báo ở MSVC); XOR được báo ở cả ba bản strip; hai dương tính giả **Speck** và **MurmurHash** chỉ xuất hiện ở MSVC `/O2`.

## 5. Cách tự tái tạo thí nghiệm

Toàn bộ binary trong bộ ghi chú sinh từ [`code/algos.c`](code/algos.c): mỗi thuật toán là một hàm `noinline`, `main` đọc input từ `argv[1]` và in kết quả. Cách dựng lại:

```bash
python3 code/gen_tables.py code/tables.h                     # sinh S-box, K, CRC...
gcc -O0 -o algos_gcc_O0 code/algos.c ; gcc -O2 -o algos_gcc_O2 code/algos.c
x86_64-w64-mingw32-gcc -O2 -static -o algos_mingw_O2.exe code/algos.c
cl /O2 /Zi /MT code\algos.c /link /DEBUG /INCREMENTAL:NO    # MSVC (vcvars64.bat)
```

Đối chiếu đúng/sai bằng `python code/ref.py` (dùng `hashlib`, `zlib`, `pycryptodome`): output phải **trùng từng dòng** với binary.
