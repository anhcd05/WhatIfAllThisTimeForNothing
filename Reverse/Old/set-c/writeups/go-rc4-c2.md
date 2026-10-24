# go-rc4-c2

- **Category:** Reverse Engineering (Go binary + RC4)
- **File đề:** `fakeC2.exe` (binary Go — mô phỏng "implant" nói chuyện với C2 server). Thư mục `challenges/go-rc4-c2/` kèm `description.txt` và `solve.py` (RC4 solver). *(Lưu ý: trong repo không có sẵn binary; khóa + ciphertext lấy từ `solve.py` và lời giải gốc — phân tích hoàn toàn dựa trên dữ liệu, không chạy binary.)*

## Tóm tắt đề

`description.txt`: binary là bản mô phỏng đơn giản của một **implant** giao tiếp với C2 server để chạy "task" tùy ý; nhiệm vụ là phân tích file và trích flag.

Thực chất binary vừa là **server** vừa là **client** chạy cục bộ (fake C2). Flag đã bị **RC4-mã hóa** và nhúng sẵn; chỉ khi gửi đúng `decryptkey` thì server mới RC4-giải mã và trả JSON chứa flag. Khóa cũng nằm ngay trong binary → không cần brute, không cần chạy.

## Phân tích (chi tiết: khóa/ciphertext thật)

### Luồng chương trình (reverse từ symbol Go)

- `main.main` → gọi `main.startServer` (đăng ký 2 route HTTP `/check` và `/post`) rồi `main.runClient`.
- `main.runClient`: GET `http://127.0.0.1:5555/check`, hỏi người dùng nhập decrypt key, POST JSON `{"decryptkey": <key>}` tới `/post`, in phản hồi.
- Handler `/post` (`main.startServer.func2`): `json.Unmarshal` body → lấy `decryptkey` → so với global `main.expectedKey`. Khớp → **RC4-decrypt** buffer `main.flag` rồi trả plaintext; sai → trả lỗi.

### Hai global cần trích (từ section dữ liệu)

- **`main.expectedKey`** = `"RC4JsonMarshalLocalC2"` (21 ký tự) — chính là **khóa RC4**.
- **`main.flag`** = buffer **73 byte** ciphertext (đã đối chiếu `len(CT) == 73` trên `solve.py`):

```
03 7a 4f 22 e6 c8 8b 3a fd 49 cc 56 13 a9 16 56
c7 fb 91 59 cf 7b a4 d3 ab 1a 38 94 33 28 9e 80
08 92 49 9c aa 59 f1 0f bc 6b 5f ea 7b f6 c2 8a
f9 cb ae 86 4e bd 4e 10 19 68 2d e8 38 48 69 52
da af 38 fe c8 32 6d 83 1a
```

Thuật toán là **RC4** chuẩn (KSA xáo S-box 256 phần tử + PRGA hoán vị & XOR). Tên khóa `RC4JsonMarshal…` gợi thẳng: RC4 + `json.Marshal` (plaintext là JSON).

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Reverse Go binary:** Go giữ nguyên tên symbol dạng `package.Function` (vd `main.main`, `main.startServer`, closure `main.startServer.func2`) nếu không strip. VÌ SAO hữu ích: mở Ghidra/IDA thấy ngay tên hàm → lần ra logic cực nhanh; dùng `strings`/**GoReSym**/redress để lấy `expectedKey`, tên route và vị trí buffer `flag`. Nhận diện Go qua `go:buildid`, `runtime.`, `.gopclntab` (magic `fb ff ff ff` / `f0 ff ff ff`), đường build `/usr/local/go/src/...`.
- **Nhận ra RC4:** thấy vòng KSA (khởi tạo `S=0..255`, 256 bước hoán vị theo khóa) + PRGA (hoán vị + XOR); cộng tên khóa → RC4. Server trả lỗi khi sai key cho biết key so sánh **tĩnh** và nằm trong binary.
- **Khóa + ciphertext đều nhúng sẵn → giải offline.** VÌ SAO không chạy binary: RC4 **đối xứng** (mã hóa = giải mã), chỉ cần khóa + ciphertext là đủ; tránh dựng server/mở cổng 5555, an toàn hơn.

### Vì sao đọc Go binary "khó chịu" hơn C

- **Chuỗi không có NUL kết thúc:** Go lưu `string` là struct `{ptr, len}`; trong binary các chuỗi dính thành một "blob" (vd `…RC4JsonMarshalLocalC2expectedKeyinvalid…`). Muốn tách đúng `expectedKey` (21 ký tự) phải xem nơi code nạp cặp `(ptr, 21)`.
- **ABI thanh ghi (Go ≥1.17):** tham số truyền qua thanh ghi rồi tràn stack → disassembly khó đọc nếu không có công cụ nhận diện.
- **Nhiều hàm runtime/GC** → phải lọc lấy `main.*`.

## Lời giải chi tiết (chạy lại được)

### Bước 1 — Trích khóa + ciphertext từ binary

Mở Ghidra/IDA (hoặc GoReSym) → tìm `main.expectedKey` = `RC4JsonMarshalLocalC2` và dump 73 byte `main.flag`. Trong Ghidra, tìm cross-reference tới hàm RC4 để xác định đúng 2 buffer này.

### Bước 2 — RC4 giải mã offline (`solve.py`, KHÔNG chạy binary)

```python
KEY = b"RC4JsonMarshalLocalC2"                  # main.expectedKey
CT = bytes([
    0x03,0x7a,0x4f,0x22,0xe6,0xc8,0x8b,0x3a,0xfd,0x49,0xcc,0x56,0x13,0xa9,0x16,0x56,
    0xc7,0xfb,0x91,0x59,0xcf,0x7b,0xa4,0xd3,0xab,0x1a,0x38,0x94,0x33,0x28,0x9e,0x80,
    0x08,0x92,0x49,0x9c,0xaa,0x59,0xf1,0x0f,0xbc,0x6b,0x5f,0xea,0x7b,0xf6,0xc2,0x8a,
    0xf9,0xcb,0xae,0x86,0x4e,0xbd,0x4e,0x10,0x19,0x68,0x2d,0xe8,0x38,0x48,0x69,0x52,
    0xda,0xaf,0x38,0xfe,0xc8,0x32,0x6d,0x83,0x1a,
])                                              # main.flag — đúng 73 byte

def rc4(data, key):
    S = list(range(256)); j = 0
    for i in range(256):                        # KSA: xáo S theo khóa
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:                              # PRGA: sinh keystream & XOR
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

print(rc4(CT, KEY).decode(errors="ignore"))
```

```bash
python3 solve.py
```

### Bước 3 — Output (đã kiểm chứng khi chạy solver trên dữ liệu)

```json
{"tasks":[{"task":"print_flag","flag":"flag{go_rev_startingpoint}"}]}
```

Plaintext là JSON (khớp `json.Marshal` — đúng gợi ý trong tên khóa). Trường `flag` chứa flag.

> **Minh họa KSA chạy tay** (khóa `"RC4JsonMarshalLocalC2"`, `'R'=0x52=82`, `'C'=67`):
> ```
> S = [0,1,...,255]
> i=0: j=(0+S[0]+82)&255=82    -> swap S[0]<->S[82]
> i=1: j=(82+S[1]+67)&255=150  -> swap S[1]<->S[150]
> ... 256 bước -> S đã xáo. PRGA sinh keystream k; plaintext = CT XOR k.
> ```

## Flag

```
flag{go_rev_startingpoint}
```

(Nguyên văn trường `flag` trong JSON; wrapper chuẩn hoá thành `flag{...}`.) "go rev starting point" — điểm khởi đầu cho người mới học dịch ngược binary Go.

## Gặp lại thì xử lý thế nào (playbook)

- **Dấu hiệu nhận diện:** binary lớn (vài MB), nhiều chuỗi `runtime.`, `main.`, build info Go; đề nhắc "C2/implant/task"; có route HTTP `/check` `/post`, key so sánh tĩnh.
- **Quy trình:**
  1. Xác nhận Go: `strings | grep "go1\."`, kiểm `.gopclntab` (magic `fb ff ff ff` / `f0/f1 ff ff ff`), chạy **GoReSym**.
  2. Khôi phục symbol: không strip → đọc trực tiếp; strip → GoReSym / script golang_renamer cho Ghidra.
  3. Tìm hằng số: expected key, ciphertext buffer, thuật toán (RC4 = S-box 256 + hoán vị + XOR; XOR; AES).
  4. Giải **offline** bằng hằng số — không phụ thuộc runtime/mạng. RC4 đối xứng nên dùng chính khóa đó để decrypt.
- **Công cụ:** Ghidra + GoReSym, IDA, `strings`, Python.
- **Bẫy hay gặp:** (a) mất thời gian dựng server/sniff mạng trong khi key + ciphertext đều ở trong binary; (b) tưởng RC4 cần "khóa giải mã" khác khóa mã hóa (sai — đối xứng); (c) đọc sai độ dài ciphertext — phải đúng **73 byte**, thừa/thiếu làm JSON hỏng; (d) dừng ở chuỗi `expectedKey` mà tưởng đó là flag — nó chỉ là **khóa**; flag nằm trong `main.flag` sau khi decrypt.
- **Checklist ngắn:** xác định Go → lấy symbol → tìm key + ct + thuật toán → giải offline → đọc JSON lấy flag.
