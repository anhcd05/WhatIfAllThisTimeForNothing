# pe-packer

- **Category:** Reverse Engineering (custom PE packer / unpacking tĩnh)
- **File đề:**
  - `challenges/pe-packer/packed.exe` — 209408 byte, md5 `0728bfc481ee20fdad43dbda9d35158f`, PE32+ (x86-64, GUI).
  - `challenges/pe-packer/decrypt_payload.py` — script giải kèm sẵn (chỉ đọc file, không chạy exe).

## Tóm tắt đề

`packed.exe` là một **packer tự chế**: trong file có một **payload đã mã hóa**; khi chạy, stub
sẽ tự giải mã payload trong bộ nhớ rồi **reflective-load** nó như một DLL và gọi export. Flag là
một chuỗi nằm trong DLL payload. Mục tiêu: **dịch ngược tĩnh** để lấy thuật toán + khóa + vị trí
blob, rồi tự giải mã — **tuyệt đối không chạy** `packed.exe`.

## Phân tích (chi tiết: khóa/offset/hằng số thật)

Tất cả số liệu dưới đây được xác nhận THẬT bằng `pefile` + giải mã dữ liệu bằng `pycryptodome`
(chỉ đọc byte của file, **không thực thi** PE).

**1) Header PE (pefile):**

```
Machine      0x8664          -> x86-64 (PE32+)
ImageBase    0x140000000
EntryPoint   RVA 0x1b38
Subsystem    2               -> GUI (có thể bật MessageBox đánh lạc hướng)
Sections (6):
  .text   VA 0x1000   VSize 0xd630   RawPtr 0x400    RawSz 0xd800
  .rdata  VA 0xf000   VSize 0x22fac  RawPtr 0xdc00   RawSz 0x23000
  .data   VA 0x32000  VSize 0x1e78   RawPtr 0x30c00  RawSz 0xc00
  .pdata  VA 0x34000  VSize 0xf18    RawPtr 0x31800  RawSz 0x1000
  _RDATA  VA 0x35000  VSize 0x15c    RawPtr 0x32800  RawSz 0x200
  .reloc  VA 0x36000  VSize 0x660    RawPtr 0x32a00  RawSz 0x800
```

**2) Vị trí payload mã hóa — quy đổi RVA → file offset (THẬT):**

- Blob tại **RVA `0xF370`**, kích thước **`0x19A00`** (= 104960 byte).
- RVA `0xF370` rơi vào section **`.rdata`** (vì `0xf000 ≤ 0xF370 < 0xf000 + 0x22fac`) → payload
  được giấu như **dữ liệu chỉ đọc**.
- Quy đổi (không cần pefile cũng ra):
  ```
  offset = RVA - .rdata.VirtualAddress + .rdata.PointerToRawData
         = 0xF370 - 0xf000 + 0xdc00 = 0xdf70
  ```
  `pefile.get_offset_from_rva(0xF370)` → **`0xdf70`** (khớp).
- 16 byte đầu của blob (đã mã hóa) tại file offset `0xdf70` — xác nhận **không phải `MZ`**:
  ```
  a2 b9 c6 c6 b8 b0 b8 1f 73 86 cb 38 2d 4d f8 6f
  ```

**3) Khóa AES-128 — hardcoded trong `.rdata` (THẬT):**

```
Key (16 byte): 49 6D 6C 39 43 90 AF 04 DD 0A BF D8 DF F1 9F B9
```

- Tìm khóa trong file: `data.find(key)` → file offset **`0x27978`** → RVA
  `0x27978 - 0xdc00 + 0xf000 = 0x29378` → VA `0x140000000 + 0x29378 = 0x140029378`.
- Trong disassembly, stub nạp khóa bằng `lea reg, [rip+disp]` trỏ tới VA `0x140029378` (khóa là
  hằng số nhúng, **không** dựng trên stack).

**4) Import table TIẾT LỘ cơ chế giải mã (THẬT, qua pefile):**

```
bcrypt.dll   -> BCryptOpenAlgorithmProvider, BCryptSetProperty, BCryptGenerateSymmetricKey,
                BCryptDecrypt, BCryptGetProperty, BCryptDestroyKey, BCryptCloseAlgorithmProvider
KERNEL32.dll -> VirtualAlloc, LoadLibraryA, GetProcAddress, GetProcessHeap, HeapAlloc, ...
USER32.dll   -> MessageBoxW
```

→ Packer **không tự nhúng AES** (nên không thấy T-box/`aesenc`) mà gọi **Windows CNG (bcrypt)**.
`VirtualAlloc` + `LoadLibraryA`/`GetProcAddress` = cấp RWX rồi reflective-load DLL sau giải mã.
`MessageBoxW` + Subsystem GUI = hộp thoại đánh lạc hướng; flag nằm trong DLL payload.

**5) Giải mã (AES-128-ECB) → kết quả THẬT:** payload sau giải mã là **PE hợp lệ**:

```
dec[:4]          = b'MZ\x90\x00'
e_lfanew (@0x3C) = 0x100
dec[0x100:0x104] = b'PE\x00\x00'
machine(payload) = 0x8664                  (x86-64)
Characteristics  = 0x2022                  (chứa bit 0x2000 = IMAGE_FILE_DLL) -> payload là DLL
```

ECB **không có IV** — khớp với việc giải mã tĩnh chỉ cần 16 byte khóa, và khớp với trình tự
bcrypt: `BCryptSetProperty(ChainingMode = ECB)`.

**6) Flag trong DLL đã giải mã — vị trí THẬT:** tại offset **`0x17408`** của payload có chuỗi:

```
... <giải>_FLAG{packer_daisuki}\x00 ...     (chuỗi ASCII phẳng; "FLAG{" bắt đầu tại 0x1740c)
```

> REDACT: chuỗi gốc có tiền tố tên giải là `<giải>_FLAG{...}` (ở đây `<giải>_` = tag kỳ thi,
> được REDACT). Nội dung flag chuẩn hóa về khung yêu cầu là `flag{packer_daisuki}`.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Unpack tĩnh thay vì chạy để tự giải** — VÌ chạy packer rủi ro (có thể có anti-debug / hành vi
  độc hại) và không cần: cả blob lẫn khóa đều là hằng số tĩnh trong `.rdata`, tái hiện bước giải
  mã là đủ.
- **Đọc import table trước khi lần mò hàm crypto** — VÌ import `bcrypt!BCryptDecrypt` nói ngay
  thuật toán; nhanh hơn nhiều so với tìm S-box trong `.text`.
- **Quy đổi RVA → file offset qua section table** — VÌ cùng một RVA ứng với file offset khác do
  alignment; đọc nhầm offset = đọc sai vùng.
- **Nhận diện ECB (không IV)** — VÌ blob giải mã độc lập từng khối 16 byte, không có feedback;
  bcrypt chỉ set `ChainingMode = ECB`, không truyền IV.
- **Verify bằng magic `MZ` + `PE\0\0`** — VÌ đây là bằng chứng chắc chắn rằng khóa/chế độ/offset
  đều đúng (xác suất trùng ngẫu nhiên gần như 0).

## Lời giải chi tiết (bước + code/lệnh sạch, chạy lại được)

`decrypt_payload.py` — **chỉ đọc** `packed.exe`, không thực thi:

```python
# pip install pefile pycryptodome
import pefile, re
from Crypto.Cipher import AES

PE_PATH = "packed.exe"
RVA, SIZE = 0xF370, 0x19A00
KEY = bytes([0x49,0x6D,0x6C,0x39,0x43,0x90,0xAF,0x04,
             0xDD,0x0A,0xBF,0xD8,0xDF,0xF1,0x9F,0xB9])

pe = pefile.PE(PE_PATH, fast_load=False)
fo = pe.get_offset_from_rva(RVA)              # 0xF370 -> 0xdf70
with open(PE_PATH, "rb") as f:
    f.seek(fo); enc = f.read(SIZE)

dec = AES.new(KEY, AES.MODE_ECB).decrypt(enc) # AES-128-ECB, không IV
assert dec[:2] == b"MZ"                        # kiểm: là PE
el = int.from_bytes(dec[0x3C:0x40], "little")  # e_lfanew = 0x100
assert dec[el:el+4] == b"PE\x00\x00"           # kiểm: chữ ký PE

open("payload.dll", "wb").write(dec)           # xuất DLL 104960 byte
for m in re.finditer(rb'(flag|FLAG|CTF)\{[^}\r\n]{3,100}\}', dec):
    print("FLAG:", m.group(0).decode("latin-1"))
```

```bash
python3 decrypt_payload.py        # -> payload.dll (104960 byte); in FLAG: ...FLAG{packer_daisuki}
strings payload.dll | grep -i flag
```

Kết quả THẬT (đã kiểm chứng tĩnh): `dec[:4] = b'MZ\x90\x00'`, `e_lfanew = 0x100`, chữ ký
`PE\x00\x00`, flag tại offset `0x17408`.

## Flag

flag{packer_daisuki}

(`daisuki` 大好き = "rất thích" — nghĩa vui "thích packer".)

## Gặp lại thì xử lý thế nào (playbook)

- **Nhận diện:** EXE có section/blob entropy cao; đề nói "packer/packed"; import gồm API crypto
  (`bcrypt`, `advapi32 CryptDecrypt`) và/hoặc `VirtualAlloc`+`LoadLibrary`+`GetProcAddress`.
- **Quy trình:**
  1. Xem **import table** trước (`pefile` / `dumpbin /imports`) → đoán thuật toán (bcrypt→AES,
     tự nhúng→tìm S-box/RC4 KSA).
  2. Trong IDA/Ghidra tìm chỗ nạp **khóa** (`lea reg,[rip+disp]`) + **RVA/size** blob (tham số
     truyền vào `BCryptDecrypt`/`VirtualAlloc`).
  3. Quy đổi RVA→offset qua section table; đọc blob; tái hiện giải mã bằng `pycryptodome`.
  4. Xác thực magic (`MZ`/`PE`, `\x7fELF`, `PK`); dump payload; `strings | grep -i flag`.
- **Cách khác (dynamic):** breakpoint sau lệnh giải mã / trước `VirtualAlloc`+jump rồi dump RAM —
  chỉ dùng khi khóa tính động; kém an toàn hơn.
- **Bẫy hay gặp:** nhầm RVA với file offset; quên ECB vs CBC (thiếu IV ra rác); mất thời gian tìm
  AES tự chế trong khi binary dùng bcrypt; tin vào MessageBox decoy.
- **Checklist ngắn:** import crypto? → khóa ở đâu? → blob RVA/size? → decrypt → magic PE hợp lệ? →
  dump → grep flag.
