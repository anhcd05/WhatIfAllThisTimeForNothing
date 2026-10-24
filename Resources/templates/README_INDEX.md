# README_INDEX — Khảo sát các DẠNG bài Reverse Engineering & bản đồ công cụ/template

> **Mục đích**: Tra nhanh "bài này thuộc dạng gì → dùng tool/template nào". Dành cho mảng
> **Reverse Engineering — Cyber SEA Game 2026** (Jeopardy, on-site Bangkok 26–27/10/2026).
> Môi trường chuẩn bị: **Windows host + Kali VM**, được `pip install`, **không GPU**.
>
> ⚠️ **AN TOÀN (bắt buộc)**: Mặc định **phân tích tĩnh** (`file`, `strings`, `xxd`, đọc mã,
> decompiler). Chỉ **chạy/debug binary lạ trong VM cô lập** (snapshot trước, no shared folder,
> ngắt mạng). Không bao giờ `eval`/thực thi payload obfuscate (PHP/JS/HTA) để "xem nó ra gì" —
> thay `eval` bằng `print`/`echo`. Đặt mỗi file tải về vào **thư mục riêng, rỗng**; chạy Python
> xử lý nó bằng `python -I` để tránh bị chiếm quyền qua `import` (vd `json.py` giả cùng thư mục).
>
> **Nguồn rút dạng bài**: 4 bộ writeup CSG cũ (`Reverse/Old/set-a..d/SOLUTIONS_VN.md`) + khảo sát
> taxonomy RE/CTF chung (angr docs, CTFd, các skill RE cộng đồng). Xem mục "Nguồn tham khảo" cuối file.

---

## 0. Các mảng RE đã thực sự ra ở CSG (rút từ set-a..d)

Thống kê nhanh để biết **phân bố thực tế** (giúp ưu tiên luyện):

| Nhóm kỹ thuật | Bài đã ra (set) | Ghi chú nhanh |
|---|---|---|
| Crackme kiểm tra input / flag dựng runtime | Password Crackme (A), RockPaperScissors (A), UPX+anti-debug (B) | `strings` **không** thấy flag → phải reverse hàm dựng/giải mã |
| Patching nhị phân | Game Win-Counter Patch (A) | sửa 1 hằng số/nhánh `je/jne` rồi chạy |
| Anti-debug | RockPaperScissors (A), UPX (B) | `IsDebuggerPresent`/`CheckRemoteDebuggerPresent` |
| Packer tự chế + crypto nhúng | PE Packer AES-128-ECB qua CNG (C), Password Crackme đóng gói (A) | payload mã hóa trong `.data`, giải mã rồi chạy/dump |
| Crypto nhúng (XOR/RC4/AES/MD5) | Go RC4 C2 (C), HTA MD5 crackme (C), XOR-halves, AES packer (C) | tái lập thuật toán bằng Python thuần |
| .NET managed | .NET AES + Rfc2898DeriveBytes (B/D) | dnSpyEx debug runtime là nhanh nhất |
| Go binary | Go RC4 C2 (C) | symbol `main.*`, string blob dính liền |
| Obfuscation script (PHP/JS/HTA) | Matryoshka PHP (C), SEO/webshell PHP nhiều lớp (A), HTA JS (C) | bóc từng lớp **tĩnh**, không `eval` |
| Corrupted / fake header | Corrupted PE (C), fake-extension (B), reversed-name RLO (B) | sửa magic bytes/đọc magic thật |
| Integer overflow / logic bug | Integer Overflow (D), format string (D), VM/bytecode nhỏ (B/D) | mô phỏng số học bằng Python `ctypes`/`struct` |
| Java | Java Serialized Object (D) | magic `AC ED 00 05`, đọc tag byte |
| VM-based / bytecode custom | VM nhỏ nhắc tới (B/D) + handout VM trong `resources/` | viết emulator/disassembler cho opcode tự chế |
| Archive crypto chặn file | SEH Crackme ZipCrypto (A) | known-plaintext `bkcrack`; AES-ZIP → `pyzipper`/`john` |

---

## Bảng 1 — Dạng bài RE thường gặp (dấu hiệu → công cụ/template)

| Dạng | Dấu hiệu nhận biết | Công cụ / Template nên dùng | Ghi chú |
|---|---|---|---|
| **Crackme kiểm tra input** (so sánh password/serial) | Binary hỏi input, in "Correct/Wrong"; có `strcmp`/`memcmp`/vòng so sánh từng ký tự | Ghidra/IDA đọc hàm check; nếu ràng buộc tuyến tính → **`GUIDE_z3.md`**; nếu nhánh phức tạp → **`GUIDE_angr.md`** | Tìm hàm compare, truy ngược buffer "đáp án" được dựng ở đâu |
| **Keygen** (sinh serial hợp lệ) | Có hàm validate(serial) nhưng **không** hardcode serial đúng | Reverse thuật toán validate → viết hàm sinh ngược (Python); hoặc `z3` giải ràng buộc | Mục tiêu: hiểu thuật toán rồi tự sinh, không brute |
| **Hệ ràng buộc / nhiều phương trình** (mỗi byte input thỏa 1 biểu thức) | Nhiều phép `+ - ^ * %` trên mảng input, so với hằng số | **`GUIDE_z3.md`** (mô hình hóa ràng buộc) | z3 trả nghiệm tức thì; nhanh hơn angr khi logic số học rõ ràng |
| **Đường đi phức tạp / nested branch** | Nhiều `if` lồng, khó dựng phương trình tay | **`GUIDE_angr.md`** (symbolic execution: `find`=địa chỉ "Correct", `avoid`=địa chỉ "Wrong") | Nếu z3 nghẹn do ràng buộc quá nặng → đổi cách format cho z3 (xem angr docs) |
| **Flag dựng ở runtime** (không có chuỗi tĩnh) | `strings`/`grep flag` **ra rỗng**; flag ghép bằng XOR/sprintf/`rand()` trong RAM | Reverse hàm dựng → tái lập bằng Python; **hoặc** debug đặt breakpoint sau khi dựng rồi dump; emulate hàm → **`GUIDE_emulation.md`** | Kinh điển CSG: Password Crackme (A), UPX-XOR (B), Integer Overflow (D) |
| **Packer / tự giải nén** | Entropy cao, ít import, section lạ (`UPX0`), payload trong `.data` giải mã lúc chạy | `upx -d` (nếu UPX chuẩn); packer tự chế → dump payload tĩnh rồi giải (AES/XOR) bằng **`GUIDE_fileparse_decrypt.md`** | PE Packer (C): AES-128-ECB qua **Windows CNG** nên `objdump` không thấy `aesenc` |
| **Anti-debug / anti-VM** | Import `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, kiểm tra PEB `BeingDebugged`, timing `rdtsc` | Patch nhánh kiểm tra (`74↔75`, `je↔jne`); x64dbg/x32dbg bypass; hoặc giải tĩnh né hẳn việc chạy | RockPaperScissors (A), UPX (B): thường chỉ cần **patch tĩnh rồi chạy** |
| **VM-based / bytecode custom** | Vòng lặp `fetch-decode-execute`, mảng "opcode", bảng dispatch (switch lớn/jump table) | Lập bảng opcode → viết **disassembler + emulator** Python; **`GUIDE_emulation.md`** (Unicorn cho hàm thật) | Có handout VM trong `resources/` — xem `HANDOUT_VM_IDA_Pseudocode.md` |
| **Obfuscation (binary)** | Control-flow flattening, opaque predicate, string encryption, junk code | Ghidra + đọc kiên nhẫn; deobfuscate script; emulate đoạn giải chuỗi | Ưu tiên tách "hàm giải chuỗi" rồi emulate nó |
| **Obfuscation (script PHP/JS/HTA)** | `eval(gzinflate(base64_decode(...)))` lồng nhiều lớp; biến rối | Bóc **tĩnh**: thay `eval`→`echo`/`print`, hoặc `php -a` in layer kế; CyberChef cho JS | Matryoshka PHP (C), SEO webshell (A): **không bao giờ chạy** payload |
| **Crypto nhúng — XOR** | Vòng `buf[i] ^= key[i % n]`; key hằng/ dẫn xuất | Script XOR Python; CyberChef "XOR"/"XOR Brute Force"; **`GUIDE_fileparse_decrypt.md`** | XOR đối xứng; key có thể từ timestamp/arg (XOR Backup A) |
| **Crypto nhúng — RC4** | Thấy KSA (`S[256]`, hoán vị theo key) + PRGA + XOR | RC4 Python thuần (mã hóa = giải mã); **`GUIDE_fileparse_decrypt.md`** | Go RC4 C2 (C): key `main.expectedKey`, CT `main.flag` |
| **Crypto nhúng — AES** | Gọi CNG/CryptoAPI, OpenSSL, `AesManaged`; thấy IV/key/sbox | `pycryptodome` giải; biết mode (ECB/CBC) + key + iv; **`GUIDE_fileparse_decrypt.md`** | PE Packer (C) ECB; .NET (B) có **KDF Rfc2898** → debug runtime dễ hơn |
| **Crypto nhúng — hash (MD5/SHA)** | Crackme so hash; có brute C sẵn trong `resources/` | So sánh/brute offline bằng `brute_md5.c`…`brute_sha512.c` (xem `README_brute.md`); CyberChef | HTA MD5 (C). **Không GPU** → brute phải thông minh (giới hạn charset/độ dài) |
| **Patching** | Cần "thắng" 1 điều kiện (win-counter, flag branch) mà không cần input đúng | Sửa byte bằng Ghidra/x64dbg/`hexedit`; đổi hằng số hoặc đảo nhánh | Game Win-Counter Patch (A): nhớ **little-endian** |
| **Corrupted / fake header** | `file` báo sai/hỏng; magic byte lệch; đuôi file đánh lừa; Unicode RLO | `xxd`/hex editor sửa magic (MZ/PE, PK, PNG `89 50`); đọc magic **thật** không tin đuôi | Corrupted PE (C), fake-extension & reversed-name RLO (B) |
| **Emulation 1 hàm** (tách 1 hàm dựng/giải để chạy riêng) | Hàm giải mã/dựng flag nằm gọn, tự chứa, phụ thuộc ít state | **Unicorn Engine** map code+stack, set reg, chạy, đọc kết quả; **`GUIDE_emulation.md`** | Nhanh hơn reverse tay khi hàm dài/obfuscate |
| **Archive crypto chặn file** | File đề là ZIP có mật khẩu; binary nằm bên trong | ZipCrypto cổ điển → `bkcrack` (known-plaintext); AES-ZIP → `pyzipper`/`john`/`hashcat` | SEH Crackme (A): ZipCrypto cần plaintext **đã deflate**, không chỉ `MZ` |
| **Serialized / định dạng dữ liệu** | Magic `AC ED 00 05` (Java), pickle, protobuf | Đọc tag byte tay; `SerializationDumper`; **cẩn trọng insecure deserialization**, không deserialize mù | Java Serialized (D) |
| **Pwn-lai-RE** (format string, int overflow, logic) | `printf(user)`, phép toán tràn, so sánh với số âm | Đọc nguồn/pseudo-C; mô phỏng số học `ctypes`/`struct`; `pwntools` nếu cần tương tác → **`GUIDE_pwntools.md`** | Integer Overflow (D): nhập số lớn để wrap sang âm |

---

## Bảng 2 — Theo ngôn ngữ / định dạng (nhận diện → bộ công cụ)

| Ngôn ngữ / định dạng | Cách nhận diện | Công cụ chính (có trên Kali / `pip`) | Ghi chú thực chiến |
|---|---|---|---|
| **C/C++ native (ELF/PE)** | `file` → `ELF`/`PE32`; không có runtime marker đặc biệt | **Ghidra** (free, có decompiler), `objdump`, `radare2`/`rizin`, `gdb`+`pwndbg`, x64dbg (Win) | Mặc định của đa số bài. C++ hay có RTTI/tên mangled → `c++filt` |
| **.NET / Mono** | `file` → "Mono/.Net assembly"; Data Directory #14 (CLR header); nhiều `System.*` | **dnSpyEx** (Win, decompile+debug+sửa IL), **ILSpy**, dotPeek, `monodis`/`ikdasm` | Tốt nhất: **debug runtime trong dnSpyEx**, set breakpoint sau khi giải mã. Có KDF → đừng giải tay |
| **Go (golang)** | Chuỗi `Go build ID`, symbol `main.*`, `runtime.*`; binary to | **Ghidra** + script phục hồi hàm (GoReSym / golang_loader_assist); **gostringungarbler** (nếu bị garble); `strings` | String blob Go **dính liền nhau**, ranh giới do `len` quyết; tìm xref tới hàm crypto để khoanh key/CT |
| **Rust** | Symbol `core::`, `alloc::`, panic message `src/main.rs`; binary rất to | **Ghidra**/IDA; `rustfilt` để demangle; đọc panic/format strings làm mốc | Khó đọc; bám panic string & chuỗi format để định vị logic |
| **Python frozen (PyInstaller/py2exe)** | `file` thấy "PyInstaller"; có `python3x.dll`; section `PYZ` | **pyinstxtractor** (hoặc `pyinstxtractor-ng`) để bung → `.pyc`; **decompile `.pyc`**: `decompyle3`/`uncompyle6` (≤3.8), **pycdc/pycdas** (3.9+) | Khớp **đúng version Python** khi decompile; pycdc build sẵn cho 3.9+ |
| **Java (.class/.jar)** | `file` → "compiled Java class"/ZIP chứa `.class`; magic `CA FE BA BE` | **jadx** (+`jadx-gui`), **CFR**, **jd-gui**, Procyon; `javap -c` xem bytecode | MCP `jadx` có cấu hình (xem lưu ý kết nối cuối file) |
| **Java serialized data** | magic `AC ED 00 05` | `SerializationDumper`; đọc tag tay; `file`/`xxd` | Không deserialize dữ liệu không tin cậy (gadget RCE) |
| **Android APK** | file `.apk` (ZIP chứa `classes.dex`, `AndroidManifest.xml`) | **jadx**/`jadx-gui` (dex→Java); `apktool` (smali+res); `dex2jar`+jd-gui | Tìm `MainActivity`, check logic trong `onCreate`; native lib trong `lib/` → reverse `.so` bằng Ghidra |
| **JavaScript / Node** | `.js`, bundle webpack, `eval`/packed | CyberChef, `js-beautify`, de4js, Node `--inspect` (sandbox) | Bóc tĩnh; beautify trước |
| **HTA / VBScript / WSH** | `.hta` (HTML+script), `<script language=vbscript>` | Mở bằng editor; tách JS/VBScript; tính MD5/logic bằng Python/CyberChef | HTA MD5 crackme (C): logic check nằm trong `<script>` |
| **PHP (webshell/obfusc)** | `<?php`, `eval(gzinflate(base64_decode(...)))` | Bóc tĩnh: `eval`→`echo`; `php -a` in layer; `vld` opcode | Matryoshka (C), SEO malware (A) |
| **WASM** | `.wasm`, magic `00 61 73 6D` | `wasm2wat` (wabt), `wasm-decompile`, Ghidra (plugin), CyberChef | Đọc `.wat`; logic check thường ở hàm export |
| **Shell/batch/PowerShell** | `.sh/.bat/.ps1`, base64 `-enc` | Decode base64; `PowerShell -EncodedCommand` → giải tĩnh | Không chạy; de-obfuscate bằng tay |

---

## Quy trình chuẩn khi nhận 1 binary (checklist)

```
0) CÁCH LY: tạo thư mục rỗng riêng, chép file đề vào. Snapshot VM. Không chạy vội.

1) NHẬN DIỆN
   file target                         # loại file, 32/64-bit, ELF/PE/.NET/Go...
   sha256sum target ; ls -l target     # ghi hash + size để đối chiếu
   (Windows) Get-FileHash target
   # Entropy cao + ít import  => nghi packer/crypto nhúng.

2) THU TÍN HIỆU TĨNH (rẻ, làm trước)
   strings -a -n 6 target | less       # flag{, URL, key, tên hàm, lib crypto
   strings -el target                  # chuỗi UTF-16 (Windows hay dùng)
   xxd target | head                    # magic bytes thật (đừng tin đuôi file)
   rabin2 -I target / objdump -f        # kiến trúc, entrypoint, imports
   # Có 'IsDebuggerPresent' => anti-debug. Có 'main.' => Go. 'Mono/.Net' => .NET.

3) CHỌN CÔNG CỤ theo Bảng 2 (ngôn ngữ) + đoán DẠNG theo Bảng 1 (dấu hiệu).

4) STATIC trước, DYNAMIC sau
   - Static: decompile (Ghidra/dnSpyEx/jadx) tìm hàm check / hàm dựng flag.
   - Nếu flag dựng runtime & không strings được => debug (breakpoint sau khi dựng)
     HOẶC emulate riêng hàm đó (GUIDE_emulation.md).
   - Dynamic chỉ trong VM cô lập, đã snapshot.

5) TRÍCH / GIẢI
   - Ràng buộc input  => z3 (GUIDE_z3.md) hoặc angr (GUIDE_angr.md).
   - Crypto nhúng     => tái lập Python (GUIDE_fileparse_decrypt.md).
   - Chỉ cần vượt 1 check => patch (đổi nhánh/hằng số).
   - Hàm tự chứa khó  => Unicorn emulate (GUIDE_emulation.md).

6) KIỂM CHỨNG: chạy lại logic trên dữ liệu đề để xác nhận flag; đối chiếu format flag{...}.
```

**Nguyên tắc chọn nhánh nhanh**:
- Thấy `strings` ra ngay flag → xong, đừng phức tạp hóa.
- Thấy so sánh tuyến tính từng byte → **z3**.
- Thấy logic phân nhánh rối, không muốn mô hình hóa → **angr**.
- Thấy thuật toán crypto rõ (RC4/XOR/AES) → **viết lại Python**, đừng chạy binary.
- Thấy chỉ cần "qua 1 cổng" → **patch**.
- Thấy hàm giải mã dài/obfuscate nhưng tự chứa → **emulate (Unicorn)**.

---

## Mục lục — các template khác trong thư mục này

| File | Dùng cho |
|---|---|
| **`GUIDE_pwntools.md`** | Tương tác process/remote, gửi payload, pwn-lai-RE, I/O tự động hóa. |
| **`GUIDE_z3.md`** | Giải hệ ràng buộc / crackme tuyến tính bằng SMT solver z3. |
| **`GUIDE_angr.md`** | Symbolic execution: tìm input tới địa chỉ "Correct", tránh "Wrong". |
| **`GUIDE_fileparse_decrypt.md`** | Parse file/section, tái lập XOR/RC4/AES/hash để giải crypto nhúng. |
| **`GUIDE_emulation.md`** | Emulate 1 hàm hoặc VM/bytecode custom bằng Unicorn Engine. |

*(Thư mục `resources/` còn có `brute_md*.c`, `brute_sha*.c` + `README_brute.md` để brute hash
offline không-GPU, và `HANDOUT_VM_IDA_Pseudocode.md` cho dạng VM-based bytecode.)*

---

## Nguồn tham khảo
- Cyber SEA Game 2026 — AJCCBC (categories: Forensics, **Reverse Engineering**, Crypto, Stego, Network, Web): https://ajccbc.ncsa.or.th/cyber-sea-game-2026/
- Writeup CSG cũ (nội bộ): `Reverse/Old/set-a/`, `set-b/`, `set-c/`, `set-d/` — `SOLUTIONS_VN.md`.
- angr — CTF examples & giới hạn z3: https://docs.angr.io/en/latest/appendix/more-examples.html
- CTFd — mô tả category Reverse Engineering: https://docs.ctfd.io/events/challenge-categories
- Crack-me & reverse engineering (tổng quan): https://shazaali.substack.com/p/crack-me-challenges-and-reverse-engineering
