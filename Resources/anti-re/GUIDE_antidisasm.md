# GUIDE: Nhận diện & ĐÁNH BẠI Anti-Disassembly (CTF / RE)

> Mục đích: PHÂN TÍCH & GIẢI đề RE trong Cyber SEA Game 2026. Đây là tài liệu
> chuẩn bị trước giải (hợp lệ). KHÔNG tải/chạy binary lạ khi soạn tài liệu.
>
> Công cụ giả định: **Ghidra**, **IDA Free**, **radare2 / rizin**, **x64dbg**.
> Kèm script `realign_helper.py` (cùng thư mục) để patch byte rác khi phân tích offline.

---

## 0. Tư duy chung: vì sao disassembler bị lừa?

Có 2 kiểu giải mã lệnh:

| Kiểu | Cơ chế | Điểm yếu bị khai thác |
|------|--------|-----------------------|
| **Linear sweep** (objdump, Ghidra phần lớn, Hopper) | Giải mã tuần tự từ đầu tới cuối, lệnh này nối tiếp lệnh kia | Chèn **byte rác** vào luồng không bao giờ chạy → lệ thuộc byte rác, lệch toàn bộ phần sau |
| **Recursive descent** (IDA, radare2 `af`, Ghidra flow) | Đi theo luồng điều khiển (jmp/jcc/call), chỉ giải mã nơi thực sự tới | Bị lừa bởi **jump giả / điều kiện giả (opaque predicate)** → đi vào nhánh chết, bỏ qua code thật |

Anti-disassembly = cố ý tạo **sự khác biệt giữa byte được giải mã và byte thực thi**.
Nguyên tắc GIẢI: tìm **luồng thực thi THẬT** (CPU chạy gì), rồi ép disassembler
hiển thị đúng luồng đó bằng cách **undefine → re-code**, hoặc **patch byte rác thành NOP**,
hoặc **ép jump điều kiện thành jump vô điều kiện**.

**Quy ước chữ viết tắt trong tài liệu:**
- `X` = địa chỉ byte đầu của khối ví dụ.
- Byte hiển thị dạng hex: `74 03` nghĩa là opcode `74`, operand `03`.
- `jcc` = jump có điều kiện (74=jz, 75=jnz, 7C=jl, ...). `rel8` = offset 1 byte có dấu.

Công thức tính đích nhảy ngắn (short jump/jcc, 2 byte):
```
dich = (dia_chi_lenh + 2) + rel8     # rel8 là số CÓ DẤU (-128..127)
```

---

## 1. Rogue byte sau jcc — hai jump cùng đích để chèn byte rác

Đây là kỹ thuật kinh điển của **Practical Malware Analysis (PMA) Lab 15-01**.

### Cơ chế đánh lừa
Đặt hai lệnh nhảy bù nhau (`jz` + `jnz`) tới **CÙNG một đích**. Vì cờ Zero (ZF)
luôn hoặc 0 hoặc 1, nên **luôn có đúng một trong hai nhảy** → thực chất là nhảy
vô điều kiện. Ngay sau cặp jump là **1 byte rác** (thường `E8` hoặc `E9`) mà CPU
KHÔNG BAO GIỜ chạy. Nhưng linear sweep giải mã byte `E8` đó như opcode
`CALL rel32` (5 byte) → "nuốt" luôn các lệnh thật phía sau, làm lệch disassembly.

### Byte cụ thể
```
X+0:  74 03        jz   short X+5      ; (X+2)+3 = X+5
X+2:  75 01        jnz  short X+5      ; (X+4)+1 = X+5
X+4:  E8           <-- BYTE RÁC (không bao giờ chạy)
X+5:  B8 01 00 00 00   mov eax, 1      ; CODE THẬT
```
- **CPU thấy:** từ X luôn nhảy tới X+5 → chạy `mov eax,1`.
- **Linear sweep thấy:** `jz`, `jnz`, rồi tại X+4 đọc `E8 B8 01 00 00` = `call rel32`
  → nuốt mất `mov eax,1`, phần sau lệch hết.

### Dấu hiệu nhận biết
- Hai lệnh `jz`/`jnz` liền nhau trỏ cùng địa chỉ.
- Có 1 `call`/`jmp` "mồ côi" ngay sau đó mà đích nhảy lại rơi vào **giữa** lệnh `call` này.
- IDA vẽ mũi tên cross-ref chỉ vào giữa một lệnh (dấu hiệu đỏ rõ nhất).

### Cách FIX / PATCH
Byte rác là `E8` tại X+4. Chỉ cần biến nó thành `NOP` (`90`):

```
Trước:  74 03 75 01 E8 B8 01 00 00 00
Sau:    74 03 75 01 90 B8 01 00 00 00    (E8 -> 90)
```
Sau khi patch, byte `90` là lệnh 1-byte, phần `B8 01 00 00 00` thẳng hàng lại thành `mov eax,1`.

- **IDA:** đặt con trỏ tại byte `E8` → nhấn **`U`** (undefine) để xoá định nghĩa sai,
  rồi tới địa chỉ X+5 nhấn **`C`** (make code). Nếu muốn patch hẳn:
  `Edit > Patch Program > Change byte...` sửa `E8` → `90`, rồi `C`.
- **Ghidra:** chọn vùng lệnh sai → chuột phải **Clear Code Bytes** → tới X+5 chuột phải
  **Disassemble** (`D`). Hoặc **Patch Instruction** (Ctrl+Shift+G) tại X+4 gõ `NOP`.
- **radare2:** `s X+4 ; wx 90` (ghi 1 byte 90) hoặc `wao nop`; rồi `s X+5 ; af` / `pd`.
  Hoặc viết vào file: mở với `r2 -w file`.
- **realign_helper.py:** `python realign_helper.py <file> <offset_X+4> --len 1` (ghi NOP).

> Biến thể: `75 ?? E8 ...` (chỉ 1 jcc + rogue byte), hoặc dùng `E9` (jmp rel32, nuốt 5 byte),
> `0F 84/85` (jcc near, 6 byte). Nguyên tắc như nhau: NOP byte rác đầu tiên.

---

## 2. Jump vào GIỮA lệnh — `EB FF C0` (impossible / overlapping disassembly)

### Cơ chế đánh lừa
Một `jmp` nhảy LÙI/ngang vào giữa chính byte operand của nó. Byte `FF` vừa là
operand của `jmp`, vừa là opcode đầu của lệnh thật `INC`. Cùng một byte được "dùng
hai lần" → disassembler chỉ hiểu được một cách, luôn sai cách còn lại.

### Byte cụ thể
```
X+0:  EB FF        jmp short X+1      ; (X+2) + (-1) = X+1  --> nhảy vào byte FF!
X+1:  FF C0        inc eax            ; CODE THẬT (trùng byte FF với operand ở trên)
```
- **CPU thấy:** tại X, `EB FF` = `jmp $-1` → nhảy tới X+1, thực thi `FF C0` = `inc eax`.
- **Linear sweep thấy:** `EB FF` (jmp), rồi tại X+2 đọc `C0 ...` = một lệnh shift rác,
  hoàn toàn không thấy `inc eax`.

### Dấu hiệu nhận biết
- Lệnh `jmp short`/`jcc` có đích rơi vào **chính byte operand của nó** hoặc 1-2 byte trước/sau.
- Đích nhảy không trùng ranh giới lệnh (IDA báo `sp-analysis failed` hoặc mũi tên vào giữa lệnh).
- Hay gặp `EB FF`, `E8 ... FF`, hoặc `jmp $+1`.

### Cách FIX / PATCH
Mục tiêu: cho disassembler bắt đầu đọc tại X+1 (luồng thật). Vì `EB FF` chỉ là lớp vỏ
làm lệch căn chỉnh, patch 2 byte `EB FF` thành `90 90` (2 NOP) để byte sau tự thẳng hàng:
```
Trước:  EB FF C0      (jmp $-1 ; <che giau> inc eax)
Sau:    90 90 C0  ... -> nhung C0 van thieu modrm; TOT HON:
Sau:    90 FF C0      (NOP ; inc eax)   <-- chi NOP byte EB (X+0), giu FF C0
```
Cách an toàn nhất: **chỉ NOP byte `EB` (X+0)**, giữ nguyên `FF C0`. Khi đó X+0=`90` (nop),
X+1=`FF C0`=`inc eax` — thẳng hàng hoàn hảo. (Nếu NOP cả 2 byte thì mất byte `FF`.)

- **IDA:** tại X nhấn **`U`** (undefine toàn vùng lệch), rồi tại **X+1** nhấn **`C`** (make code).
  Thường chỉ cần làm vậy, không cần patch byte. Nếu cần patch: `Edit > Patch Program` sửa X+0 `EB`→`90`.
- **Ghidra:** chọn vùng → **Clear Code Bytes** → đặt con trỏ tại X+1 → **Disassemble (D)**.
  Ghidra có khái niệm "disassemble from here" rất hợp để căn lại.
- **radare2:** `s X+1 ; af` để phân tích từ offset đúng; hoặc `s X ; wx 90` NOP byte EB rồi `pd`.
- **realign_helper.py:** `python realign_helper.py <file> <offset_X> --len 1` (NOP byte EB).

---

## 3. Opaque predicate — điều kiện giả LUÔN đúng/sai

### Cơ chế đánh lừa
Tạo một biểu thức mà kết quả đã biết trước khi chạy (CPU biết, người đọc tưởng là
điều kiện thật). Nhánh "không bao giờ chạy" được nhồi byte rác để làm lệch disassembler;
nhánh "luôn chạy" chứa code thật.

### 3a. `xor eax,eax; jz` — nhảy luôn xảy ra
```
X+0:  31 C0        xor eax, eax       ; eax=0  => ZF=1 LUON LUON
X+2:  74 01        jz  short X+5       ; vi ZF=1, LUON nhay
X+4:  E8           <-- byte rac (fall-through khong bao gio chay)
X+5:  ...          ; CODE THAT
```
`jz` sau `xor eax,eax` **luôn nhảy**. Tương tự: `sub eax,eax; jz`, `and eax,0; jz`,
`cmp eax,eax; jz` (so bằng chính nó → luôn bằng), `test eax,eax` sau khi biết eax=0.

### 3b. `jz target` + `jnz target` — nhảy vô điều kiện (như Mục 1)
```
X+0:  74 05  jz  short X+7
X+2:  75 03  jnz short X+7     ; mot trong hai LUON dung => luon nhay toi X+7
```

### Dấu hiệu nhận biết
- Lệnh set cờ "cứng" (`xor reg,reg`, `cmp reg,reg`, `sub reg,reg`) ngay trước jcc.
- `jz`+`jnz` (hoặc `jc`+`jnc`, `jo`+`jno`) liền nhau cùng đích.
- Nhánh fall-through trông như code nhưng IDA không có xref nào trỏ vào, hoặc giải mã ra rác.

### Cách FIX / PATCH
Ý tưởng: ÉP jcc thành jmp vô điều kiện để disassembler bỏ nhánh chết, rồi NOP byte rác.

Patch opcode: `74` (jz) hoặc `75` (jnz) → `EB` (jmp short). Giữ nguyên operand (cùng rel8).
```
Truoc:  31 C0 74 01 E8 ...
Buoc 1: doi 74 -> EB  =>  31 C0 EB 01 E8 ...   (jz thanh jmp: nhanh chay ro rang)
Buoc 2: NOP byte rac E8 (neu con lech) -> 90
```
- **IDA:** `U` tại byte rác → `C` tại code thật. Muốn ép nhảy rõ ràng:
  `Edit > Patch Program > Change byte` sửa `74`→`EB`. (IDA Free có Patch Program.)
- **Ghidra:** **Patch Instruction** tại jcc, đổi `JZ` → `JMP` (Ghidra tự tính lại byte);
  hoặc Clear + Disassemble tại đích.
- **radare2:** `s <addr_jcc> ; wao nop` để NOP luôn jcc nếu nhánh fall-through là code thật;
  hoặc `wx eb` để đổi opcode `74`→`EB`; hoặc `wao jmp` tuỳ bản.
- **x64dbg (động):** đặt breakpoint, xem cờ ZF thực tế; chuột phải lệnh → **Assemble** sửa
  thành `jmp`/`nop`; hoặc **Binary > Fill with NOPs** vùng rác. Patch rồi **Patch file** để lưu.
- **realign_helper.py:** `python realign_helper.py <file> <offset_jcc> --set 0xEB` (đổi 74→EB).

---

## 4. `push addr; ret` — dùng RET thay cho JMP

### Cơ chế đánh lừa
Thay vì `jmp target`, đẩy địa chỉ đích lên stack rồi `ret`. Disassembler thấy `ret`
sẽ coi đây là **kết thúc hàm** và KHÔNG đi theo luồng (recursive descent dừng lại) →
bỏ qua toàn bộ code tại `target`.

### Byte cụ thể
```
X+0:  68 44 33 22 11   push 0x11223344     ; day dia chi dich len stack
X+5:  C3               ret                  ; "jmp 0x11223344" tra hinh
```
Biến thể tinh vi: `call $+5 ; add [esp], off ; ret` để tính đích động.

### Dấu hiệu nhận biết
- `push imm32` ngay trước `ret`, và imm32 là một địa chỉ hợp lệ trong .text.
- Hàm "kết thúc" đột ngột bằng `ret` dù logic chưa xong; vùng sau `ret` không được giải mã.

### Cách FIX / PATCH
- **Nhận diện đích:** đọc imm32 trong `push` = địa chỉ nhảy thật. Tới đó ép make-code.
- **IDA:** tại `target` nhấn **`C`**; thêm cross-ref thủ công để IDA nối luồng
  (`Edit > ... > Cross references`, hoặc script `add_cref`). Có thể patch `68 addr C3`
  thành `jmp`: `jmp rel32` = `E9 <rel32>` (5 byte) + 1 byte `90` dư (vì push+ret = 6 byte).
  Tính `rel32 = target - (X+5)`.
- **Ghidra:** chuột phải `target` → **Disassemble**. Dùng **Patch Instruction** hoặc
  script Python/Jython thêm reference; hoặc chấp nhận và đặt label thủ công.
- **radare2:** `s target ; af` để ép phân tích hàm tại đích; `axc` xem/thêm xref.
- **realign_helper.py:** dùng để NOP/patch byte nếu bạn quyết định viết đè `E9 rel32`
  (tính rel32 thủ công rồi dùng `--set` cho từng byte, hoặc chỉnh script — xem `# TODO`).

---

## 5. `call $+5; pop reg` — lấy EIP/con trỏ lệnh (thunk)

### Cơ chế
```
X+0:  E8 00 00 00 00   call X+5    ; push dia chi X+5 len stack, roi "goi" X+5
X+5:  58               pop eax     ; eax = X+5 (lay duoc dia chi hien tai)
```
`call rel32 = 0` nghĩa là gọi ngay lệnh kế tiếp → chỉ để đẩy EIP lên stack rồi `pop`
lấy ra. Thường dùng cho **position-independent code / shellcode / giải mã chuỗi**.
Bản thân không làm lệch disassembly nhiều, NHƯNG hay đi kèm biến thể `call` nhảy vào
giữa lệnh (gộp với Mục 1/2) để vừa lấy EIP vừa giấu code.

### Dấu hiệu & xử lý
- `E8 00 00 00 00` (call tới chính lệnh sau) theo sau là `pop`.
- Không cần patch để "sửa" — chỉ cần hiểu `reg` = địa chỉ runtime của X+5, dùng để
  tính offset các chuỗi/khóa giải mã. Nếu biến thể giấu code, áp dụng FIX của Mục 1/2.
- **x64dbg:** chạy tới `pop`, đọc giá trị `reg` thật để biết base dùng cho giải mã.

---

## 6. Stack-string — dựng chuỗi trên stack (chống `strings`)

### Cơ chế đánh lừa
Chuỗi không nằm trong .data/.rdata nên `strings` và tìm-chuỗi tĩnh KHÔNG thấy. Thay
vào đó từng ký tự được ghi lần lượt lên stack bằng `mov byte ptr`.

### Byte cụ thể
```
C6 45 F0 66      mov byte ptr [ebp-10h], 'f'   ; 0x66
C6 45 F1 6C      mov byte ptr [ebp-0Fh], 'l'   ; 0x6C
C6 45 F2 61      mov byte ptr [ebp-0Eh], 'a'   ; 0x61
C6 45 F3 67      mov byte ptr [ebp-0Dh], 'g'   ; 0x67
...                                             -> "flag"
```
Biến thể: ghi theo DWORD `mov dword ptr [ebp-X], 'galf'` (little-endian, đảo byte),
hoặc dùng `push` liên tiếp.

### Dấu hiệu nhận biết
- Chuỗi dài các `mov byte/dword ptr [ebp-X], imm` với imm là mã ASCII in được (0x20–0x7E).
- Offset `[ebp-X]` tăng/giảm đều → đang ghép mảng ký tự.

### Cách khôi phục
- Đọc lần lượt các imm, sắp theo offset → ghép lại thành chuỗi (nhớ little-endian với DWORD).
- **IDA:** bật cột opcode/hex, hoặc dùng script lấy operand. IDAPython gợi ý trong `# TODO`.
- **Ghidra:** chọn vùng → xem listing; có thể dùng script hoặc đọc tay.
- **radare2:** `pd 40 @ fcn` rồi đọc imm; hoặc `/c mov byte` tìm mẫu.
- **x64dbg (động, dễ nhất):** đặt breakpoint sau đoạn dựng chuỗi, xem vùng `[ebp-X]`
  trong dump → chuỗi hiện nguyên văn. Đây thường là cách nhanh nhất trong CTF.

---

## 7. Fake / rogue `E8` `E9` — opcode giả nuốt lệnh

### Cơ chế
`E8` (call rel32) và `E9` (jmp rel32) là lệnh 5 byte. Chèn một byte `E8`/`E9` lạc
vào luồng chết khiến linear sweep "nuốt" 4 byte sau nó (là code thật) → lệch. Đây là
"vật liệu" chung của Mục 1 và 3 (byte rác hay chọn `E8` chính vì nó dài 5 byte).

### Dấu hiệu & FIX
- Một `call`/`jmp rel32` mà đích vô nghĩa (trỏ ra ngoài .text, hoặc vào giữa lệnh khác),
  và có một jcc/jump trỏ vào **giữa** nó.
- FIX: NOP byte `E8`/`E9` đầu (như Mục 1) → 4 byte sau tự thẳng hàng. `U` rồi `C` trong IDA.

---

## 8. Bảng tra nhanh lệnh công cụ

| Việc cần làm | IDA (Free) | Ghidra | radare2 | x64dbg (động) |
|---|---|---|---|---|
| Xoá định nghĩa sai | `U` (undefine) | chuột phải → **Clear Code Bytes** | `s addr; af-` | — |
| Ép thành code | `C` (make code) | chuột phải → **Disassemble** (`D`) | `s addr; af` / `pd` | — |
| Ép thành data | `D` (make data) | **Clear** → right-click → set data type | `Cd`, `Cx` | — |
| Phân tích lại hàm | `P` (make function) | **Create Function** (`F`) | `af` | Analyse module |
| Patch 1 byte | `Edit > Patch Program > Change byte` | **Patch Instruction** (Ctrl+Shift+G) | `wx <hex>` | right-click → **Assemble** |
| Ghi NOP | Patch byte → `90`, hoặc `Edit>Patch>Assemble: nop` | **Patch Instruction** gõ `NOP` | `wao nop` | **Binary > Fill with NOPs** |
| Lưu patch ra file | `Edit > Patch Program > Apply patches to input file` | **File > Export Program** / save | `r2 -w` (ghi trực tiếp) | **Patch file...** |

> Lưu ý IDA: patch trong view là trong database; muốn ghi ra .exe phải
> `Edit > Patch Program > Apply patches to input file...`.
>
> Lưu ý Ghidra: "Patch Instruction" sửa trong CodeBrowser; xuất file qua
> `File > Export Program > Format: Original File` (giữ patch nếu dùng đúng loader).

---

## 9. Quy trình giải một đề RE có anti-disassembly (checklist)

1. **Quét tổng thể** (triage): `file`, PE/ELF? packer? `rabin2 -I`, `strings` (ít chuỗi → nghi stack-string).
2. **Mở bằng recursive-descent** (IDA/r2 `aaa`): chỗ nào báo lỗi, mũi tên vào giữa lệnh,
   hàm cụt đột ngột → đánh dấu nghi vấn.
3. **Đối chiếu byte thô** (hex view) với disassembly: tìm `jz/jnz` cùng đích, `EB FF`,
   `push imm; ret`, `xor reg,reg; jz`, chuỗi `C6 45 ..`.
4. **Xác định luồng THẬT**: tính đích nhảy bằng tay (công thức Mục 0). Luồng thật là
   luồng CPU chạy, không phải byte đầu tiên disassembler đọc.
5. **Ép hiển thị đúng**: `U`→`C` (IDA) / Clear→Disassemble (Ghidra) / `s;af` (r2).
   Nếu vẫn lệch, **patch byte rác → NOP** hoặc **jcc → jmp** (dùng `realign_helper.py` offline,
   hoặc patch ngay trong tool).
6. **Xác thực bằng động** (x64dbg): chạy tới vùng nghi, xem cờ/stack/dump thực tế để
   chắc chắn luồng và lấy chuỗi/flag.
7. **Lặp lại** cho tới khi toàn hàm hiển thị mạch lạc.

---

## 10. Mapping tới Practical Malware Analysis — Lab 15-01 / 02 / 03

Kho mẫu luyện tập (hợp lệ, để học offline, CHẠY TRONG VM cách ly):
**https://github.com/rikonaka/PracticalMalwareAnalysis-Labs-Sample**
→ giải nén `PracticalMalwareAnalysis-Labs.tar.gz` →
`Practical Malware Analysis Labs/BinaryCollection/Chapter_15L/` →
`Lab15-01.exe`, `Lab15-02.exe`, `Lab15-03.exe`. (Có `Hashes.csv` để đối chiếu.)
> Đây là mẫu malware thật — chỉ phân tích trong VM restorable, không chạy trên máy giải.

### Lab 15-01 — Rogue byte + jump-after-jcc (Mục 1)
- **Kỹ thuật:** cặp jump (jz/jnz hoặc jump tới constant) + byte rác `0xE8` chèn sau,
  lặp lại **5 lần**. Mỗi lần byte `E8` làm linear sweep nuốt lệnh thật.
- **Cách giải:** tại mỗi byte rác `E8`: trong IDA nhấn `U` rồi `C` tại địa chỉ ngay sau;
  hoặc patch `E8`→`90`. Đếm/sửa cả 5 chỗ. Sau khi sạch, chương trình với tham số đúng
  (vd `pdq`) in `"Good Job!"`. (Xem writeup baotdvi: đếm đủ 5 byte `E8`.)
- **Khớp tài liệu:** Mục 1 + Mục 7.

### Lab 15-02 — Nhiều lớp opaque predicate + jump vào giữa lệnh (Mục 2, 3)
- **Kỹ thuật:** dùng điều kiện giả và jump làm lệch căn chỉnh ở nhiều vị trí; phải
  "sửa code trước khi phân tích" (như writeup nêu: phải chỉnh lại các đoạn chống-disasm
  rồi mới đọc được logic). Thường liên quan tới chuỗi URL/hành vi mạng bị giấu.
- **Cách giải:** lần lượt `U`→`C`/Clear→Disassemble tại các điểm lệch; ép jcc→jmp ở
  opaque predicate; NOP byte rác. Sau khi căn lại, logic (vd dựng URL, so sánh) hiện rõ.
- **Khớp tài liệu:** Mục 2 + Mục 3 (+ 7).

### Lab 15-03 — Thủ thuật `call`/stack + chuyển luồng tinh vi (Mục 4, 5)
- **Kỹ thuật:** lạm dụng `call`/`ret` và thao tác stack (kiểu `push addr; ret` / sửa
  địa chỉ trả về / thunk lấy EIP) để chuyển hướng luồng mà disassembler không theo kịp;
  dẫn tới hàm bị cắt luồng, bỏ qua code thật (thường gọi ngược `main` hoặc nhảy tới
  thủ tục bị giấu).
- **Cách giải:** truy đích thật của `ret`/`call` (đọc imm được push, hoặc chạy động trong
  x64dbg để lấy địa chỉ trả về), rồi `C`/Disassemble tại đích, thêm xref thủ công.
  Phân tích động giúp xác nhận đích nhanh nhất.
- **Khớp tài liệu:** Mục 4 + Mục 5 (+ 7).

> Ghi chú: tên gọi/chi tiết từng lab có thể khác nhẹ giữa các writeup; hãy dùng checklist
> Mục 9 để tự nhận diện thay vì nhớ máy móc. Writeup tham khảo: baotdvi.wordpress.com,
> medium/@aitichoumustapha (Lab 15).

---

## 11. Nguồn tham khảo đã đọc / đối chiếu
- 1malware1, "Anti-Disassembly Techniques" (nguồn chính; truy cập bị chặn 403 khi soạn,
  nội dung đối chiếu qua kiến thức PMA Ch.15 + các nguồn dưới):
  https://1malware1.medium.com/anti-disassembly-techniques-e012338f2ae0
- baotdvi, "Practical Malware Analysis – OllyDbg Lab15":
  https://baotdvi.wordpress.com/2019/05/31/practical-malware-analysis-ollydbg-lab15/
- aitichoumustapha, "Lab 15 – Discover Anti-Disassembly Techniques" (403 khi soạn):
  https://medium.com/@aitichoumustapha/lab-15-practical-malware-analysis-discover-anti-disassembly-techniques-7198b91baf3f
- Mẫu luyện tập rikonaka (Lab15-01/02/03):
  https://github.com/rikonaka/PracticalMalwareAnalysis-Labs-Sample
- aldeid wiki — Impossible Disassembly (minh hoạ `EB FF C0`):
  https://www.aldeid.com/wiki/Category:Digital-Forensics/Computer-Forensics/Anti-Reverse-Engineering/Anti-Disassembly/Impossible-Disassembly
- UMBC CMSC491 Chapter 16 notes (rogue byte, `0xE8` 5-byte swallow):
  https://courses.cs.umbc.edu/undergraduate/CMSC491malware/chapter16.html
- NDSS 2020 bar2020-23004 (opaque predicate `xor; jz`):
  https://www.ndss-symposium.org/wp-content/uploads/2020/04/bar2020-23004-paper.pdf

*Tài liệu phục vụ phân tích/giải đề CTF hợp lệ. Luôn chạy mẫu trong môi trường cách ly.*
