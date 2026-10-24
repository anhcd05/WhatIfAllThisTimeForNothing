# GUIDE: PATCH FILE cho CTF Reverse (PE + ELF)

> Bo cong cu di kem: `patch_bytes.py` (universal byte patcher).
> Muc tieu: bo qua check / ep nhanh / vo hieu anti-debug & anti-disasm
> **SAU KHI** da reverse ra chinh xac cho can sua.

---

## 1. Khi nao patch?

Patch la buoc **cuoi**, chi lam sau khi da hieu logic:

1. Reverse bang Ghidra / IDA / radare2 -> tim ham check (so sanh flag, verify key...).
2. Xac dinh **lenh re nhanh quyet dinh** (thuong la `jz/jnz/je/jne` sau `cmp/test`,
   hoac gia tri tra ve `eax` cua ham `check()`).
3. Dong o x64dbg / gdb de **xac nhan runtime** dia chi do thuc su chay qua.
4. Chon kieu patch toi thieu (dao 1 jcc thuong du, dung NOP ca khoi khi chua chac).

Khi nao KHONG patch: neu de can **tinh dung** flag (crackme sinh flag tu input).
Luc do patch chi giup "qua man hinh Correct", KHONG cho ra flag -> phai giai thuat toan.
Patch chi hop ly khi: flag duoc so sanh truc tiep (patch de in ra), hoac flag nam
san trong binary va bi check chan.

Cac tinh huong patch dien hinh:
- Bo qua kiem tra license / serial (ep nhanh dung).
- Vo hieu anti-debug (`ptrace`, `IsDebuggerPresent`, `/proc/self/status`...).
- Go anti-disassembly (junk byte, opcode rac lam Ghidra doc sai) -> NOP vung rac.
- Mo khoa chuc nang bi an sau mot cmp.

---

## 2. VA <-> FILE OFFSET (quan trong nhat)

Patch **ghi vao FILE tren dia** -> ban can **FILE OFFSET**.
Nhung disassembler hien thi **VA (Virtual Address)** luc chay. Phai quy doi.

### 2.1 PE (Windows, .exe/.dll)

```
RVA = VA - ImageBase
file_offset = RVA - Section.VirtualAddress + Section.PointerToRawData
```

- `ImageBase`: trong Optional Header (hay gap 0x140000000 cho exe x64, 0x400000 x86).
- Moi section (`.text`, `.rdata`...) co `VirtualAddress` (RVA khi map) va
  `PointerToRawData` (offset trong file). Tim section chua RVA roi quy doi.
- **ASLR**: exe co the duoc re-base khi chay. Dia chi x64dbg hien thi co the lech
  ImageBase. Luon tinh lai theo ImageBase that (x64dbg: tab Memory Map, hoac dung
  "File offset" column). Khi patch file TINH, chi quan tam offset trong file, khong
  phai dia chi runtime.

### 2.2 ELF (Linux)

```
file_offset = VA - Segment.p_vaddr + Segment.p_offset   (voi segment PT_LOAD chua VA)
```

- Khong co khai niem section cho viec map; dung **program headers (PT_LOAD)**.
- **PIE (Position-Independent Executable)**: VA trong Ghidra thuong bat dau tu
  0x0 hoac 0x100000. Luc chay bi cong them base ngau nhien (ASLR). Khi patch FILE,
  BO QUA base runtime — chi dung VA "tinh" ma Ghidra/readelf hien thi, quy doi theo
  program header. Neu ban doc dia chi tu gdb luc chay (co ASLR), phai tru base:
  `VA_tinh = VA_runtime - load_base`.
- Kiem tra nhanh: `readelf -l binary` (xem PT_LOAD: Offset/VirtAddr),
  `readelf -S binary` (section -> offset).

### 2.3 Cong cu quy doi nhanh

- `patch_bytes.py --show 0x401234` -> tu quy doi VA->offset va hexdump.
- radare2: `s 0x401234` roi `s` (hien addr), hoac dung `iS` xem section.
- objdump: `objdump -d -F binary` -> cot `(File Offset: 0x...)`.
- Ghidra: "Window > Memory Map" cho thay anh xa; hoac chuot phai dia chi >
  "Copy Special" / dung script lay file offset.

---

## 3. Patch bang tung cong cu

### 3.1 x64dbg (Windows, RUNTIME + luu ra file)

1. Chay toi dia chi can sua (F2 dat breakpoint, F9 run).
2. Chuot phai lenh -> **Assemble** (phim cach) -> go lenh moi (vd `jmp` thay `jz`,
   hoac `nop`). x64dbg tu NOP phan du neu lenh moi ngan hon.
3. Hoac **Binary > Edit** (Ctrl+E) de sua byte truc tiep.
4. Luu file: **Menu > File > Patch file** (Ctrl+P) -> dialog Patches ->
   chon cac patch -> **Patch File** -> xuat .exe moi da va vao dia.

> x64dbg ghi lai danh sach patch; rat tien de review truoc khi xuat.

### 3.2 Ghidra (tinh)

1. Chon byte/lenh -> chuot phai -> **Patch Instruction** (go asm moi) hoac
   **Modify Bytes...** (sua hex). (Phim tat: Ctrl+Shift+G cho patch instruction
   tuy phien ban.)
2. Ghidra chi sua trong database, chua ghi file.
3. Xuat file da va: **File > Export Program...** -> format **Binary** (hoac
   "Original File" / "PE" tuy ban). Luu ra file moi.

### 3.3 radare2 (nhanh, manh)

```sh
r2 -w ./binary          # mo che do GHI (-w)
[0x...]> s 0x401234     # seek toi dia chi (r2 tu xu ly offset/map)
[0x...]> wx 90 90       # ghi hex (NOP NOP)
[0x...]> wa jmp 0x401250  # ghi assembly (write assemble)
[0x...]> wao nop        # write-assemble-op: NOP lenh hien tai, tu bu do dai
[0x...]> wao nocj        # bien conditional jump -> unconditional (ep jmp)
[0x...]> pd 5            # disasm lai 5 lenh de kiem tra
[0x...]> q
```

- `wx <hex>`: ghi hex thang.
- `wa <asm>`: assemble + ghi.
- `wao <op>`: thao tac theo lenh hien tai: `nop`, `jz`, `jnz`, `ret`, `nocj`
  (conditional->unconditional jump), `recj` (dao dieu kien).
- Neu mo file khong co `-w`: `oo+` de chuyen sang che do ghi.

### 3.4 gdb (RUNTIME, khong ghi file)

Chi doi bo nho khi dang chay (khong luu ra dia):

```gdb
# ghi 1 byte
set {char}0x401234 = 0xeb
# ghi nhieu byte (NOP 2 byte)
set {short}0x401234 = 0x9090
# ghi gia tri tra ve (ep eax = 1 khi dang o dau ham check)
set $eax = 1
# bo qua call anti-debug: dat bp truoc call, roi set $pc qua lenh sau
set $pc = $pc + 5
```

Meo ptrace tren Linux: `catch syscall ptrace` roi `set $rax = 0` khi no return,
hoac dat bien moi truong `LD_PRELOAD` mot `ptrace` gia. Nhung de qua vinh vien
nen patch FILE.

### 3.5 objcopy / dd (tinh, dong lenh)

```sh
# dd: ghi byte tai offset (seek tinh theo byte, khong truncate)
printf '\xeb' | dd of=binary bs=1 seek=$((0x1234)) count=1 conv=notrunc
# ghi nhieu byte tu file hex
printf '\x90\x90\x90\x90\x90' | dd of=binary bs=1 seek=$((0x1234)) conv=notrunc

# objcopy: trich/doi section, it dung de va 1 byte; hay dung cho update-section
objcopy --update-section .text=patched.text binary out
```

> Luon `cp binary binary.bak` truoc khi `dd conv=notrunc` vi no ghi de tai cho.

---

## 4. Cac patch kinh dien

| Muc tieu | Truoc | Sau | Ghi chu |
|---|---|---|---|
| Bo qua `jz` (luon di tiep, khong nhay) | `74 xx` | `90 90` | NOP ca lenh 2 byte |
| Bo qua `jnz` | `75 xx` | `90 90` | |
| Ep LUON nhay (jcc->jmp) | `74 xx` | `EB xx` | giu rel8; `75->EB` tuong tu |
| Ep LUON nhay (near jcc) | `0F 84 rel32` | `E9 rel32 90` | 6 byte -> 5 byte E9 + 1 NOP |
| Dao dieu kien | `74` (jz) | `75` (jnz) | opcode XOR 1 |
| Dao near | `0F 84` | `0F 85` | op2 XOR 1 |
| Tra ve som | `55 ...` (prologue) | `C3` | ham tra ve ngay |
| Ep return = 1 (TRUE) | ... | `B8 01 00 00 00` | mov eax,1 (+ NOP neu du) |
| Ep return = 0 (FALSE) | ... | `31 C0` | xor eax,eax (2 byte) |
| Vo hieu call anti-debug | `E8 rel32` | `90 x5` | NOP 5 byte CALL |

Vo hieu anti-debug cu the:
- **Linux `ptrace(PTRACE_TRACEME)`**: tim `call ptrace` (hoac syscall 101) ->
  NOP call, hoac patch de ket qua coi nhu 0. Co the ep nhanh "neu da bi trace".
- **Windows `IsDebuggerPresent`**: ham tra ve `eax`. Sau `call IsDebuggerPresent`
  thuong co `test eax,eax; jnz debugger_detected`. Patch: NOP call + `xor eax,eax`,
  hoac dao/NOP cai `jnz`.
- **PEB `BeingDebugged`**: doc `fs:[30h]`/`gs:[60h]` + offset 2. Patch nhanh:
  NOP doan doc va ep so sanh.
- **`/proc/self/status` TracerPid**: patch nhanh nhat la bo nhanh phan ung.

---

## 5. Dung `patch_bytes.py` tung buoc

```sh
# 0) chi xem truoc (quy doi VA->offset + hexdump, KHONG sua)
python patch_bytes.py chall --show 0x401234 --len 48

# 1) patch nhanh 1 cho tu CLI (luu ra chall.patched)
python patch_bytes.py chall --va 0x401234 --jmp         # ep jcc -> jmp
python patch_bytes.py chall --off 0x11B0 --nop 2        # NOP jz 2 byte
python patch_bytes.py chall --off 0x1200 --ret          # ret som
python patch_bytes.py chall --va 0x40120F --eax1        # return 1
python patch_bytes.py chall --off 0x1240 --invert       # dao je<->jne
python patch_bytes.py chall --va 0x401055 --nopcall     # NOP call ptrace
python patch_bytes.py chall --off 0x1300 --hex 90 90 90 # hex thu cong
python patch_bytes.py chall -o chall_win --va 0x401234 --jmp  # dat ten dau ra

# 2) patch nhieu cho cung luc: sua list PATCHES trong main() (co # TODO) roi:
python patch_bytes.py chall -o chall_patched
```

- Moi lan chay deu in **hexdump TRUOC/SAU** va danh dau `[..]` byte da doi.
- Dau ra mac dinh `<infile>.patched` — **file goc khong bi ghi de**.
- Vi tri: dung `off=` (file offset) hoac `va=` (tu quy doi: PE qua pefile neu co,
  khong thi tu parse section; ELF tu parse program header).

Vi du list trong `PATCHES`:
```python
PATCHES = [
    {"va": 0x0040129A, "jmp": True,  "note": "ep nhanh Correct luon chay"},
    {"off": 0x11B0,    "nop": 2,     "note": "nop jz sau strcmp"},
    {"off": 0x1200,    "ret": True,  "note": "anti_debug() tra ve ngay"},
]
```

---

## 6. Cam bay thuong gap

1. **Do dai lenh khac nhau**: lenh moi phai <= lenh cu. Neu ngan hon -> **NOP phan
   du** (vd `0F 84 rel32` 6 byte -> `E9 rel32` 5 byte + 1 NOP). `force_jmp` da tu lo.
   Tuyet doi khong de du 1 byte opcode -> lech toan bo disasm phia sau.
2. **Khong doi do dai tong**: dung ghi chen/xoa byte lam xe dich mon offset va vo
   hieu relocation. Chi ghi **de tai cho** (in-place), bu NOP.
3. **Checksum PE**: mot so PE co `CheckSum` trong Optional Header. Sau khi va,
   checksum sai. Da so loader bo qua, nhung driver/ky so thi khong. Neu can:
   `pefile` -> `pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()` roi ghi lai.
4. **Chu ky so (Authenticode / codesign)**: patch lam HONG chu ky. Voi CTF thuong
   khong sao; voi binary ky that se bi tu choi chay -> can go ky.
5. **Packed/obfuscated (UPX, VMProtect...)**: code that chi hien ra sau khi unpack
   trong bo nho. Patch file tinh KHONG an voi code da nen -> phai dump sau unpack
   roi patch, hoac patch runtime bang x64dbg.
6. **Self-check / integrity (CRC code)**: binary tu kiem tra chinh no. Patch mot cho
   co the kich hoat nhanh "tamper detected" o cho khac -> phai tim va vo hieu ca
   routine kiem tra toan ven.
7. **Relative call/jump (E8/E9 rel32)**: rel la **tuong doi so voi lenh ke tiep**.
   Neu tu assemble tay phai tinh `rel = target - (addr_lenh + do_dai_lenh)`.
   Dung `wa`/`wao` (r2) hoac Assemble (x64dbg) de khoi tinh tay.
8. **Nham VA runtime (ASLR/PIE) voi VA tinh**: luon quy doi ra FILE OFFSET; dung
   dia chi runtime co base ngau nhien de patch file.
9. **Endianness khi ghi gia tri nhieu byte** (gdb `set {int}`): x86/x64 little-endian.

---

## 7. Tham khao

- x64dbg docs — Patches dialog, "Patch file" (Ctrl+P): https://help.x64dbg.com/
- Ghidra — Patch Instruction / Export Program (Binary).
- radare2 book — Writing / `w`, `wx`, `wa`, `wao`: https://book.rada.re/
- gdb manual — "Patching", convenience/memory assignment (`set {type}addr=`).
- objcopy / dd (GNU binutils / coreutils) man pages.
- pefile — VA/RVA/offset: `get_offset_from_rva`, `get_rva_from_offset`.
- ELF spec — program headers (PT_LOAD) cho quy doi VA->offset.
- Intel SDM Vol.2 — opcode Jcc (70-7F / 0F 80-8F), JMP (EB/E9), RET (C3), MOV (B8).
