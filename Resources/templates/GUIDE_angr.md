# GUIDE — angr (Symbolic Execution) cho Reverse

> File di kem: `tmpl_angr.py`
> Dung cho: Cyber SEA Game 2026 — mang Reverse. Chuan bi truoc giai.

---

## Muc luc
1. [Khi nao dung angr (vs z3)](#1-khi-nao-dung-angr-vs-z3)
2. [Cai dat](#2-cai-dat)
3. [Template lam gi](#3-template-lam-gi)
4. [Cach dung tung buoc + cach tim dia chi find/avoid](#4-cach-dung-tung-buoc--cach-tim-dia-chi-findavoid)
5. [Giai thich tung phan](#5-giai-thich-tung-phan)
6. [Vi du ap dung](#6-vi-du-ap-dung)
7. [Cam bay thuong gap](#7-cam-bay-thuong-gap)
8. [Tham khao](#8-tham-khao)

---

## 1. Khi nao dung angr (vs z3)

**angr** = framework phan tich binary + **symbolic execution**: no "chay thu" chuong trinh
voi input la bien ky hieu (symbolic), roi tu dong thu thap rang buoc tren moi duong di.
Ban chi can chi cho no "dich den dung" (nhanh in `Correct`) va "nhanh can tranh"
(nhanh in `Wrong`); angr se giai ra input dua ban toi dich.

| Tinh huong | Nen dung |
|---|---|
| **Khong muon dich tay logic kiem tra**; chi biet "doan nay in Correct, doan kia in Wrong" | **angr** — no tu kham pha duong di, ta khong can hieu thuat toan ben trong |
| Chuong trinh nho/vua, input vai chuc byte, logic re nhanh (if/else, so sanh byte) | **angr** rat hop |
| **Da dich tay** xong cong thuc/rang buoc (vd `a*x + b == c`, bang phep XOR/so sanh ro rang) | **z3** — minh tu viet rang buoc, nhanh va goi nhe hon nhieu |
| Vong lap rat lon / nhieu nhanh / hash manh (MD5, SHA, AES) | **z3** (sau khi reverse tay) hoac brute — angr se bi *path explosion* hoac qua cham |
| Binary lon, nhieu syscall/IO phuc tap | Can **hook** (Mau C) hoac chuyen sang reverse tay + z3 |

**Tom tat:** angr = "luoi, de may lo"; z3 = "da hieu bai, chi can giai he rang buoc".
Trong giai, **thu angr truoc** cho cac flag-checker nho (thuong an trong vai phut);
neu no treo/no bo nho thi reverse tay roi chuyen qua z3.

---

## 2. Cai dat

```bash
pip install angr
```

- `claripy` (tao bien symbolic) di kem khi cai `angr`, khong can cai rieng.
- Nen cai truoc giai (tren Kali VM) vi angr keo nhieu dependency (cle, pyvex, z3...).
- Kiem tra nhanh:
  ```bash
  python -c "import angr, claripy; print(angr.__version__)"
  ```
- Chi check cu phap template (khong can cai angr):
  ```bash
  python -m py_compile tmpl_angr.py
  ```

> Goi y: angr chay on dinh tren Linux (Kali VM). Tren Windows cung chay duoc
> nhung nen uu tien VM cho nhat quan, nhat la khi phan tich ELF.

---

## 3. Template lam gi

`tmpl_angr.py` cung cap 3 "mau" (chon bang bien `MODE` o dau file):

- **Mau A — stdin symbolic + find/avoid.**
  Chuong trinh doc input tu `stdin` roi in `Correct`/`Wrong`.
  Ho tro 2 kieu dich: **theo dia chi** (A1) hoac **theo chuoi stdout** (A2).

- **Mau B — input symbolic vao buffer/argv + rang buoc printable.**
  Input lay tu tham so dong lenh `argv[1]` (B2), hoac ta tu dat bien symbolic
  vao mot buffer trong bo nho roi bat dau tu giua ham check (B1, dung `blank_state`).

- **Mau C — hook/bo qua ham nhieu bang `SimProcedure`.**
  Khi co ham lam angr mac ket hoac no nhanh (chong debug, scanf phuc tap, hash
  nang...), ta thay the/bo qua chung de symbolic execution chay duoc.

Ca 3 mau deu lay ket qua qua `_report()`: dung `state.posix.dumps(0)` (stdin)
hoac `solver.eval(bv, cast_to=bytes)` (buffer/argv).

---

## 4. Cach dung tung buoc + cach tim dia chi find/avoid

### Cac buoc
1. Mo `tmpl_angr.py`, sua **CAU HINH CHUNG**:
   - `BINARY` = duong dan file de bai.
   - `MODE` = `"A"` / `"B"` / `"C"`.
   - `INPUT_LEN` = so byte input ban doan (co the thu vai gia tri).
2. Chon kieu dich:
   - **De nhat:** dung A2 (theo chuoi stdout). Sua `b"Correct"` / `b"Wrong"`
     cho khop dung thong bao binary in ra (chay thu binary 1 lan de biet).
   - **Chinh xac hon:** dung A1/B1 theo dia chi (xem cach tim ben duoi).
3. (Tuy chon) sua rang buoc ky tu:
   - `constrain_printable` cho flag ASCII thong thuong.
   - `constrain_charset(..., b"abcdef0123456789")` neu flag dang hex/charset hep.
4. Chay: `python tmpl_angr.py`. Doi ket qua `[+] TIM THAY! Input = ...`.
5. Neu `[-] KHONG tim thay`: xem phan [Cam bay](#7-cam-bay-thuong-gap).

### Cach tim dia chi `find` / `avoid`
Dich den thuong la lenh ngay sau khi so sanh "dung/sai", hoac dau khoi in
`Correct`/`Wrong`. Cach lay dia chi:

- **IDA / Ghidra:** mo binary, tim chuoi `"Correct"`/`"Wrong"`/`"Flag"`, double-click
  de nhay toi noi dung, lay dia chi lenh (vd `0x401337`). Dia chi `find` = cho bat
  dau nhanh thanh cong; `avoid` = cho bat dau nhanh that bai.
- **objdump:** `objdump -d chall | less` roi tim lenh `call puts`/`printf` tuong ung.
- **strings + grep:** `strings -t x chall | grep -i correct` (lay offset chuoi, roi
  xref trong IDA).
- **radare2:** `r2 -A chall`, dung `axt @ str.Correct` de tim xref.

> **Luu y PIE/ASLR:** neu binary la PIE, dia chi trong IDA thuong tinh tu base
> `0x0` hoac `0x400000`. angr mac dinh nap PIE tai `0x400000`. Neu lech, kiem tra
> `proj.loader.main_object.mapped_base` va cong offset tuong ung. Dung A2
> (theo chuoi) de tranh han van de dia chi tuyet doi.

---

## 5. Giai thich tung phan

### Tao Project
```python
proj = angr.Project(BINARY, auto_load_libs=False)
```
- `auto_load_libs=False`: khong nap libc that (nhanh hon, tranh lac vao ham thu vien);
  angr se dung SimProcedure gia lap cho ham libc.
- `use_sim_procedures=True` (Mau C): ep angr thay ham libc pho bien bang ban gia lap
  on dinh cua no.

### Tao bien symbolic
```python
flag_bytes = [claripy.BVS(f"flag_{i}", 8) for i in range(n)]   # moi byte 8 bit
flag = claripy.Concat(*flag_bytes)                             # noi thanh 1 BV
```
- `claripy.BVS(name, bits)`: bien symbolic (Bit-Vector Symbolic).
- `claripy.BVV(value, bits)`: gia tri cu the (Bit-Vector Value) — dung khi can.

### Tao trang thai khoi dau (state)
- `proj.factory.entry_state(stdin=flag, ...)` — bat dau tu entry point, nap `flag`
  lam stdin. **Hay dung khi** input qua stdin.
- `proj.factory.full_init_state(args=[BINARY, flag], ...)` — chay ca phan khoi tao
  (vd ham khoi tao libc). **Dung khi** input qua `argv` hoac can moi truong day du.
- `proj.factory.blank_state(addr=X, ...)` — trang thai "trong", bat dau tai dia chi `X`.
  **Dung khi** muon nhay vao giua mot ham (Mau B1), tu dat thanh ghi/buffer.

### `add_options` hay dung
- `ZERO_FILL_UNCONSTRAINED_MEMORY` / `..._REGISTERS`: vung nho/thanh ghi chua khoi
  tao se dien 0 thay vi tao them bien symbolic -> **giam path explosion** va bot
  canh bao "unconstrained".
- `angr.options.unicorn`: bat engine unicorn de chay nhanh doan code "dac" (it nhanh re).
- `remove_options={angr.options.LAZY_SOLVES}`: giai rang buoc sat hon (bo dong lai
  nhanh chet som hon) — danh doi toc do lay chinh xac. Thu bat khi ket qua sai la.

### Rang buoc ky tu
```python
state.solver.add(b >= 0x20); state.solver.add(b <= 0x7e)   # printable
```
Giup solver tra ve input doc duoc va thuong hoi tu nhanh hon.

### Explore (tim duong)
```python
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=..., avoid=...)
```
- `find` / `avoid` nhan: **1 dia chi**, **list/set dia chi**, hoac **ham predicate**
  `lambda s: ...` tra ve True/False.
- Kieu chuoi stdout (ben vung nhat):
  ```python
  simgr.explore(find=lambda s: b"Correct" in s.posix.dumps(1),
                avoid=lambda s: b"Wrong"   in s.posix.dumps(1))
  ```
  (`1` = fd stdout, `2` = stderr).
- `num_find=N`: tim du N nghiem moi dung (mac dinh 1).
- `step_func=lambda lsm: lsm.drop(stash="avoid")`: xoa cac state bi `avoid` sau moi
  buoc -> tiet kiem RAM cho bai nhieu nhanh.

### Hook / SimProcedure (Mau C)
```python
class SkipProcedure(angr.SimProcedure):
    def run(self, *args):
        return 0

proj.hook(0x401500, SkipProcedure())        # hook theo dia chi
proj.hook_symbol("anti_debug", SkipProcedure())   # hook theo ten ham
```
- Hook = thay the 1 ham/1 doan bang code Python cua minh -> bo qua ham nhieu,
  tra gia tri co dinh, hoac cat nhanh.
- `@proj.hook(addr, length=5)`: thay `length` byte lenh goc bang 1 ham inline.

### Lay ket qua
```python
# input qua stdin:
data = found.posix.dumps(0)
# input qua buffer/argv (eval truc tiep BitVector):
data = found.solver.eval(flag, cast_to=bytes)
```

---

## 6. Vi du ap dung

### Vi du 1 — crackme co dien (stdin -> Correct/Wrong)
Binary doc 1 dong tu stdin, in `Correct!` neu dung.
- `MODE = "A"`, dung A2 (theo chuoi), `INPUT_LEN` = do dai flag.
- Chay -> `found.posix.dumps(0)` cho ra flag. (Day la bai mau "kinh dien" cua angr.)

### Vi du 2 — kiem tra argv[1]
`./chall PASSWORD` -> in `Access granted`.
- `MODE = "B"` (nhanh B2 argv), doi `find` thanh `b"Access granted"`.
- Ket qua lay bang `solver.eval(flag, cast_to=bytes)` (template da lam san).

### Vi du 3 — co ham chong debug lam ket treo
Binary goi `ptrace`/ham `anti_debug` khien angr di lac.
- `MODE = "C"`, `proj.hook_symbol("anti_debug", SkipProcedure())` (hoac hook theo
  dia chi neu khong con symbol), roi explore nhu Mau A.

### Vi du 4 — bat dau tu giua ham check(buf)
Chi muon symbolic tu dau ham `check`, buffer o dia chi co dinh.
- `MODE = "B"` nhanh B1: `blank_state(addr=CHECK_ADDR)`, `memory.store(BUF_ADDR, flag)`,
  dat con tro (`state.regs.rdi = BUF_ADDR` cho x86-64 SysV), roi explore theo dia chi.

---

## 7. Cam bay thuong gap

- **Path explosion (no so nhanh):** vong lap/nhanh re qua nhieu -> angr treo, an het RAM.
  Cach xu ly:
  - Them `ZERO_FILL_UNCONSTRAINED_*` (template da bat).
  - `step_func=lambda lsm: lsm.drop(stash="avoid")` de khong giu state bo di.
  - Gioi han do dai input (`INPUT_LEN`) va rang buoc ky tu chat hon (`constrain_charset`).
  - **Hook** cac ham nang/nhieu (Mau C) de cat bot nhanh.
  - Neu van no: dung `blank_state` bat dau sat diem kiem tra, bo qua phan khoi tao.

- **Chay rat cham:** thu `add_options=angr.options.unicorn`; giam INPUT_LEN; bo bot
  rang buoc khong can; hoac chap nhan reverse tay roi chuyen sang z3.

- **Khong tim thay (`simgr.found` rong):**
  - Sai chuoi `Correct`/`Wrong` (chay binary that de xem dung chu).
  - `INPUT_LEN` sai (qua ngan/dai). Thu vai gia tri.
  - Rang buoc printable loai mat nghiem that -> noi long.
  - Dia chi find/avoid sai (nham PIE base). Doi sang kieu chuoi (A2).
  - Nhanh thanh cong bi angr `avoid` nham -> kiem tra lai dieu kien avoid.

- **Chon entry_state vs blank_state vs full_init_state:**
  - Input qua stdin -> `entry_state(stdin=...)`.
  - Input qua argv / can khoi tao day du -> `full_init_state(args=...)`.
  - Bat dau giua chung / tu set thanh ghi+buffer -> `blank_state(addr=...)` (nho
    la state nay "trong", nhieu thu chua khoi tao -> can ZERO_FILL).

- **Canh bao "unconstrained state":** thuong do bo nho/thanh ghi symbolic khong rang
  buoc. Them `ZERO_FILL_UNCONSTRAINED_*`; hoac co the do dang chay vao vung khong hop le
  (kiem tra lai dia chi / ABI khi dat con tro).

- **Ket qua "dung" ma binary bao sai:** co the do `LAZY_SOLVES` dong lai rang buoc muon.
  Thu `remove_options={angr.options.LAZY_SOLVES}`.

- **An toan:** chi chay voi binary cua de bai. Khong tai/chay binary la; neu nghi ngo,
  chay trong VM/sandbox cach ly mang.

---

## 8. Tham khao

- angr — Core concepts (Simulation Managers / pathgroups):
  https://docs.angr.io/en/latest/core-concepts/pathgroups.html
- angr — Explorer (find/avoid, num_find, avoid_priority):
  https://docs.angr.io/en/latest/api/angr.exploration_techniques.explorer.html
- angr — Cheatsheet (full_init_state, BVS, hook, posix.dumps...):
  https://docs.angr.io/en/latest/appendix/cheatsheet.html
- angr — Trang chu / cai dat: https://angr.io  (`pip install angr`)
- angr examples (nhieu crackme mau): https://github.com/angr/angr-doc/tree/master/examples
