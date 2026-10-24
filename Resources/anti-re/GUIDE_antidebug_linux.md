# GUIDE — Bypass Anti-Debug trên Linux (CTF / RE)

> Mục đích: **phân tích & giải đề CTF** (Cyber SEA Game 2026) trên Kali Linux VM
> (có sẵn `gcc`, `gdb`, `radare2`). Mọi kỹ thuật dưới đây dùng trên binary của
> ban tổ chức — không áp dụng lên phần mềm/máy không được phép.

---

## 0. Quy trình chung khi gặp một chall "cứ chạy gdb là thoát"

1. **Trinh sát hành vi (dynamic, nhẹ):**
   - `strace -f -e trace=ptrace,prctl,clock_gettime,getppid ./chall`
     → thấy ngay `ptrace(PTRACE_TRACEME)`, `prctl(PR_SET_DUMPABLE)`, timing...
   - `ltrace -f ./chall` → thấy `fopen("/proc/self/status")`, `getenv(...)`.
   - `strace` **không gắn ptrace vào luồng chính như gdb** nên nhiều check
     "có gdb không" sẽ không nổ khi dùng strace — rất hợp để *khảo sát* trước.
2. **Trinh sát tĩnh (static):**
   - `rabin2 -i ./chall` / `nm -D ./chall` → có `ptrace`, `prctl`, `fork`,
     `signal`/`sigaction`, `getppid`, `clock_gettime` không.
   - `r2 -A ./chall` rồi `axt sym.imp.ptrace` → tìm **mọi chỗ gọi ptrace**.
3. **Chọn vũ khí (theo thứ tự ưu tiên thực dụng):**
   - Gọi **qua libc** (dynamic, có PLT) → `LD_PRELOAD` (nhanh nhất, không sửa file).
   - Gọi **syscall trực tiếp** / static binary / check nằm rải rác →
     **patch tĩnh** bằng r2 hoặc **gdb runtime** (`catch syscall` + sửa `$rax`).
   - Check đọc `/proc` → hook `open/read/fopen` bằng LD_PRELOAD, hoặc patch so sánh.

> **Nguyên tắc vàng:** bypass **đầu ra của check**, không cần diệt chính check.
> Thường chỉ cần làm hàm detect trả về "không có debugger" hoặc đảo nhánh `jz/jnz`.

---

## 1. `ptrace(PTRACE_TRACEME, 0, 0, 0)` — self-attach

### Nguyên lý
Một tiến trình chỉ có thể bị **một** tracer. Khi chall tự gọi `PTRACE_TRACEME`:
- Không có debugger → trả `0` (thành công) → chạy tiếp bình thường.
- Đang bị gdb attach → trả `-1`, `errno=EPERM` → chall biết bị debug → thoát/đi sai nhánh.

Biến thể hay gặp:
- Gọi **hai lần**: lần 1 để "chiếm chỗ" tracer, lần 2 nếu thành công nghĩa là
  không ai trace → đổi hành vi.
- Lưu kết quả vào biến rồi dùng để **giải mã flag** (nếu bypass sai, flag hỏng).
- Gọi **gián tiếp** qua `syscall(SYS_ptrace, ...)` để né hook libc.

### Cách phát hiện
```bash
strace -f -e trace=ptrace ./chall      # thấy: ptrace(PTRACE_TRACEME) = -1 EPERM
rabin2 -i ./chall | grep -i ptrace     # có import ptrace
r2 -A -q -c 'axt sym.imp.ptrace' ./chall   # liệt kê mọi caller
```

### Cách BYPASS

**(A) LD_PRELOAD — giả `ptrace()` (ưu tiên, không sửa file)**
Dùng `fake_ptrace.c` kèm theo (override `ptrace` *và* `syscall(SYS_ptrace)` → luôn trả 0):
```bash
gcc -shared -fPIC fake_ptrace.c -o fake_ptrace.so -ldl
LD_PRELOAD=./fake_ptrace.so ./chall
# Chạy cùng gdb:
gdb -q ./chall
(gdb) set environment LD_PRELOAD ./fake_ptrace.so
(gdb) run
```
> ⚠️ **Lưu ý thực chiến:** đặt `fake_ptrace.so` trên **hệ thống file Linux gốc**
> (vd `~/` hoặc `/home/...`), KHÔNG để trên mount lạ (vd `/mnt/...` của WSL/9p) —
> glibc có thể lặng lẽ bỏ qua `LD_PRELOAD` từ các mount đó.
> Chỉ ăn với binary **dynamic, gọi ptrace qua libc**. Static / direct-syscall → dùng (B)/(C).

**(B) gdb runtime — bắt syscall rồi ép kết quả = 0**
```gdb
catch syscall ptrace
run
# Mỗi lần dừng ở ptrace, cho syscall chạy xong rồi sửa giá trị trả về:
# dừng lần 1 = lúc VÀO syscall; next để ra khỏi syscall rồi set $rax
# Cách gọn: dừng khi VÀO, đổi request thành vô hại hoặc bỏ qua:
set $rax = 0
# Hoặc dùng catchpoint 2 lần (entry/return) và chỉ sửa ở return:
# (xem gdb_antidebug.md, phần "ptrace return = 0")
continue
```
Mẹo tự động (bỏ qua MỌI ptrace, trả 0 ở return):
```gdb
catch syscall ptrace
commands
  silent
  # catch syscall dừng cả lúc vào và ra; sửa rax ở lần "ra"
  if $rax != 0xffffffffffffffff && $_siginfo == 0
  end
  set $rax = 0
  continue
end
```
(Đơn giản & chắc hơn: xem `gdb_antidebug.md`.)

**(C) Patch tĩnh — biến lời gọi ptrace thành vô hại**
Mục tiêu: sau `call ptrace`, `rax` phải = 0. Ba cách:
1. NOP luôn lời gọi + xoá rax:
   - thay `call ptrace` (E8 ..) bằng `xor eax,eax` + NOP padding.
2. Đảo nhánh so sánh kết quả (vd `js`/`jne` → `jmp`/NOP).
3. Nếu binary tự implement bằng `mov eax, 101; syscall`: NOP cụm syscall, set eax=0.

radare2:
```bash
r2 -w -A ./chall
[0x..]> axt sym.imp.ptrace         # tìm địa chỉ caller
[0x..]> s <addr_call_ptrace>
[0x..]> wa xor eax, eax            # ghi đè lệnh call thành xor eax,eax
# nếu lệnh call dài 5 byte, bù NOP cho đủ:
[0x..]> wa nop ; nop ; nop         # (hoặc 'wx 90...' cho đủ số byte)
```
Hoặc đảo điều kiện nhánh:
```bash
[0x..]> s <addr_jump_sau_cmp>
[0x..]> wao nop                    # vô hiệu nhánh thoát
# hoặc đảo: wx 90 90 ... / dùng 'wao nocj' để xoá conditional jump
```

---

## 2. `/proc/self/status` → `TracerPid != 0`

### Nguyên lý
`/proc/<pid>/status` có dòng `TracerPid:` = PID của tiến trình đang trace.
- Không bị trace → `TracerPid: 0`.
- Bị gdb/strace attach → `TracerPid: <pid của gdb>` (khác 0).
Chall `open("/proc/self/status")`, đọc, `strstr("TracerPid:")`, parse số → nếu ≠ 0 thì thoát.

### Cách phát hiện
```bash
ltrace -e 'fopen+open+read+strstr' ./chall     # thấy mở /proc/self/status
strings ./chall | grep -iE 'TracerPid|/proc/self/status'
r2 -q -c 'izz~TracerPid' ./chall
```

### Cách BYPASS

**(A) LD_PRELOAD — hook `open`/`fopen`, chuyển hướng sang file giả**
Tạo một `status` giả có `TracerPid: 0`, rồi hook để khi chall mở
`/proc/self/status` sẽ nhận file giả:
```c
// fake_status.c  —  gcc -shared -fPIC fake_status.c -o fake_status.so -ldl
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
static const char *redir(const char *p){
    if (p && (strstr(p,"/proc/self/status") || strstr(p,"/status")
              && strstr(p,"/proc")))
        return "/tmp/fake_status";   // file giả, TracerPid: 0
    return p;
}
FILE *fopen(const char *p, const char *m){
    FILE *(*real)(const char*,const char*) = dlsym(RTLD_NEXT,"fopen");
    return real(redir(p), m);
}
int open(const char *p, int fl, ...){      // (bỏ bớt mode cho gọn)
    int (*real)(const char*,int,...) = dlsym(RTLD_NEXT,"open");
    return real(redir(p), fl);
}
```
Chuẩn bị file giả & chạy:
```bash
grep -v TracerPid /proc/self/status > /tmp/fake_status
printf 'TracerPid:\t0\n' >> /tmp/fake_status
LD_PRELOAD=./fake_status.so ./chall
```

**(B) Patch tĩnh — vô hiệu so sánh**
Sau khi parse ra số TracerPid, có lệnh `cmp`/`test` + nhánh. Đảo/NOP nhánh đó:
```bash
r2 -w -A ./chall
[0x..]> izz~TracerPid          # tìm chuỗi
[0x..]> axt <addr_string>      # tìm nơi dùng → lần tới cmp/jne
[0x..]> s <addr_jne>
[0x..]> wao nop                # bỏ nhánh thoát khi TracerPid != 0
```

**(C) gdb runtime — sửa giá trị đọc được về 0**
Đặt breakpoint sau khi đọc/parse, set biến/thanh ghi chứa TracerPid = 0:
```gdb
b *<addr_sau_parse>
run
set $eax = 0        # hoặc sửa biến cục bộ: set var tracer_pid = 0
continue
```

**(D) "Né" bằng công cụ không attach kiểu ptrace**
Nhiều check chỉ nhắm gdb/strace. Có thể **đọc tĩnh + mô phỏng** bằng
`r2` (ESIL, `aei; aeim; aer; aes`) hoặc **Qiling/Unicorn** để chạy emulate
mà không hề có TracerPid — check tự nhiên trả 0.

---

## 3. `getppid` / tên tiến trình cha

### Nguyên lý
Khi chạy dưới gdb, **cha** của chall là gdb (hoặc shell khác bình thường).
- `getppid()` rồi đọc `/proc/<ppid>/comm` hoặc `/proc/<ppid>/cmdline` →
  nếu thấy `gdb`, `strace`, `ltrace`, `r2`, `ida`... thì thoát.
- Hoặc so `getppid()` với PID shell "bình thường".

### Phát hiện
```bash
ltrace -e 'getppid+open+read' ./chall
strings ./chall | grep -iE 'gdb|strace|ltrace|radare|/proc/.*/comm|cmdline'
```

### BYPASS
**(A) Đổi tên tiến trình debugger** — hiếm khi cần, nhưng:
- Chạy gdb qua một wrapper đổi `argv[0]`, hoặc rename binary gdb → ít thực dụng.

**(B) LD_PRELOAD hook `open`/`read`** đối với `/proc/<ppid>/comm|cmdline`
(tương tự mục 2A): trả về chuỗi `bash\n` thay vì `gdb`.

**(C) Patch tĩnh / gdb runtime (ưu tiên):**
- Tìm `strstr(comm,"gdb")` / `strcmp` → đảo nhánh (`wao nop`), hoặc
- gdb: breakpoint sau khi đọc comm, `set` chuỗi về `"bash"` hoặc ép so sánh "không khớp".

**(D) Chạy "detach" khỏi cây tiến trình debugger:**
```gdb
set exec-wrapper setsid        # đặt chall vào session mới, đổi quan hệ cha-con
```
hoặc dùng `setarch`/wrapper để `getppid()` trả về tiến trình trông "lành".

---

## 4. Timing checks (`clock_gettime` / `rdtsc` / `time`)

### Nguyên lý
Debugger làm chậm thực thi. Chall đo thời gian giữa hai mốc; nếu quá lớn
(do ta đang single-step / dừng breakpoint) → kết luận bị debug.
- `rdtsc` (đọc Time Stamp Counter) trước/sau một đoạn, so delta.
- `clock_gettime(CLOCK_MONOTONIC,...)` hoặc `gettimeofday`/`time`.

### Phát hiện
```bash
strace -e trace=clock_gettime,gettimeofday ./chall
r2 -q -c 'pd 9999 @ main ~ rdtsc' ./chall      # tìm lệnh rdtsc (0F 31)
objdump -d ./chall | grep -i rdtsc
```

### BYPASS
**(A) Đừng single-step qua vùng timing** — đặt breakpoint **sau** mốc đo thứ 2,
rồi `continue` qua cả đoạn (delta nhỏ vì không dừng ở giữa).

**(B) gdb — ép delta nhỏ / giả giá trị thời gian:**
```gdb
# với rdtsc: đặt bp tại lệnh sau rdtsc thứ 2, ép edx:eax = giá trị gần với lần 1
# đơn giản hơn: ép nhánh "quá chậm" không chạy -> set cờ/nhảy qua
b *<addr_sau_cmp_delta>
run
set $zf = ... / jump <addr_nhanh_ok>
```
**(C) LD_PRELOAD giả `clock_gettime`/`gettimeofday`** — trả thời gian tăng đều,
mỗi lần gọi chỉ +1 "tick" nhỏ → delta luôn bé:
```c
// fake_time.c — gcc -shared -fPIC fake_time.c -o fake_time.so -ldl
#define _GNU_SOURCE
#include <time.h>
static long t = 0;
int clock_gettime(clockid_t c, struct timespec *ts){
    ts->tv_sec = t; ts->tv_nsec = (t++ % 1000)*1000; return 0;   // tăng rất chậm
}
```
**(D) Patch tĩnh:** NOP lệnh `rdtsc` hoặc đảo nhánh `ja/jg` so sánh delta:
```bash
r2 -w -c 's <addr_rdtsc>; wx 31C0 31D2' ./chall   # rdtsc -> xor eax,eax; xor edx,edx
# hoặc 'wao nop' tại nhánh so sánh delta
```
> Với emulator (Unicorn/Qiling) có thể hook `rdtsc`/MSR để luôn trả delta cố định.

---

## 5. Bẫy tín hiệu SIGTRAP (self-debug bằng INT3)

### Nguyên lý
Chall tự cài handler cho `SIGTRAP` (qua `signal`/`sigaction`), rồi **cố ý**
thực thi `int3` (0xCC). Bình thường tín hiệu SIGTRAP sẽ vào handler của chall
→ handler giải mã/giải flag. Nhưng khi chạy dưới gdb, **gdb nuốt SIGTRAP**
(vì gdb dùng SIGTRAP cho breakpoint) → handler của chall không chạy →
flag sai / chall biết bị debug.

### Phát hiện
```bash
rabin2 -i ./chall | grep -iE 'signal|sigaction'
objdump -d ./chall | grep -iE 'int3|cc '      # tìm int3 nhúng
r2 -q -c 'pd 200 @ main ~ int3' ./chall
```

### BYPASS
**(A) Trả SIGTRAP lại cho chương trình (quan trọng nhất):**
```gdb
handle SIGTRAP nostop pass noprint
# nostop: không dừng; pass: chuyển tín hiệu cho handler của chall
run
```
> Nếu chall dùng SIGTRAP cho logic, `pass` là bắt buộc để handler chạy.
> Cẩn thận: `pass` có thể xung đột với breakpoint phần mềm của gdb trong
> cùng vùng — đặt breakpoint ở nơi khác, hoặc dùng hardware bp (`hbreak`).

**(B) Các tín hiệu khác** chall có thể lạm dụng (SIGSEGV, SIGILL, SIGFPE để
nhảy vào handler giải mã):
```gdb
handle SIGSEGV nostop pass noprint
handle SIGILL  nostop pass noprint
```
**(C) Patch tĩnh:** nếu check chỉ dùng SIGTRAP để *phát hiện* (không phải để
giải mã), có thể NOP lệnh `int3` và đảo nhánh. Nhưng nếu handler **giải mã
flag**, KHÔNG được NOP — phải để handler chạy (dùng A) hoặc tự mô phỏng handler.

---

## 6. `prctl(PR_SET_DUMPABLE, 0)` — chống attach

### Nguyên lý
`prctl(PR_SET_DUMPABLE, 0)` khiến tiến trình "non-dumpable" → gdb/attach
(`PTRACE_ATTACH`) bị từ chối với `EPERM`, và `/proc/<pid>/mem` khó đọc.

### Phát hiện
```bash
strace -e trace=prctl ./chall        # prctl(PR_SET_DUMPABLE, 0)
rabin2 -i ./chall | grep -i prctl
```

### BYPASS
**(A) LD_PRELOAD giả `prctl`** (nuốt PR_SET_DUMPABLE):
```c
// trong fake lib: nếu option == PR_SET_DUMPABLE -> return 0 (không làm gì)
int prctl(int option, ...){ if (option==4/*PR_SET_DUMPABLE*/) return 0; ... }
```
**(B) Patch tĩnh / gdb:** NOP lời gọi `prctl`, hoặc `catch syscall prctl` rồi
sửa `rdi`(option) sang giá trị vô hại trước khi chạy.
**(C)** Khởi động chall **dưới gdb từ đầu** (`run`, không `attach`) — vì
non-dumpable chặn *attach sau*, còn tracer đã có từ `PTRACE_TRACEME`/`fork` thì
thường vẫn ok. Ưu tiên `gdb ./chall; run` thay vì gắn vào tiến trình đang chạy.

---

## 7. fork/clone tricks (cha debug con)

### Nguyên lý
Chall `fork()`; **tiến trình cha tự `PTRACE_ATTACH` vào con** và làm tracer
"hợp lệ". Khi đó debugger của ta KHÔNG thể attach vào con nữa (đã có tracer).
Logic thật chạy ở con, dưới sự kiểm soát của cha; nếu ta chen vào, hỏng.

### Phát hiện
```bash
strace -f ./chall    # thấy clone/fork + ptrace(PTRACE_ATTACH/PTRACE_CONT) giữa 2 pid
```

### BYPASS
**(A) Theo đúng tiến trình con trong gdb:**
```gdb
set follow-fork-mode child       # bám con (nơi có logic thật)
set detach-on-fork off           # giữ cả hai để kiểm soát
run
```
Để bám cha (nếu logic ở cha): `set follow-fork-mode parent`.
**(B) Vô hiệu việc cha-trace-con:** patch/hook sao cho `ptrace(PTRACE_ATTACH)`
của cha thất bại hoặc bị bỏ qua → dùng `fake_ptrace.so` (trả 0, không thực sự
attach) để cha "tưởng" đã trace nhưng không chiếm chỗ tracer, mở đường cho gdb.
**(C) inferior calls / scheduler:**
```gdb
set schedule-multiple on         # chạy mọi inferior
info inferiors                   # xem các tiến trình đang theo
inferior <n>                     # chuyển qua lại cha/con
```

---

## 8. Biến môi trường (LD_PRELOAD / LINES / COLUMNS / `_`)

### Nguyên lý
- Phát hiện **chính LD_PRELOAD** của ta: chall `getenv("LD_PRELOAD")` → nếu có
  thì biết đang bị hook → thoát (đòn phản LD_PRELOAD).
- `getenv("LINES")`/`getenv("COLUMNS")`: gdb/terminal hay set các biến này;
  môi trường chạy "sạch" thường không có → sự hiện diện ⇒ nghi có debugger/terminal.
- `getenv("_")`: chứa đường dẫn chương trình khởi chạy; nếu = `/usr/bin/gdb`
  (hoặc chứa `gdb`) ⇒ bị debug.

### Phát hiện
```bash
ltrace -e getenv ./chall
strings ./chall | grep -iE 'LD_PRELOAD|LINES|COLUMNS|^_$|gdb'
```

### BYPASS
**(A) Dọn môi trường trước khi chạy:**
```bash
env -i PATH=/usr/bin ./chall             # chạy với môi trường tối thiểu
unset LINES COLUMNS                       # gỡ biến terminal
```
Trong gdb:
```gdb
unset environment LINES
unset environment COLUMNS
unset environment _
run
```
**(B) Né check LD_PRELOAD mà vẫn hook:** thay vì `LD_PRELOAD`, dùng
`/etc/ld.so.preload` (file) hoặc **patch `getenv("LD_PRELOAD")`** để trả NULL:
- hook `getenv`: nếu tên == "LD_PRELOAD" → trả `NULL`.
```c
char *getenv(const char *name){
    char *(*real)(const char*) = dlsym(RTLD_NEXT,"getenv");
    if (name && !strcmp(name,"LD_PRELOAD")) return 0;   // giấu chính mình
    return real(name);
}
```
**(C) Patch tĩnh:** đảo nhánh sau `getenv` so sánh (giống các mục trên).

---

## 9. Các check khác hay gặp (tóm tắt nhanh)

| Check | Dấu hiệu | Bypass nhanh |
|---|---|---|
| `/proc/self/stat` (trường 4 = ppid, hoặc state 't') | đọc `/proc/self/stat` | hook open (mục 2A) / patch so sánh |
| Scan `/proc/self/maps` tìm lib hook/debugger | đọc `maps`, `strstr("gdb"/"preload")` | đừng preload tên lộ; hook open; patch |
| Breakpoint detection (quét byte `0xCC` trong .text) | tự đọc code mình, so `0xCC` | dùng **hardware bp** (`hbreak`) thay vì sw bp |
| Checksum/CRC đoạn code (phát hiện patch) | hàm băm .text rồi so hằng số | dùng gdb runtime thay vì patch tĩnh; hoặc patch cả hằng số kỳ vọng |
| `PTRACE_TRACEME` kết quả dùng để **giải mã** | flag hỏng nếu bypass sai | phải cho ptrace trả **0** đúng lúc (fake_ptrace / set $rax=0), không NOP mù |
| `personality(ADDR_NO_RANDOMIZE)` + so sánh | tắt ASLR để check | thường vô hại khi debug; bỏ qua |
| `ptrace(PTRACE_TRACEME)` rồi `kill(0, SIGSTOP)` tự kiểm | | `handle SIGSTOP nostop pass` + fake_ptrace |

---

## 10. CHIẾN LƯỢC tổng — "combo" khuyến nghị

**Bước 1 — Khảo sát không xâm nhập:**
```bash
strace -f -e trace=ptrace,prctl,clock_gettime,getppid,openat ./chall 2>&1 | less
ltrace -f -e 'getenv+fopen+open+strstr+strcmp' ./chall 2>&1 | less
rabin2 -I -i ./chall ; rabin2 -zz ./chall | grep -iE 'proc|gdb|Tracer|preload'
```

**Bước 2 — Thử LD_PRELOAD (rẻ, không sửa file):**
```bash
gcc -shared -fPIC fake_ptrace.c -o fake_ptrace.so -ldl   # (giữ .so trên fs Linux gốc)
LD_PRELOAD=./fake_ptrace.so ./chall
# nếu còn check /proc hoặc timing, cộng thêm fake_status.so / fake_time.so
LD_PRELOAD='./fake_ptrace.so ./fake_status.so' ./chall
```

**Bước 3 — gdb với cấu hình "điếc trước anti-debug"** (xem `gdb_antidebug.md`):
```gdb
set follow-fork-mode child
set detach-on-fork off
handle SIGTRAP nostop pass noprint
handle SIGSEGV nostop pass noprint
catch syscall ptrace
set environment LD_PRELOAD ./fake_ptrace.so
unset environment LINES
unset environment COLUMNS
run
```
Khuyến nghị cài **gef** hoặc **pwndbg** (có sẵn tiện ích; gef có `aslr`,
`checksec`, và nhìn trạng thái tracer dễ hơn).

**Bước 4 — Nếu vẫn chặn (static / direct syscall / nhiều check): PATCH TĨNH bằng r2:**
```bash
r2 -w -A ./chall
[0x..]> axt sym.imp.ptrace          # và các import prctl, getppid...
[0x..]> s <addr> ; wa xor eax,eax ; wao nop   # vô hiệu từng điểm
[0x..]> /x cc                        # tìm int3 nhúng nếu nghi SIGTRAP trick
[0x..]> pdf @ main                    # đọc lại để xác nhận nhánh đã đảo
```
Sau patch, kiểm chứng lại bằng `strace`/chạy thường.

**Bước 5 — Khi tất cả đều khó (nhiều lớp, direct syscall, self-modifying):**
- **Emulate**: Qiling / Unicorn — hook `ptrace`, `rdtsc`, `open("/proc/...")`
  ở tầng syscall/instruction, không có khái niệm TracerPid → phần lớn check tự thua.
- **Static recovery**: nếu logic giải flag nằm gọn, trích thuật toán rồi tự
  viết lại bằng Python, bỏ qua toàn bộ vỏ anti-debug.

---

## 11. Ghi chú quan trọng về "đừng bypass mù"

- Nếu kết quả ptrace / TracerPid / SIGTRAP được **đưa vào phép giải mã flag**
  (XOR key, nhánh tính toán), thì **NOP mù sẽ cho flag rác**. Khi đó phải làm
  check trả về **đúng giá trị của trường hợp "không bị debug"** (ptrace→0,
  TracerPid→0, handler SIGTRAP **được chạy**), chứ không phải xoá nó đi.
- Luôn so sánh output "chạy thường (không gdb)" vs "chạy có bypass": nếu khác,
  bypass đã làm lệch logic → xem lại.
- Ưu tiên **gdb runtime / emulate** khi nghi có checksum code (patch tĩnh sẽ bị
  phát hiện bởi CRC).

---

## Phụ lục — Bảng tra nhanh gdb/r2

| Việc | gdb | radare2 |
|---|---|---|
| Bắt syscall ptrace | `catch syscall ptrace` | `dcs ptrace` (trong `r2 -d`) |
| Ép rax=0 | `set $rax=0` | `dr rax=0` |
| Bỏ dừng ở SIGTRAP | `handle SIGTRAP nostop pass noprint` | `dk` / `e dbg.bep` |
| Bám tiến trình con | `set follow-fork-mode child` | `e dbg.forks=true` |
| Ghi đè lệnh | `set {char}addr=0x90` | `wx 90 @ addr` / `wa nop @ addr` |
| Đảo nhánh | `jump addr` | `wao nop` / `wao recj` |
| Đặt breakpoint HW | `hbreak *addr` | `drx`/`dbh` |

> Chi tiết lệnh & ví dụ patch xem `gdb_antidebug.md`.
