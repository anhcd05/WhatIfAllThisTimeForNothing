# gdb + radare2 — Lệnh vượt anti-debug (cheat sheet CTF)

> Dùng kèm `GUIDE_antidebug_linux.md` và `fake_ptrace.c`.
> Cuối file có mẫu `.gdbinit` dán vào dự án để tự áp dụng khi mở gdb.

---

## A. gdb — vượt `ptrace(PTRACE_TRACEME)` self-attach

### A1. Bắt syscall ptrace rồi ép kết quả = 0 (chắc chắn nhất)
`catch syscall ptrace` dừng **hai lần** mỗi lời gọi: lúc **vào** (entry) và lúc
**ra** (return). Phải sửa `rax` ở lần **ra** (vì entry chưa có kết quả).

```gdb
catch syscall ptrace
run

# --- Lần dừng 1: ENTRY (sắp gọi) ---
# $rax lúc này = số syscall (101 trên x86-64), CHƯA phải kết quả. Bỏ qua.
continue

# --- Lần dừng 2: RETURN (vừa gọi xong) ---
# $rax = kết quả thật (-1 nếu bị detect). Ép về 0:
set $rax = 0
continue
```

### A2. Tự động hoá: luôn ép ptrace trả 0 (không phải bấm tay)
```gdb
catch syscall ptrace
commands
  silent
  # $_siginfo/stop lý do khó phân biệt entry/return gọn trong 1 if,
  # cách bền: dùng biến cờ xen kẽ entry/return.
  if $_ad_in == 0
    set $_ad_in = 1
  else
    set $_ad_in = 0
    set $rax = 0
  end
  continue
end
# khởi tạo cờ trước khi run:
set $_ad_in = 0
run
```
> Nếu phiên bản gdb của bạn hỗ trợ `$_syscall_entry`/catch return tốt hơn,
> có thể đơn giản còn: khi ở return thì `set $rax=0; continue`.

### A3. Đơn giản nhất: dùng LD_PRELOAD trong gdb (khỏi đụng syscall)
```gdb
set environment LD_PRELOAD ./fake_ptrace.so
# (nếu lib kén đường dẫn mnt lạ, copy .so ra ~/ rồi dùng đường dẫn tuyệt đối)
run
```

### A4. Patch ngay trong gdb (nếu biết địa chỉ `call ptrace`)
```gdb
# NOP lời gọi (5 byte call E8 xx xx xx xx) + xoá rax:
# ghi 'xor eax,eax' (31 C0) rồi NOP cho đủ 5 byte:
set {char}0x<addr>   = 0x31
set {char}0x<addr+1> = 0xc0
set {char}0x<addr+2> = 0x90
set {char}0x<addr+3> = 0x90
set {char}0x<addr+4> = 0x90
```

---

## B. gdb — `/proc/self/status` TracerPid, getppid, env

### B1. Sửa giá trị sau khi đọc/parse
```gdb
b *<addr_sau_khi_parse_TracerPid>
run
set $eax = 0          # hoặc: set var tracer = 0 (nếu biết tên biến)
continue
```

### B2. Chuyển hướng file đọc bằng LD_PRELOAD (hook open) — xem GUIDE mục 2A
```gdb
set environment LD_PRELOAD ./fake_status.so
run
```

### B3. Dọn biến môi trường tố giác
```gdb
unset environment LINES
unset environment COLUMNS
unset environment _
# nếu chall tìm LD_PRELOAD mà ta vẫn muốn preload -> dùng fake_status.so hook getenv
run
```

---

## C. gdb — SIGTRAP / tín hiệu

```gdb
# Trả tín hiệu lại cho handler của chall (BẮT BUỘC nếu handler giải mã flag):
handle SIGTRAP nostop pass noprint
handle SIGSEGV nostop pass noprint
handle SIGILL  nostop pass noprint
handle SIGFPE  nostop pass noprint

# Nếu cần đặt breakpoint trong vùng dùng int3, ưu tiên hardware breakpoint
# để không chèn 0xCC trùng với logic của chall:
hbreak *<addr>
```
Xem danh sách xử lý tín hiệu hiện tại: `info signals`.

---

## D. gdb — fork/clone

```gdb
set follow-fork-mode child     # bám tiến trình con (nơi thường có logic)
set detach-on-fork off         # giữ cả cha lẫn con dưới quyền gdb
set schedule-multiple on       # cho cả hai chạy
info inferiors                 # liệt kê các tiến trình
inferior 2                     # chuyển sang inferior khác
run
```
Để tách chall khỏi quan hệ cha-con với gdb (qua mặt getppid):
```gdb
set exec-wrapper setsid
run
```

---

## E. gef / pwndbg — tiện ích thêm

```gdb
# gef:
gef config context.enable 1
aslr off               # tắt ASLR cho ổn định địa chỉ
checksec               # xem RELRO/Canary/NX/PIE
# pwndbg:
checksec
vmmap                  # bản đồ bộ nhớ (xem /proc/self/maps từ phía gdb)
```
Cài nhanh (trên Kali thường có sẵn một trong hai):
```bash
# gef:
bash -c "$(wget -qO- https://gef.blah.cat/sh)"   # (chỉ khi được phép mạng)
```

---

## F. radare2 — khảo sát & PATCH TĨNH

### F1. Phân tích & tìm điểm anti-debug
```bash
r2 -A ./chall
[0x..]> ii                      # imports
[0x..]> axt sym.imp.ptrace      # mọi nơi gọi ptrace
[0x..]> axt sym.imp.prctl
[0x..]> axt sym.imp.getppid
[0x..]> izz~TracerPid           # chuỗi "TracerPid"
[0x..]> /x cc                   # tìm byte int3 (0xCC) nhúng
[0x..]> pdf @ main              # xem disasm hàm main
```

### F2. Patch — các mẫu `wa`/`wx`/`wao`
```bash
r2 -w -A ./chall                # -w: mở ghi

# (1) Biến call ptrace -> xor eax,eax (rax=0), bù nop cho đủ độ dài lệnh:
[0x..]> s <addr_call_ptrace>
[0x..]> wa xor eax, eax         # 'wa' = write assembly
[0x..]> wao nop                 # lặp wao nop nếu còn dư byte của lệnh call cũ
#   hoặc ghi thẳng bytes:
[0x..]> wx 31c09090 90          # 31 c0 = xor eax,eax; 90... = nop

# (2) Đảo / vô hiệu nhánh điều kiện (vd 'jne' thoát khi phát hiện debug):
[0x..]> s <addr_jne>
[0x..]> wao nop                 # xoá hẳn nhánh nhảy
#   hoặc đổi jne->je, ja->jbe... :
[0x..]> wao recj                # 'reverse conditional jump' (đảo điều kiện)

# (3) rdtsc -> xor eax,eax; xor edx,edx (delta luôn 0):
[0x..]> s <addr_rdtsc>
[0x..]> wx 31c031d2             # (rdtsc là 2 byte 0F 31; cần bù nop nếu ghi 4 byte)
[0x..]> wao nop

# (4) NOP nguyên một lời gọi (prctl, kill...) :
[0x..]> s <addr_call>
[0x..]> "wa nop;nop;nop;nop;nop"   # đủ số byte của call

[0x..]> pdf @ main              # đọc lại kiểm chứng
[0x..]> q                       # lưu & thoát (đã mở -w nên ghi trực tiếp)
```

### F3. r2 ở chế độ debug (động) — ép thanh ghi / bắt syscall
```bash
r2 -d ./chall
[0x..]> dcs ptrace              # chạy tới syscall ptrace
[0x..]> dr rax=0                # ép kết quả = 0
[0x..]> dc                      # tiếp tục
[0x..]> e dbg.forks=true        # bám fork
```

### F4. Làm việc trên bản sao (an toàn)
```bash
cp ./chall ./chall_patched
r2 -w -A ./chall_patched        # patch bản sao, giữ gốc để đối chiếu
```

---

## G. Mẫu `.gdbinit` — dán vào thư mục chall rồi `gdb ./chall`

```gdb
# .gdbinit — cấu hình chống anti-debug cho CTF (đặt cùng thư mục chall)
set pagination off
set confirm off

# --- fork/clone: bám con, giữ cả hai ---
set follow-fork-mode child
set detach-on-fork off
set schedule-multiple on

# --- tín hiệu: trả lại cho handler của chall, không dừng gdb ---
handle SIGTRAP nostop pass noprint
handle SIGSEGV nostop pass noprint
handle SIGILL  nostop pass noprint
handle SIGFPE  nostop pass noprint

# --- môi trường: gỡ biến tố giác ---
unset environment LINES
unset environment COLUMNS

# --- ptrace self-attach: ép mọi lần trả 0 (entry/return xen kẽ) ---
set $_ad_in = 0
catch syscall ptrace
commands
  silent
  if $_ad_in == 0
    set $_ad_in = 1
  else
    set $_ad_in = 0
    set $rax = 0
  end
  continue
end

# --- (tuỳ chọn) bật LD_PRELOAD giả ptrace nếu đã build fake_ptrace.so ---
# set environment LD_PRELOAD ./fake_ptrace.so

echo [.gdbinit] da nap cau hinh anti-debug. Go 'run' de bat dau.\n
```

> **Lưu ý bảo mật gdb:** mặc định gdb không tự nạp `.gdbinit` trong thư mục làm
> việc (tính năng *auto-load safe-path*). Cho phép bằng một trong hai cách:
> - thêm vào `~/.config/gdb/gdbinit` (hoặc `~/.gdbinit`):
>   `add-auto-load-safe-path /duong/dan/thu-muc-chall`
> - hoặc nạp thủ công: `gdb -x ./.gdbinit ./chall`

---

## H. Checklist khi "chạy mãi vẫn bị bắt"

1. Đã `strace`/`ltrace` để biết **chính xác** check nào nổ chưa? (đừng đoán)
2. ptrace gọi **qua libc** hay **syscall trực tiếp**? (quyết định LD_PRELOAD vs patch)
3. Có **nhiều** lời gọi ptrace không? (`axt sym.imp.ptrace` — phải xử lý hết)
4. Kết quả check có **dùng để giải mã** không? (nếu có: trả đúng 0, đừng NOP mù)
5. Có **checksum code** không? (nếu có: ưu tiên gdb runtime / emulate, tránh patch tĩnh)
6. Có **SIGTRAP/int3** handler giải mã không? (`handle SIGTRAP pass`, đừng NOP int3)
7. `.so` LD_PRELOAD đặt trên **fs Linux gốc** chưa? (mnt/9p có thể bị bỏ qua)
