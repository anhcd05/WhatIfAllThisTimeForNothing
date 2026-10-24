# GUIDE — Bypass Anti-Debug trên Windows (CTF Reverse / Malware Analysis)

> **Mục đích:** Phục vụ phân tích / giải đề Reverse Engineering & Malware Analysis (Cyber SEA Game 2026). Đây là tài liệu phòng thủ/phân tích — KHÔNG phải để tạo malware. Mọi kỹ thuật dưới đây là để *vô hiệu hoá các lớp chống-gỡ-lỗi* trong binary mục tiêu, giúp ta đọc được logic thật của chương trình.
>
> **Môi trường:** Windows host (gỡ lỗi), Kali VM (phụ trợ). Công cụ chính: **x64dbg + plugin ScyllaHide**, **Frida**, và vá tĩnh bằng x64dbg / HxD / IDA.

---

## 0. Khái niệm nền tảng (đọc trước)

### 0.1 PEB (Process Environment Block)
PEB là cấu trúc của mỗi tiến trình, chứa nhiều cờ bị thay đổi khi có debugger. Lấy con trỏ PEB:

| Kiến trúc | Lấy PEB |
|---|---|
| x86 | `mov eax, fs:[0x30]` |
| x64 | `mov rax, gs:[0x60]` |

Các offset quan trọng trong PEB (theo Microsoft `winternl.h` và ntdoc.m417z.com/peb):

| Trường | x86 | x64 | WOW64 | Giá trị "sạch" |
|---|---|---|---|---|
| `BeingDebugged` (BYTE) | PEB+0x02 | PEB+0x02 | PEB+0x1002 | `0` |
| `NtGlobalFlag` (DWORD) | PEB+0x68 | PEB+0xBC | PEB+0x10BC | `0` |
| `ProcessHeap` (con trỏ) | PEB+0x18 | PEB+0x30 | PEB+0x1030 | — |

### 0.2 Hai chiến lược bypass tổng quát
1. **Sửa runtime (nhanh, không ghi đĩa):** dùng x64dbg + ScyllaHide tự che, hoặc đặt breakpoint tại API/kiểm tra rồi sửa giá trị trả về / cờ ZF, hoặc Frida hook.
2. **Vá tĩnh (patch bền vững):** sửa byte trong file/bộ nhớ để nhánh kiểm tra luôn đi theo đường "không có debugger". Thường là: NOP (`0x90`) khối kiểm tra, hoặc lật điều kiện nhảy (`JZ`↔`JNZ`, hoặc ép thành `JMP`/NOP).

### 0.3 Mẹo x64dbg dùng suốt bài
- **Đặt breakpoint API:** cửa sổ Command gõ `bp IsDebuggerPresent`, `bp NtQueryInformationProcess`, `bp GetThreadContext`...
- **Sửa thanh ghi trả về:** sau khi hàm `ret`, kết quả nằm ở `EAX`/`RAX`. Click đúp để sửa về giá trị mong muốn.
- **Lật cờ nhảy:** dừng tại lệnh `test`/`cmp` ngay trước `jz/jnz`, double-click cờ `ZF` ở panel Registers để lật, hoặc sửa trực tiếp lệnh jump.
- **Vá byte:** chọn lệnh → `Space` (assemble) hoặc chuột phải → *Binary > Fill with NOPs*. Sau đó chuột phải → *Patches* (Ctrl+P) → *Patch file* để lưu ra .exe mới.
- **Tìm nhánh:** chuột phải trên dòng kiểm tra → *Toggle breakpoint*; dùng *Trace* nếu cần log.

### 0.4 ScyllaHide — cấu hình nên bật (xử lý ~80% chiêu phổ biến tự động)
Plugin cho x64dbg (menu *Plugins > ScyllaHide > Options*). Các tick nên bật:

- **PEB:** `BeingDebugged`, `NtGlobalFlag`, `HeapFlags` (che PEB.BeingDebugged, NtGlobalFlag, Heap Flags/ForceFlags).
- **Hooks (ntdll):** `NtQueryInformationProcess`, `NtSetInformationThread` (chặn `ThreadHideFromDebugger`), `NtQuerySystemInformation`, `NtQueryObject`, `NtClose` (chống crash do invalid handle), `NtSetDebugFilterState`, `NtYieldExecution`, `NtGetContextThread` / `NtSetContextThread` (debug registers), `NtContinue`, `NtCreateThreadEx`.
- **kernel32/user32:** `OutputDebugStringA`, `BlockInput`, `FindWindow` series.
- **GetTickCount / timing:** bật nhóm timing nếu đề dùng (xem mục 4).
- **Misc:** `Protect DRx` (bảo vệ hardware breakpoint của chính debugger), `Remove debug privileges`, `preventThreadCreation` (tuỳ đề).

> **Quy trình chuẩn:** mở target trong x64dbg → bật ScyllaHide profile `x64dbg` với các tick trên → chạy. Nếu vẫn bị phát hiện → tìm kỹ thuật cụ thể bên dưới và xử lý thủ công.

---

## 1. Nhóm PEB & Debug Flags

### 1.1 `PEB.BeingDebugged` (offset 0x02)
**Phát hiện:** Đọc byte `fs:[30h]+2` (x86) / `gs:[60h]+2` (x64). Khác 0 ⇒ có debugger. `IsDebuggerPresent()` chỉ là wrapper đọc byte này.

**Bypass:**
- *ScyllaHide:* tick `BeingDebugged` → tự set 0.
- *x64dbg runtime:* cửa sổ Command: `SetBeingDebugged 0` hoặc mở Memory map tới PEB, sửa byte offset 2 về `00`.
  - Nhanh hơn: lệnh `bp IsDebuggerPresent` rồi xem mục 2.1.
- *Vá tĩnh:* nếu code tự đọc PEB, tìm chuỗi đọc `movzx eax, byte ptr [... +2]` theo sau là `test/jnz` → lật nhánh.

### 1.2 `NtGlobalFlag` (offset 0x68 x86 / 0xBC x64, mask 0x70)
**Phát hiện:** Khi tiến trình được **khởi chạy bởi debugger**, 3 cờ heap được bật: `FLG_HEAP_ENABLE_TAIL_CHECK (0x10)` | `FLG_HEAP_ENABLE_FREE_CHECK (0x20)` | `FLG_HEAP_VALIDATE_PARAMETERS (0x40)` = **0x70**. Code kiểm tra `(NtGlobalFlag & 0x70) == 0x70`.
> Lưu ý: *attach* vào tiến trình đang chạy KHÔNG set 3 cờ này — nên nếu được, hãy attach thay vì launch.

**Bypass:**
- *ScyllaHide:* tick `NtGlobalFlag`.
- *x64dbg runtime:* sửa DWORD tại PEB+0x68 (x86)/+0xBC (x64) về `0`.
- *Vá tĩnh:* tìm đọc `[peb+0xBC]` + `and ...,0x70` / `cmp ...,0x70` → NOP hoặc lật jump.

### 1.3 Heap Flags — `Flags` & `ForceFlags`
**Phát hiện:** Đọc từ heap base (lấy qua `ProcessHeap` ở PEB). Offset theo nền tảng:

| Nền tảng | Flags | ForceFlags |
|---|---|---|
| x86, Vista+ | heap+0x40 | heap+0x44 |
| x86, pre-Vista | heap+0x0C | heap+0x10 |
| x64, Vista+ | heap+0x70 | heap+0x74 |
| x64, pre-Vista | heap+0x14 | heap+0x18 |

Giá trị "sạch": `Flags = 0x2` (HEAP_GROWABLE), `ForceFlags = 0`. Có debugger ⇒ `Flags` thêm bit (0x20/0x40/0x40000000...), `ForceFlags != 0`.

**Bypass:**
- *ScyllaHide:* tick `HeapFlags`/`ProtectProcessId` nhóm heap.
- *x64dbg runtime:* lấy ProcessHeap (PEB+0x30 x64), tới heap base, set `Flags=0x2`, `ForceFlags=0`.
- *Vá tĩnh:* lật nhánh so sánh.

### 1.4 `IsDebuggerPresent` (kernel32) — xem mục 2.1
### 1.5 `RtlQueryProcessHeapInformation` / `RtlQueryProcessDebugInformation`
**Phát hiện:** đọc `Heaps[0].Flags`; bất kỳ bit nào ngoài `HEAP_GROWABLE (0x2)` ⇒ debugger.
**Bypass:** ScyllaHide hook; hoặc Frida hook trả về Flags=0x2.

### 1.6 `NtQuerySystemInformation(SystemKernelDebuggerInformation = 0x23)`
**Phát hiện:** trả 2 byte `DebuggerEnabled`(AL)/`DebuggerNotPresent`(AH). Kernel debugger hiện diện khi Enabled set & NotPresent clear.
**Bypass:** ScyllaHide `NtQuerySystemInformation`; hoặc hook trả `DebuggerEnabled=0, DebuggerNotPresent=1`.

---

## 2. Nhóm API trực tiếp

### 2.1 `IsDebuggerPresent()`
**Phát hiện:** trả về `PEB.BeingDebugged`. Pattern điển hình: `call IsDebuggerPresent` → `test eax,eax` → `jnz debugger_found`.

**Bypass (3 cách, chọn 1):**
1. *ScyllaHide:* tick `BeingDebugged` (vì hàm đọc PEB).
2. *x64dbg runtime:* `bp IsDebuggerPresent` → F9 tới khi dừng → `Ctrl+F9` (execute till return) → sửa `EAX = 0` → F8 ra. Hoặc lật `ZF` tại `test eax,eax`.
3. *Vá tĩnh:* vá chính nhánh gọi. Ví dụ minh hoạ:
   ```
   00401050  FF15 xxxxxxxx   call IsDebuggerPresent
   00401056  85 C0            test eax, eax
   00401058  75 20            jnz  00401078   ; nhảy khi bị gỡ lỗi
   ```
   Vá `75 20` (JNZ) → `90 90` (2x NOP) hoặc `EB 00`? Không — tốt nhất NOP 2 byte để rơi xuống nhánh "sạch". Hoặc ép `EAX=0` bằng cách thay `call` + `test` thành `xor eax,eax; nop...`.

### 2.2 `CheckRemoteDebuggerPresent()`
**Phát hiện:** gọi nội bộ `NtQueryInformationProcess(ProcessDebugPort)`. Tham số thứ 2 là con trỏ `BOOL` được set TRUE nếu bị gỡ lỗi.
**Bypass:** hook `NtQueryInformationProcess` (xem 2.3) — ScyllaHide xử lý. Runtime: `Ctrl+F9` sau call, sửa giá trị `*pbDebuggerPresent = 0` (đối số thứ 2), hoặc lật nhánh sau đó.

### 2.3 `NtQueryInformationProcess()` (ntdll) — rất hay gặp
3 information class chính:

| Class | Giá trị | Khi bị gỡ lỗi | Giá trị spoof |
|---|---|---|---|
| `ProcessDebugPort` | 0x07 | trả `-1` (0xFFFFFFFF) | đặt `0` |
| `ProcessDebugFlags` | 0x1F | trả `0` | đặt khác 0 (vd `1`) |
| `ProcessDebugObjectHandle` | 0x1E | trả handle != 0 | đặt `0` |

**Bypass:**
- *ScyllaHide:* tick `NtQueryInformationProcess` → tự spoof cả 3 class.
- *x64dbg runtime:* `bp NtQueryInformationProcess`. Khi dừng, xem đối số thứ 2 (`ProcessInformationClass`): x64 = `RDX`, x86 = `[esp+8]`. Nếu là `7/0x1E/0x1F`, `Ctrl+F9` ra khỏi hàm rồi sửa buffer đầu ra (`ProcessInformation`, đối số 3: x64 `R8`, x86 `[esp+0xC]`) về giá trị spoof ở bảng.
- *Frida:* xem `bypass_antidebug_frida.js` (hàm `onLeave` chỉnh buffer).

### 2.4 `OutputDebugString()` (trick GetLastError, pre-Vista) / `DbgPrint`
**Phát hiện:**
- Pre-Vista: gọi `OutputDebugStringA` sau khi set `SetLastError(x)`; nếu KHÔNG có debugger, LastError bị đổi; nếu có debugger, LastError giữ nguyên → suy ra có gỡ lỗi (logic đảo tuỳ biến thể).
- Biến thể `DbgPrint`/`OutputDebugString` ném exception `DBG_PRINTEXCEPTION_C (0x40010006)`: debugger "nuốt" exception ⇒ handler riêng không chạy ⇒ coi là bị gỡ lỗi.
**Bypass:** ScyllaHide `OutputDebugStringA`; hoặc trong x64dbg bật *Options > Exceptions*: để debugger **chuyển (pass) exception** `0x40010006` về cho chương trình (add vào ignore list). Hoặc NOP call.

### 2.5 `FindWindow` / `EnumWindows` — xem mục 7 (Interactive)

---

## 3. Nhóm Object Handles

### 3.1 `CloseHandle` / `NtClose` với handle không hợp lệ
**Phát hiện:** gọi `CloseHandle(0xDEADBEEF)` trong `__try/__except`. Bình thường chỉ fail; **khi bị gỡ lỗi** ném `EXCEPTION_INVALID_HANDLE (0xC0000008)`, handler bắt được ⇒ kết luận có debugger.
**Bypass:** ScyllaHide tick `NtClose` (quan trọng, cũng chống crash). x64dbg: *Options > Exceptions* cho pass `0xC0000008`. Hoặc NOP nhánh.

### 3.2 `NtQueryObject` — đếm `DebugObject`
**Phát hiện:** `NtQueryObject(ObjectAllTypesInformation)` liệt kê mọi loại object hệ thống; nếu loại "DebugObject" có count > 0 ⇒ (từng) có debugger trên máy. *Lưu ý: chỉ cho biết hệ thống đã dùng debugger kể từ khi boot, không chắc tiến trình hiện tại bị gỡ.*
**Bypass:** ScyllaHide `NtQueryObject` (xoá entry DebugObject); hoặc hook trả count=0; hoặc patch nhánh.

### 3.3 `OpenProcess` trên csrss.exe
**Phát hiện:** lấy PID csrss qua `CsrGetProcessId` rồi `OpenProcess` full-access; thành công ⇒ tiến trình có quyền debug (admin) ⇒ nghi có debugger.
**Bypass:** hook `OpenProcess` trả NULL khi target là csrss; hoặc chạy không bằng quyền admin; hoặc patch nhánh.

### 3.4 `CreateFile` mở độc quyền chính file exe / `LoadLibrary`
**Phát hiện:** mở file exe của chính mình với share=0. Debugger giữ handle (từ create-process event) ⇒ mở độc quyền thất bại ⇒ có debugger. Biến thể `LoadLibraryA("calc.exe")` rồi thử mở độc quyền.
**Bypass:** patch nhánh fail, hoặc lật `ZF` sau call `CreateFileW`. (Hook `NtCreateFile` quá rộng, dễ hỏng; ưu tiên patch.)

---

## 4. Nhóm Timing (đo thời gian)

**Nguyên lý chung:** đọc timer → chạy đoạn code → đọc timer lần 2 → nếu `delta` lớn bất thường ⇒ nghi đang bị single-step/breakpoint. Các nguồn timer:

| Hàm/instruction | Ghi chú |
|---|---|
| `RDTSC` | đọc timestamp counter; so 2 lần đọc |
| `GetTickCount` / `GetTickCount64` | độ phân giải ms |
| `QueryPerformanceCounter` | độ phân giải cao |
| `GetLocalTime` / `GetSystemTime` | đổi sang FILETIME rồi trừ |
| `timeGetTime` (winmm) | ms |

**Bypass:**
- *ScyllaHide:* bật nhóm timing (`GetTickCount`, `GetTickCount64`, `QueryPerformanceCounter`, `GetLocalTime`, `GetSystemTime`, `timeGetTime`) — ScyllaHide làm cho thời gian "trôi" ít đi giữa 2 lần đọc.
- *Với `RDTSC`:* ScyllaHide không phải lúc nào cũng che được RDTSC thuần (nó là lệnh CPU). Cách xử lý:
  1. **Đừng single-step qua vùng đo** — đặt breakpoint SAU đoạn đo rồi F9 chạy thẳng (giảm overhead).
  2. Đặt breakpoint tại lệnh `rdtsc` thứ 2, sửa `EDX:EAX` cho sát giá trị lần đọc đầu (delta nhỏ).
  3. *Vá tĩnh:* NOP cả khối so sánh `delta > threshold`, hoặc lật nhánh `ja/jg debugger_found`.
- *Nguyên tắc vàng:* timing check "không đáng tin" (chính CheckPoint nói vậy) → thường chỉ cần patch nhánh so sánh ngưỡng là xong.

Ví dụ x64dbg (RDTSC):
```
rdtsc              ; lần 1 -> EDX:EAX
mov  esi, eax
... code ...
rdtsc              ; lần 2
sub  eax, esi
cmp  eax, 0xFFFF   ; ngưỡng
ja   debugger_found   ; <-- lật thành NOP/JMP hoặc đặt bp sau đoạn này
```

---

## 5. Nhóm Exception / CPU instruction

### 5.1 `INT3` (0xCC; dạng dài `CD 03`)
**Phát hiện:** `INT3` ném `EXCEPTION_BREAKPOINT`. Không debugger ⇒ handler riêng của chương trình bắt được (đi nhánh "sạch"). Có debugger ⇒ debugger "nuốt" exception trước ⇒ handler không chạy.
**Bypass:** x64dbg *Options > Exceptions*: thêm `EXCEPTION_BREAKPOINT (0x80000003)` vào danh sách **pass to program** (không để debugger giữ). Hoặc NOP lệnh `INT3`. (Dạng dài: địa chỉ exception rơi vào byte `03`, handler cần chỉnh EIP.)

### 5.2 `INT 2D`
**Phát hiện:** cũng ném `EXCEPTION_BREAKPOINT` nhưng Windows dùng EIP làm địa chỉ exception rồi **tăng EIP**; nếu EAX ∈ {1,3,4 (và 5 trên Vista+)} thì bỏ thêm 1 byte. Một số debugger xử lý sai ⇒ resume vào lệnh hỏng/lộ diện.
**Bypass:** đặt NOP ngay sau `INT 2D` để "hấp thụ" byte bị skip; cho pass exception; hoặc NOP toàn khối.

### 5.3 `ICEBP` / `INT1` (0xF1)
**Phát hiện:** opcode không chính thức, bình thường ném `EXCEPTION_SINGLE_STEP (0x80000004)`. Dưới tracer, debugger coi như single-step thường ⇒ bỏ qua handler ⇒ chạy tiếp qua byte đó (lộ).
**Bypass:** cho pass `0x80000004` về chương trình; hoặc NOP.

### 5.4 Trap Flag / single-step (`PUSHF`/`POPF`, `push ss;pop ss;pushf`)
**Phát hiện:** set bit TF (0x100) trong EFLAGS lưu lại rồi `popf` + `nop`. Không debugger ⇒ phát sinh SINGLE_STEP exception. Debugger thường **xoá TF** sau mỗi event ⇒ không có exception ⇒ lộ. Biến thể `push ss; pop ss; pushf`: single-step qua chuỗi này để bit TF còn trong bản EFLAGS đã lưu (test bit 0x100).
**Bypass:** đừng single-step qua đoạn này — đặt breakpoint sau đó và F9 chạy thẳng. Hoặc NOP khối, hoặc cho pass SINGLE_STEP.

### 5.5 `UnhandledExceptionFilter` / `SetUnhandledExceptionFilter`
**Phát hiện:** cài filter top-level riêng rồi `int 3`. Không debugger ⇒ filter chạy, chỉnh EIP vượt qua `CC EB xx` (đi nhánh "không bị gỡ"). Có debugger ⇒ filter không được gọi, exception về debugger (lộ).
**Bypass:** NOP khối kiểm tra; hoặc cho pass `EXCEPTION_BREAKPOINT`; hoặc viết plugin chỉnh cách debugger xử lý event.

### 5.6 `RaiseException(DBG_CONTROL_C / DBG_PRINTEXCEPTION_C)` — xem 2.4

### 5.7 SEH / VEH chain (che luồng, không trực tiếp phát hiện)
Mỗi `int 3` chuyền control sang handler kế tiếp tới khi tới payload. **Bypass:** trace tay theo chuỗi handler tới payload (đặt bp tại từng handler), hoặc dùng cửa sổ *SEH* trong x64dbg.

### 5.8 Selectors / segment registers khi single-step
**Phát hiện:** single-step làm đổi giá trị DS/SS/FS/GS; code nạp giá trị vào segment reg và kiểm tra có giữ nguyên không.
**Bypass:** tránh single-step; đặt breakpoint phần mềm và F9.

---

## 6. Nhóm Hardware — Debug Registers (Dr0–Dr7)

### 6.1 `GetThreadContext` kiểm tra Dr0–Dr3 / Dr7
**Phát hiện:** zero `CONTEXT`, set `ContextFlags = CONTEXT_DEBUG_REGISTERS (0x00010010)`, gọi `GetThreadContext(GetCurrentThread(), &ctx)`; nếu `Dr0|Dr1|Dr2|Dr3 != 0` ⇒ có **hardware breakpoint** (tức debugger). `Dr7` chứa bit điều khiển bật/tắt từng breakpoint.

**Bypass:**
- *ScyllaHide:* tick `NtGetContextThread`/`NtSetContextThread` + `Protect DRx` → trả Dr0–Dr7 = 0 và bảo vệ HWBP của debugger.
- *Tránh dùng hardware breakpoint:* dùng software breakpoint (F2 trong x64dbg) thay vì hardware breakpoint để không để lại dấu ở Dr0–Dr3.
- *x64dbg runtime:* `bp GetThreadContext` → `Ctrl+F9` → trong CONTEXT (con trỏ ở đối số 2: x64 `RDX`, x86 `[esp+8]`) zero các trường Dr0..Dr7.
- *Vá tĩnh:* lật nhánh so sánh Dr != 0.

### 6.2 Offset Dr trong CONTEXT (x64)
Dr0=`Ctx+0x48`, Dr1=`+0x50`, Dr2=`+0x58`, Dr3=`+0x60`, Dr6=`+0x68`, Dr7=`+0x70` (tham khảo khi sửa tay). Trên x86 các trường Dr0..Dr7 nằm đầu `_CONTEXT` (offset 0x04..0x18).

---

## 7. Nhóm Interactive / Window / Process

### 7.1 `FindWindow` / `FindWindowEx` theo class name
**Phát hiện:** tìm class name debugger: `OLLYDBG`, `WinDbgFrameClass`, `ID` (IDA), `Qt5QWindowIcon`/`__x64dbg` tuỳ build... Handle != NULL ⇒ có debugger.
**Bypass:** ScyllaHide/Frida hook `NtUserFindWindowEx` trả 0; hoặc đổi tiêu đề cửa sổ debugger; hoặc patch nhánh.

### 7.2 `EnumWindows` + kiểm tra title ("dbg"/"debugger") + `SuspendThread`
**Phát hiện:** duyệt cửa sổ top-level, tìm title chứa "dbg"/"debugger", có thể `SuspendThread` luồng cha.
**Bypass:** hook `NtUserBuildHwndList` lọc output; hook `SuspendThread`; hoặc NOP.

### 7.3 Parent process (phải là explorer.exe)
**Phát hiện:** tiến trình chạy bình thường có cha là explorer.exe. Cha khác (vd x64dbg.exe) ⇒ nghi bị launch bởi debugger. Hai cách: (a) `NtQueryInformationProcess(ProcessBasicInformation)` so với PID shell; (b) `CreateToolhelp32Snapshot` + `Process32First/Next`.
**Bypass:** ScyllaHide hook `NtQuerySystemInformation` (các class liệt kê process) đổi tên process khả nghi; **mẹo mạnh nhất: attach vào tiến trình đang chạy thay vì launch** (lúc đó cha vẫn là explorer); hoặc patch nhánh.

### 7.4 Enumerate process tìm tên debugger (x64dbg/ollydbg/ida/x32dbg/windbg)
**Phát hiện:** duyệt process list so tên với blacklist.
**Bypass:** đổi tên file debugger (vd `x64dbg.exe` → `calc_analyzer.exe`); hook snapshot API ẩn tên; hoặc patch.

### 7.5 `BlockInput`, `SwitchDesktop`, `GenerateConsoleCtrlEvent`
Chủ yếu để *quấy rối* người phân tích hơn là phát hiện. **Bypass:** ScyllaHide `BlockInput`; hook `SwitchDesktop`; hook `GenerateConsoleCtrlEvent`.

---

## 8. Nhóm Khác (Misc / nâng cao)

### 8.1 TLS Callbacks
**Vấn đề:** code chống-gỡ chạy **trước** entry point (trong TLS callback), nên breakpoint ở OEP là quá muộn.
**Bypass:** x64dbg *Options > Events*: tick **"TLS Callbacks"** để debugger dừng ở từng TLS callback. Hoặc dùng *Entry Breakpoint* + *System Breakpoint* để bắt sớm; xem list TLS callback trong tab *Memory map > PE sections* / IDA (segment `.tls`).

### 8.2 `NtSetInformationThread(ThreadHideFromDebugger = 0x11)`
**Phát hiện/quấy rối:** ẩn luồng khỏi debugger ⇒ debugger không nhận event của luồng đó ⇒ breakpoint trong luồng có thể làm treo/crash.
**Bypass:** ScyllaHide tick `NtSetInformationThread` (chặn class 0x11) — bắt buộc bật. Hoặc hook trả về mà không thực thi.

### 8.3 Self-debugging (`DebugActiveProcess`)
**Phát hiện:** tiến trình tự spawn bản sao để attach vào chính nó qua `DebugActiveProcess`; nếu attach fail ⇒ đã có debugger khác giữ ⇒ lộ.
**Bypass:** ScyllaHide/hook `DebugActiveProcess`/`NtDebugActiveProcess`/`DbgUiDebugActiveProcess` trả thành công giả; hoặc NOP.

### 8.4 Patch `ntdll!DbgBreakPoint` / `DbgUiRemoteBreakin` (chống attach)
**Phát hiện/chống:** ghi `C3` (RET) vào `DbgBreakPoint`, hoặc thay `DbgUiRemoteBreakin` bằng stub `TerminateProcess` ⇒ debugger không attach được / tiến trình tự chết khi bị attach.
**Bypass:** đặt breakpoint sớm (launch thay vì attach), hoặc khôi phục byte gốc của 2 hàm này trong ntdll trước khi chúng bị patch (bp tại hàm patch), hoặc dùng attach kiểu khác (kernel debugger).

### 8.5 Software breakpoint scan (quét 0xCC) & Code checksum (CRC32)
**Phát hiện:** chương trình tự quét thân hàm tìm byte `0xCC` (dấu software breakpoint) hoặc tính CRC32 định kỳ để phát hiện byte bị sửa (breakpoint, inline hook, patch).
**Bypass:** dùng **hardware breakpoint** (Dr0–Dr3) thay software BP để không để lại `0xCC` — *trừ khi* đề đồng thời check debug registers (mục 6), lúc đó phải cân nhắc. Hoặc tìm & NOP vòng lặp quét/tính checksum. Hoặc đặt BP tại nơi đọc kết quả checksum và sửa cho khớp.

### 8.6 `NtYieldExecution` / `SwitchToThread`, `GetWriteWatch`, Instruction counting
Các kỹ thuật phụ, độ tin cậy thấp. **Bypass chung:** ScyllaHide (`NtYieldExecution`), hoặc NOP khối kiểm tra ngưỡng/đếm.

---

## 9. Chiến lược tổng quát — quy trình xử lý một binary CTF

1. **Trinh sát tĩnh (IDA / strings):** tìm import khả nghi: `IsDebuggerPresent`, `NtQueryInformationProcess`, `CheckRemoteDebuggerPresent`, `GetThreadContext`, `OutputDebugString`, `FindWindow`, `rdtsc`, `int 3`, segment `.tls`. Đánh dấu các nhánh kiểm tra.
2. **Bật ScyllaHide** với profile đầy đủ (mục 0.4) rồi chạy trong x64dbg. Xử lý được phần lớn PEB/API/handle/thread.
3. **Chọn attach thay vì launch** khi có thể (né NtGlobalFlag, Heap flags, parent-process).
4. **Nếu vẫn bị phát hiện:** khoanh vùng — chạy tới điểm chương trình "biết có debugger" (thường ngay trước khi exit/đổi luồng), xem backtrace, tìm hàm/nhánh kiểm tra cụ thể, đối chiếu mục 1–8.
5. **Vá tại nhánh quyết định** là cách chắc chắn nhất: lật `JZ/JNZ`, NOP khối, hoặc ép `EAX=0`. Lưu patch ra .exe (Ctrl+P) để lần sau khỏi làm lại.
6. **Timing/RDTSC & exception-based:** ưu tiên đặt breakpoint SAU vùng nhạy cảm và F9 chạy thẳng (tránh single-step); cấu hình *Options > Exceptions* để pass đúng exception về chương trình.
7. **TLS / anti-attach:** bật dừng ở TLS callback; với anti-attach thì launch-under-debugger và bp sớm.
8. **Khi debugger quá "ồn":** chuyển sang **Frida** (hook mức API, không để lại dấu software BP) — xem `bypass_antidebug_frida.js`. Hoặc kết hợp cả hai.

### Bảng tra nhanh "kỹ thuật → cách xử lý nhanh nhất"
| Kỹ thuật | Cách nhanh nhất |
|---|---|
| BeingDebugged / IsDebuggerPresent | ScyllaHide `BeingDebugged` |
| NtGlobalFlag / Heap flags | ScyllaHide heap; hoặc attach |
| NtQueryInformationProcess | ScyllaHide; Frida onLeave |
| CloseHandle invalid / NtClose | ScyllaHide `NtClose` + pass 0xC0000008 |
| GetThreadContext (Dr0-3) | dùng software BP; ScyllaHide `Protect DRx` |
| RDTSC/timing | bp sau vùng đo + F9; NOP so sánh ngưỡng |
| INT3/INT2D/ICEBP/TF | Options>Exceptions pass; tránh single-step |
| FindWindow/EnumWindows | ScyllaHide/Frida; đổi tên debugger |
| Parent process | attach thay vì launch |
| TLS callback | Options>Events: TLS Callbacks |
| ThreadHideFromDebugger | ScyllaHide `NtSetInformationThread` |
| Self/anti-attach | hook DebugActiveProcess; khôi phục DbgBreakPoint |

---

## 10. Nguồn tham khảo
- CheckPoint Anti-Debug catalog — https://anti-debug.checkpoint.com/ (Debug Flags, Assembly, Timing, Exceptions, Object Handles, Process Memory, Interactive, Misc)
- Unprotect Project — https://unprotect.it/techniques/ và https://unprotect.it/technique/ntglobalflag/
- Microsoft PEB — https://learn.microsoft.com/windows/win32/api/winternl/ns-winternl-peb
- ntdoc PEB (offset chi tiết) — https://ntdoc.m417z.com/peb
- AntiDebug Workshop (Windows) — https://hackmd.io/tJkMd4QZS_-8fjYVcP94eA
- ScyllaHide — https://github.com/x64dbg/ScyllaHide

> **Ghi chú công cụ:** ScyllaHide tích hợp sẵn trong bản x64dbg mới (Plugins). Cập nhật ScyllaHide để hỗ trợ Windows build mới. Frida: `pip install frida-tools`.
