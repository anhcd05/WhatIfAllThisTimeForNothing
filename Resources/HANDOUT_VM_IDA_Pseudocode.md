# HANDOUT: Kết nối VM (VMware) và lấy pseudo-code từ IDA

Tài liệu ghi lại cách Claude Code (chạy trên máy host Windows) điều khiển 2 VM trong VMware Workstation và lấy pseudo-code của một file bằng IDA Free. Mọi thứ đã được chạy thử thành công ngày 2026-10-18.

> Lưu ý: tài khoản/mật khẩu dưới đây là của máy lab CTF, chỉ để dùng nội bộ. Không dùng cho máy thật.

---

## 1. Môi trường

| | Kali | FlareVM (Windows 10) |
|---|---|---|
| File `.vmx` | `E:\Kali\kali-linux-2026.2-vmware-amd64\kali-linux-2026.2-vmware-amd64.vmwarevm\kali-linux-2026.2-vmware-amd64.vmx` | `E:\VMs\FlareVM\FlareVM.vmx` |
| Mạng | NAT (VMnet8, `192.168.83.0/24`) | NAT (VMnet8) |
| IP (lúc test) | `192.168.83.139` | `192.168.83.144` |
| Tài khoản | `kali` / `kali` (có sudo) | `analyst` / `Analyst123!` (Administrator) |
| IDA | `~/ida-free-9.4/ida` (IDA Free 9.4, bản Linux) | `C:\Program Files\IDA Free 9.4\ida.exe` |
| Công cụ khác | `xdotool`, `import`, `java`, `python3` | Ghidra 12.1.2, x64dbg, nhiều tool trong `Desktop\Tools` |
| Màn hình guest | 1670x878 | 1670x878 |

- `vmrun` nằm ở `C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe` (hoặc `C:\Program Files\VMware\VMware Workstation\`).
- IP có thể đổi sau khi khởi động lại VM. Lấy IP hiện tại bằng `vmrun getGuestIPAddress <vmx> -wait`.
- SSH trên Kali và WinRM/RDP trên Windows đều **không bật**. Toàn bộ điều khiển đi qua kênh `vmrun` + VMware Tools, không cần mở cổng nào.

### Kiểm tra nhanh

```powershell
$v = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
& $v list                                  # liệt kê VM đang chạy
& $v getGuestIPAddress '<vmx>' -wait       # IP của guest
& $v -T ws checkToolsState '<vmx>'         # phải là "running"
```

---

## 2. Kết nối và chạy lệnh trong guest bằng `vmrun`

`vmrun` **không trả stdout** của lệnh chạy trong guest. Mẫu chung là: **ghi kết quả ra file trong guest → copy file về host → đọc**.

```powershell
$v = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$k = '<vmx của Kali>';  $a = @('-T','ws','-gu','kali','-gp','kali')

# 1. đẩy script vào guest
& $v @a CopyFileFromHostToGuest $k .\probe.sh /tmp/probe.sh
# 2. chạy
& $v @a runScriptInGuest $k /bin/bash '/bin/bash /tmp/probe.sh'
# 3. lấy output về host
& $v @a CopyFileFromGuestToHost $k /tmp/probe.txt .\probe_out.txt
```

Với Windows dùng `runProgramInGuest`:

```powershell
$f = '<vmx của FlareVM>';  $a = @('-T','ws','-gu','analyst','-gp','Analyst123!')
& $v @a CopyFileFromHostToGuest $f .\probe.bat 'C:\Users\Public\probe.bat'
& $v @a runProgramInGuest $f 'C:\Users\Public\probe.bat'
& $v @a CopyFileFromGuestToHost $f 'C:\Users\Public\out.txt' .\out.txt
```

### Những lỗi hay gặp

| Triệu chứng | Nguyên nhân và cách xử lý |
|---|---|
| `Error: Unrecognized command: ...vmx` | PowerShell nuốt tham số mật khẩu rỗng `-gp ""`. Gán mật khẩu thật cho tài khoản, đừng dùng mật khẩu rỗng. |
| `The guest OS does not support empty passwords` | Tài khoản Windows chưa có mật khẩu. Đặt trong guest: `net user analyst <mật khẩu>`. Sửa `LimitBlankPasswordUse` **không** giải quyết được. |
| `Guest program exited with non-zero exit code: 1` khi chạy `cmd /c "a & b"` | PowerShell làm hỏng dấu nháy của đối số. Viết lệnh vào file `.bat`/`.ps1`, copy vào guest rồi chạy file đó. |
| Script `.sh` trên Kali không chạy | File phải dùng line ending LF, không phải CRLF. Ghi file bằng `-replace "`r`n","`n"` và `-NoNewline`. |
| Lệnh quét dài (ví dụ `Get-ChildItem C:\ -Recurse`) bị timeout | Chạy nền hoặc giới hạn thư mục tìm. Đừng quét cả ổ đĩa, hãy hỏi vị trí cài tool trước. |

### Tạo mật khẩu/đặt quyền cho Windows (làm một lần, trong console VM)

```powershell
net user analyst Analyst123!
# (tuỳ chọn) nếu từng nới chính sách mật khẩu rỗng thì trả lại:
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LimitBlankPasswordUse -Value 1
```

---

## 3. Lấy pseudo-code bằng IDA

### 3.1. Thực tế về IDA Free

- Bản IDA Free **không có** `idat/idat64` (chạy dòng lệnh), **không có IDAPython**. Không viết script headless được.
- Decompiler là **Hex-Rays cloud** (`hexcx64`): cần internet, chạy qua GUI. Không bắt đăng nhập trong lần test này.
- Vì vậy cách làm là **điều khiển GUI IDA từ xa**: gửi chuột/phím vào màn hình guest, rồi dùng `vmrun captureScreen` để chụp màn hình và đọc kết quả.
- Muốn headless thật sự (`idat -A -S...`, `ida-pro-mcp`, `idalib`) thì cần IDA Pro/Home có giấy phép. Không vá hay bẻ bản Free.

### 3.2. Quy tắc quan trọng trước khi mở IDA

1. **Không mở IDA trực tiếp trên file mà IDA khác đang giữ.** Lần test đầu bị lỗi `Read error. The database is corrupted beyond repair` vì database `chall.id0/.id1/...` trong `~/Downloads` đang bị một IDA khác mở.
2. **Luôn copy file sang thư mục riêng rồi mở bản copy**, ví dụ `/tmp/ida_work/chall` (Kali) hoặc `C:\Users\Public\ida_work\chall9.exe` (Windows).
3. Kiểm tra `ps`/`listProcessesInGuest` xem có IDA nào đang chạy chưa. Chỉ tắt tiến trình **của mình**, trừ khi chủ máy cho phép tắt hết.
4. Đối chiếu hash (`sha256sum`) giữa bản gốc và bản copy.

### 3.3. Quy trình chung (cả hai VM)

1. Copy file vào thư mục riêng.
2. Mở IDA với file đó.
3. Xác nhận hộp thoại Load file (OK). Với PE, chọn `No` cho hộp thoại PDB.
4. Đợi auto-analysis xong (dòng `The initial autoanalysis has been finished.` ở Output).
5. Nhảy tới `main` (với PE đã thấy sẵn `main`). Với ELF stripped IDA vẫn nhận ra `main` qua `__libc_start_main`.
6. Gọi decompiler bằng menu **`View → Open subviews → Generate pseudocode`**.
7. Chụp màn hình bằng `captureScreen` để đọc pseudo-code. Có thể xuất ra file bằng `File → Produce file → Create C file…`.

> Ghi chú: phím tắt `F5` gửi bằng `xdotool`/`SendKeys` **không có tác dụng** trong lần test. Gọi qua menu thì chạy được. Nguyên nhân chưa xác định.

---

## 4. Kali: điều khiển IDA bằng `xdotool`

Màn hình Kali là X11 `:0`, session của user `kali`. Mọi lệnh GUI phải đặt hai biến môi trường:

```bash
export DISPLAY=:0 XAUTHORITY=/home/kali/.Xauthority
```

### 4.1. Mở khoá màn hình nếu bị khoá

Màn hình có thể tự khoá khi VM nhàn rỗi (hiện hộp thoại "Unlock" của `kali`). Cần được chủ máy đồng ý trước khi nhập mật khẩu.

```bash
xdotool key Escape; sleep 1
xdotool type --delay 80 'kali'
xdotool key --clearmodifiers KP_Enter      # "Return" bình thường có thể không nhận
```

### 4.2. Mở IDA trên bản copy

```bash
mkdir -p /tmp/ida_work && cp ~/Downloads/chall /tmp/ida_work/chall
cd /tmp/ida_work
setsid nohup ~/ida-free-9.4/ida /tmp/ida_work/chall > /tmp/ida2.log 2>&1 < /dev/null &
```

### 4.3. Xác nhận load, nhảy `main`, gọi decompiler

Hộp thoại Load file nhận phím Enter bình thường:

```bash
xdotool key --clearmodifiers Return                 # OK ở hộp thoại Load
sleep 15                                            # đợi auto-analysis
xdotool key --clearmodifiers g; sleep 2             # Jump to address
xdotool type --delay 80 'main'; sleep 1
xdotool key --clearmodifiers Return
```

Gọi decompiler bằng chuột (toạ độ cho màn hình 1670x878):

```bash
xdotool mousemove 940 300 click 1; sleep 1          # focus vào IDA View
xdotool mousemove 203 74  click 1; sleep 1          # menu View
xdotool mousemove 258 96  click 1; sleep 1          # Open subviews
xdotool mousemove 662 208 click 1                   # Generate pseudocode
```

### 4.4. Chụp màn hình (chạy trên host)

```powershell
& $v @a captureScreen $k "$PWD\shot.png"
```

---

## 5. FlareVM (Windows): điều khiển IDA bằng PowerShell và `user32`

Trên Windows không có `xdotool`. Cách dùng: chạy script PowerShell **trong session tương tác** của `analyst`, dùng `SetCursorPos` và `mouse_event` để click.

> Chạy script bằng `-interactive` nhưng **không** dùng `-activeWindow`. Cờ `-activeWindow` làm cửa sổ PowerShell chiếm focus của IDA. Phím gửi bằng `SendKeys` không tới được IDA, nên chỉ dùng click chuột.

### 5.1. Mở IDA trên bản copy

```powershell
# fl_launch.ps1 (chạy trong guest)
New-Item -ItemType Directory -Force C:\Users\Public\ida_work | Out-Null
Copy-Item 'C:\Users\analyst\Downloads\<file>.exe' 'C:\Users\Public\ida_work\chall9.exe' -Force
Start-Process 'C:\Program Files\IDA Free 9.4\ida.exe' -ArgumentList '"C:\Users\Public\ida_work\chall9.exe"'
```

```powershell
& $v @a runProgramInGuest $f -noWait -interactive `
    'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
    -NoProfile -ExecutionPolicy Bypass -File 'C:\Users\Public\fl_launch.ps1'
```

### 5.2. Script click chuột (mẫu)

```powershell
Add-Type @"
using System; using System.Runtime.InteropServices;
public class W { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
 [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint dx,uint dy,uint d,UIntPtr e); }
"@
[void][W]::SetProcessDPIAware()
function Click($x,$y,$wait=1200){
  [W]::SetCursorPos($x,$y); Start-Sleep -Milliseconds 300
  [W]::mouse_event(2,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 100
  [W]::mouse_event(4,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds $wait }
```

### 5.3. Chuỗi click (màn hình 1670x878)

| Bước | Toạ độ | Ghi chú |
|---|---|---|
| OK ở hộp thoại **Load a new file** | `733, 740` | PE AMD64, metapc |
| **No** ở hộp thoại **Load PDB file** | `874, 527` | PDB là đường dẫn của máy tác giả, không cần tra cứu |
| Tab **IDA View-A** | `470, 170` | quay lại tab disassembly |
| Focus vào disassembly | `900, 458` | |
| Menu **View** | `235, 42` | |
| **Open subviews** | `300, 74` | |
| **Generate pseudocode** | `734, 172` | đợi khoảng 6 giây |

Toàn bộ chuỗi chạy trong **một** script (menu sẽ đóng nếu tách thành nhiều lần chạy):

```powershell
Click 470 170
Click 900 458
Click 235 42
Click 300 74
Click 734 172 6000
```

### 5.4. Chụp màn hình

```powershell
& $v @a captureScreen $f "$PWD\fl_shot.png"
```

---

## 6. Kết quả tham chiếu (đã chạy thử)

**Kali, `chall` (ELF64 PIE, stripped, 14472 byte, sha256 `512d252c...3fba92`):**

```c
// main @ 0x1209
v6 = &unk_2004;                       // key 4 byte
stream = fopen("flag.png", "rb");
s      = fopen("encrypted", "wb");
v5 = 0;
while ( fread(&ptr, 1, 1, stream) == 1 ) {
    ptr ^= v6[v5 % 4];
    ptr += 19;
    fwrite(&ptr, 1, 1, s);
    ++v5;
}
```

Bản chép đầy đủ: `chall_main_pseudocode.c` (cùng thư mục).

**FlareVM, `chall9 (1).exe` (PE x64, 11776 byte):**

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[256];
  memset(v4, 0, sizeof(v4));
  sub_1400012E0("Input : ");          // printf
  sub_140001340("%256s", v4);         // scanf
  if ( (unsigned int)sub_140001000(v4) != 0 ) puts("Correct");
  else puts("Wrong");
  return 0;
}
```

---

## 7. Lưu ý an toàn và dọn dẹp

- Hai VM là máy lab. Đừng để lộ mật khẩu ngoài phạm vi nhóm.
- Script/output tạm nằm ở `/tmp/*` (Kali) và `C:\Users\Public\` (Windows). Xoá khi xong việc.
- Sau khi xong, đóng IDA đã mở trên bản copy. Các file database `*.id0/.id1/.id2/.nam/.til` còn sót trong `~/Downloads` (Kali) và `Downloads\` (Windows) là rác của IDA, có thể xoá khi không còn IDA nào giữ.
- Trả `LimitBlankPasswordUse` về `1` nếu đã đổi (xem mục 2).
- Tôi chỉ tắt tiến trình IDA do chính mình mở, trừ khi chủ máy cho phép tắt hết (đã được phép trong phiên làm việc này).

---

## 8. Lấy pseudo-code hàng loạt (đã dùng cho ~260 hàm của bộ `notes/`)

IDA Free 9.4 **không có** `File → Produce file → Create C file` (chỉ có MAP/ASM/LST/HTML/EXE/DIF/header/IDC), nên không xuất cả file một lần được. Quy trình thay thế cho **từng hàm**:

1. `g` (Jump) → gõ tên hàm → đợi ~2,5 giây (hộp thoại Jump tìm kiếm bất đồng bộ) → `Enter`.
2. Menu `View → Open subviews → Generate pseudocode` (phím `F5` gửi giả không chạy).
3. Click vào cửa sổ pseudocode → `Ctrl+A`, `Ctrl+C`.
4. Đọc clipboard: Kali `xclip -o -selection clipboard`; Windows `[Windows.Forms.Clipboard]::GetText()` trong PowerShell `-STA`.
5. Kiểm tra **3 dòng đầu có đúng tên hàm** rồi mới nhận; nếu không thì chờ và copy lại (tối đa 5 lần).

Script nằm trong `notes/code/tools/` (`ida_batch.sh` + `ida_all.sh` cho Kali, `ida_batch_win.ps1` + `win_all.ps1` cho Windows, `win_step.ps1` để chạy từng bước kèm chụp màn hình). Tốc độ: ~16 giây/hàm (Kali), ~20 giây/hàm (Windows).

### Bẫy đã gặp (đều đã xử lý trong script)

| Triệu chứng | Nguyên nhân | Cách xử lý |
|---|---|---|
| Phím bị gõ vào **IDA khác** của người dùng (Windows) | IDA của mình kẹt sau hộp thoại (PDB) nên cửa sổ phía trước là IDA khác | Trước **mỗi** phím: kiểm tra PID cửa sổ foreground = PID IDA do mình mở; trước **mỗi** click: PID cửa sổ dưới con trỏ cũng phải khớp; sai thì dừng. Chỉ tắt tiến trình IDA do mình mở (lọc theo đường dẫn thư mục làm việc) |
| `SetForegroundWindow` không đưa cửa sổ lên | Windows chặn tiến trình nền | `Microsoft.VisualBasic.Interaction::AppActivate(<PID>)` + thu nhỏ/khôi phục cửa sổ, rồi vẫn xác minh PID |
| `Enter`/`SendKeys` không tới hộp thoại | Cửa sổ PowerShell của chính script chiếm focus | Chạy `vmrun -interactive` **không** kèm `-activeWindow`; dùng click chuột + AppActivate |
| Hàm đầu tiên sau khi nạp bị lỗi, các phím thành hotkey (`a`, `d`… hiện "Directly convert to data?") | IDA còn bận (file `mingw -static` lớn) nên phím `g` bị bỏ qua | Đợi lâu hơn trước hàm đầu; có vòng thử lại; nếu lỡ thì bấm `No` rồi làm lại (chỉ ảnh hưởng bản copy) |
| Nhảy tới `b64_encode+97` hoặc hàm khác | Jump nhận kết quả đầu tiên ở danh sách khi kết quả chưa cập nhật; tên `main` khớp nhiều mục | Đợi 2,5 giây sau khi gõ; kiểm tra dòng đầu của pseudo-code |
| `j_<tên>` (thunk) làm Jump mơ hồ | MSVC link incremental | Build với `/link /INCREMENTAL:NO` |
| File chứa ký tự lạ ở đầu | PowerShell 5.1 `Set-Content -Encoding utf8` thêm BOM | Đọc bằng `utf-8-sig` khi ghép ghi chú |
| `Error: Cannot open VM: ...\algos.c` | Trong PowerShell, `$f` và `$F` là **cùng một biến** (không phân biệt hoa/thường): vòng `foreach ($f ...)` ghi đè đường dẫn `.vmx` | Đừng đặt tên biến lặp trùng biến cấu hình |
| Màn hình Kali tự khoá giữa chừng | Khoá khi nhàn rỗi | `xset s off; xset -dpms` (chỉ phiên hiện tại); mở khoá bằng `KP_Enter` hoặc click nút Unlock |

Quy tắc đã giữ: **không mở trực tiếp file mà IDA khác đang giữ** (copy sang `/tmp/ida_work` hoặc `C:\Users\Public\ida_work2`); mọi file thí nghiệm chỉ build/chạy trong VM.

## 9. capa trên FlareVM

`C:\Tools\capa\capa.exe -q <file>` (capa 9.4.0, có sẵn luật nhúng, không cần Internet). Mất ~4 phút cho binary ~400 KB. Kết quả trên 6 binary thí nghiệm nằm trong `notes/00-nhan-dien-nhanh.md`.

## 10. Kiểm tra bộ ghi chú

```
python code/tools/check_notes.py .        # trong thư mục notes: liên kết, khối Python, khối C
python code/test_decoders.py code/algos_ground_truth.txt
gcc -O2 -Wall -Wextra -fsanitize=address,undefined -o t code/test_ctfdec.c && ./t
```

## 11. Bản strip + ảnh chụp màn hình pseudo-code (đã làm cho 3 build)

**Tạo binary strip** (xem `notes/code/build_*.sh|bat`): gcc `strip -s`, mingw `x86_64-w64-mingw32-strip -s`, MSVC build **không** `/Zi`/`/DEBUG` (kèm `/MAP` để lấy địa chỉ hàm). Output của cả ba vẫn khớp `ref.py`. Địa chỉ hàm lấy từ bản chưa strip (`nm`) hoặc file `.map`; IDA đặt tên hàm strip là `sub_<địa chỉ viết hoa>` (`sub_2ED0`, `sub_140005C80`) nên Jump bằng **tên** đó.

**Bài học khi chụp ảnh tự động**
- Hộp thoại `Jump` (phím `g`) của IDA 9 là ô *tìm kiếm*: nhập `0x2ed0` không nhảy tới địa chỉ; mục menu "Jump to address…" bị khoá. Dùng tên `sub_2ED0`.
- Bố cục chụp: đóng 3 dock (Output, Functions, Graph overview) bằng click vào nút ✕ để cửa sổ pseudo-code rộng hết cỡ: Kali 48 dòng/trang, Windows 29 dòng/trang.
- Sau `Ctrl+A`/`Ctrl+C` view nhảy xuống cuối hàm: phải `Ctrl+Home` rồi mới chụp; `PageDown` cuộn đúng một trang, không chồng lấn; số trang = `ceil(số dòng / dòng mỗi trang)`.
- Mỗi lần "Generate pseudocode" mở thêm tab (`Pseudocode-A`, `-B`…) và làm lệch tọa độ: luôn đóng tab sau mỗi hàm; nếu một lần đóng trượt thì các hàm sau bị "kẹt" ở hàm cũ. Script có bước reset ở đầu mỗi hàm và kiểm tra dòng đầu của text.
- Ảnh được cắt trên host theo bề rộng/ chiều cao nội dung thật (bỏ đường viền xám ở đầu vùng nội dung gây tính sai bề rộng).
- Lệnh `Stop`/dừng script chạy nền: dừng đúng tác vụ nền theo ID, đừng giết tiến trình theo tên.

Script: `notes/code/tools/shots_kali.ps1`, `shots_win.ps1`, `recrop.ps1`, `s_gen.sh`, `s_page.sh`, `s_close.sh`. Kết quả: `notes/images/<build>_strip/<hàm>_pN.png` (301 ảnh) và `notes/pseudocode/<build>_strip/<hàm>.c`.
