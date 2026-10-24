# startup-artifact

- **Category:** Forensic
- **File đề:** không còn trong repo. ⚠️ README trong repo **rỗng** — không có lời giải sẵn; nội dung dưới đây là định hướng phân tích tĩnh theo SOLUTIONS_VN.md.

## Tóm tắt đề

Repo không kèm mô tả. Tên bài gốc "Starting" gợi ý **startup/autorun** — các cơ chế tự chạy khi khởi động Windows (Run key, Startup folder, Scheduled Task, Service, `.lnk`), hoặc "điểm khởi đầu" của một chuỗi điều tra forensic. Flag nhiều khả năng nằm trong một **persistence artifact** mà kẻ tấn công cài để tự chạy.

## Phân tích (chi tiết)

Các vị trí **autostart (ASEP)** cần soi khi điều tra:

- **Registry Run/RunOnce:** `HKLM\...\CurrentVersion\Run`, `HKCU\...\Run`, `RunOnce`, `Winlogon\Shell/Userinit`.
- **Startup folder:** `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup` (thường chứa `.lnk`).
- **Scheduled Tasks:** `C:\Windows\System32\Tasks\*` (XML) + registry `...\Schedule\TaskCache`.
- **Services:** `HKLM\SYSTEM\CurrentControlSet\Services`.
- **WMI event subscription, `.lnk` arguments, startup script GPO.**

Artifact đề có thể là: một hive registry (`NTUSER.DAT`, `SOFTWARE`, `SYSTEM`), một file `.lnk`, một XML scheduled task, hoặc output của công cụ như **Autoruns** (`autorunsc`). Flag thường là **đường dẫn/tham số lệnh** của mục autostart độc hại, hoặc chuỗi ẩn trong đó.

Vì README rỗng và không có file, không thể khẳng định flag.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **Phân tích hive registry (RegRipper / `reglookup` / python-registry).** *Vì sao:* phần lớn persistence ghi vào registry Run/Services.
2. **Đọc `.lnk` (lnkinfo / LECmd).** *Vì sao:* shortcut trong Startup chứa target + arguments (có thể là lệnh ẩn/flag).
3. **Parse Scheduled Task XML.** *Vì sao:* task chứa `<Command>`/`<Arguments>` tự chạy.
4. **`strings`/`grep` toàn artifact.** *Vì sao:* bắt nhanh chuỗi flag/Base64 khả nghi.

## Lời giải chi tiết (bước + code/lệnh sạch)

```bash
file startup_artifact.*                       # xác định loại artifact

# Nếu là hive registry:
rip.pl -r NTUSER.DAT -p user_run               # RegRipper plugin các Run key
reglookup NTUSER.DAT | grep -i -E 'Run|Startup'

# Nếu là .lnk:
lnkinfo shortcut.lnk                            # target + arguments

# Nếu là Scheduled Task XML:
grep -i -E 'Command|Arguments' Tasks/*.xml

# Vét chung:
strings -n 6 startup_artifact.* | grep -i -E 'flag|http|powershell|cmd'
```

## Flag

flag{...}  *(nguồn không nêu — README repo rỗng, không có file đề; SOLUTIONS_VN.md không ghi flag cho bài này.)*

## Gặp lại thì xử lý thế nào (playbook)

1. "Startup/Starting/autorun/persistence" → rà hết các **ASEP**: Run/RunOnce, Startup folder, Scheduled Tasks, Services, Winlogon, WMI.
2. Dùng công cụ chuyên: **RegRipper** (hive), **LECmd/lnkinfo** (`.lnk`), parse XML task; hoặc đọc output **Autoruns/autorunsc**.
3. Flag thường là **command line / path / argument** của mục tự chạy; chú ý lệnh PowerShell `-EncodedCommand`, URL tải payload.
4. `strings`/`grep` toàn bộ để bắt nhanh; giải tiếp nếu chuỗi bị Base64/hex.
5. Tham khảo MITRE ATT&CK T1547 (Boot or Logon Autostart Execution), T1053 (Scheduled Task).
