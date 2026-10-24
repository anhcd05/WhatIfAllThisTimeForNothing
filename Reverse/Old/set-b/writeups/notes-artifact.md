# notes-artifact

- **Category:** Forensic
- **File đề:** không còn trong repo. ⚠️ README trong repo **rỗng** — không có lời giải sẵn; nội dung dưới đây là định hướng phân tích tĩnh theo SOLUTIONS_VN.md.

## Tóm tắt đề

Repo không kèm mô tả. Tên bài "Notes" gợi ý một **artifact của ứng dụng ghi chú** (Windows Sticky Notes, OneNote, hoặc dữ liệu chứa ghi chú ẩn). Flag nhiều khả năng nằm trong nội dung ghi chú đã xóa/ẩn hoặc trong cấu trúc lưu trữ của ứng dụng.

## Phân tích (chi tiết)

Forensic về "notes" thường xoay quanh các artifact lưu ghi chú của người dùng:

- **Windows Sticky Notes (cũ):** file `StickyNotes.snt` tại `%AppData%\Microsoft\Sticky Notes\` — thực chất là một **OLE Compound File** (magic `D0 CF 11 E0`), chứa các stream RTF/text của từng note.
- **Sticky Notes (mới, UWP):** CSDL **SQLite** `plum.sqlite` tại `%LocalAppData%\Packages\Microsoft.MicrosoftStickyNotes_*\LocalState\` — bảng `Note` lưu nội dung (kể cả note đã "xóa" vẫn còn trong WAL/freelist).
- **OneNote:** file `.one`/`.onetoc2` định dạng riêng, dùng `one-extract`/`strings`.

Hướng chung: xác định loại artifact → mở đúng cách → đọc nội dung ghi chú, chú ý dữ liệu đã xóa còn sót trong SQLite (freelist, WAL) hoặc stream ẩn trong Compound File.

Vì README rỗng và không có file, không thể khẳng định flag.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **`file` + magic bytes** để nhận loại artifact. *Vì sao:* `.snt` là OLE, Sticky Notes mới là SQLite — cách mở khác nhau.
2. **`sqlite3` / `strings` / carve WAL + freelist.** *Vì sao:* ghi chú đã xóa thường vẫn nằm trong trang tự do của SQLite.
3. **`7z`/`olefile` cho Compound File.** *Vì sao:* tách các stream RTF/text trong `StickyNotes.snt`.

## Lời giải chi tiết (bước + code/lệnh sạch)

```bash
file note_artifact.*                         # xác định loại

# Nếu là SQLite (Sticky Notes mới):
sqlite3 plum.sqlite ".tables"
sqlite3 plum.sqlite "SELECT Text FROM Note;"
strings -n 6 plum.sqlite | grep -i flag       # vét cả note đã xóa trong freelist/WAL
strings -n 6 plum.sqlite-wal | grep -i flag

# Nếu là OLE Compound (.snt):
7z x StickyNotes.snt -oout                     # tách stream
strings -n 6 out/* | grep -i flag
# hoặc Python: python3 -c "import olefile; ..."  đọc từng stream RTF
```

## Flag

flag{...}  *(nguồn không nêu — README repo rỗng, không có file đề; SOLUTIONS_VN.md không ghi flag cho bài này.)*

## Gặp lại thì xử lý thế nào (playbook)

1. "Notes" → nghĩ artifact ứng dụng ghi chú: Sticky Notes (`.snt` OLE **hoặc** `plum.sqlite`), OneNote, Notepad++ backup (`%AppData%\Notepad++\backup`).
2. `file` xác định loại; OLE → `7z`/`olefile`, SQLite → `sqlite3`.
3. **Luôn vét dữ liệu đã xóa:** `strings` trên file SQLite và file `-wal`/`-shm`; dùng `sqlite3 .recover` hoặc công cụ carve freelist.
4. Note cũng có thể ẩn trong registry (`HKCU\...\Notepad`), clipboard history, hoặc `ConsoleHost_history.txt` của PowerShell.
5. `grep -i flag` nhưng cũng tìm chuỗi Base64/hex khả nghi nếu flag bị mã hóa.
