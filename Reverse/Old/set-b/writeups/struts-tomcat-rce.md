# struts-tomcat-rce

- **Category:** MISC (phân loại trong set là Web — bài khai thác dịch vụ)
- **File đề:** `struts-tomcat-rce/README.md` (chỉ mô tả, không có binary). Mục tiêu là một **dịch vụ live**; flag xuất hiện khi chạy exploit trên server.

## Tóm tắt đề

Gợi ý từ tên bài: "well-known vulnerability" — lỗ hổng nổi tiếng, có **exploit công khai**. Trinh sát thấy máy chủ chạy **Apache Tomcat 7.0.96** (lộ ở trang 404/Not Found). Theo README gốc: tìm được lỗ hổng **Struts2**, chạy lệnh tùy ý trên target và lấy flag.

## Phân tích (chi tiết)

Các khung Java/Tomcat có nhiều RCE nổi tiếng. README gốc chỉ đích danh **Struts2** — chuỗi lỗ hổng **OGNL injection** cho phép thực thi lệnh qua header/tham số:

- **S2-045 (CVE-2017-5638):** OGNL injection qua header `Content-Type` (Jakarta Multipart parser) — PoC public rất nhiều, dễ khai thác nhất.
- **S2-046, S2-048, S2-057 (CVE-2018-11776):** các biến thể OGNL khác qua `Content-Disposition`, action mapping/namespace.

Ngoài Struts2, Tomcat còn có các RCE khác cần loại trừ khi gặp banner Tomcat:

- **CVE-2017-12617 (PUT JSP):** khi `readonly=false`, upload JSP bằng `PUT` rồi gọi để RCE.
- **Ghostcat (CVE-2020-1938):** đọc/đưa file qua AJP (cổng 8009).

Quy trình chung: xác định đúng **component + phiên bản** → tìm PoC public khớp → thực thi lệnh đọc flag trên server. Banner `Apache Tomcat/7.0.96` + gợi ý "well-known" + hướng Struts2 từ README ⇒ dùng PoC Struts2 OGNL.

Vì đây là bài khai thác dịch vụ live (server CTF đã gỡ), writeup gốc **không ghi lại giá trị flag**.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **Fingerprint version qua trang lỗi 404.** *Vì sao:* Tomcat in version ở trang Not Found → biết chính xác để chọn CVE.
2. **Struts2 OGNL RCE (S2-045/057).** *Vì sao:* README chỉ đích danh Struts2; OGNL injection cho RCE trực tiếp, PoC sẵn có.
3. **Dùng PoC public (struts-pwn / Metasploit).** *Vì sao:* "well-known vulnerability" ⇒ không cần tự viết exploit.
4. **Phân tích tĩnh phía ta, không chạy binary nội bộ.** *Vì sao:* không có file đề; mọi thao tác là request mạng tới service (nên làm trong lab được phép).

## Lời giải chi tiết (bước + code/lệnh sạch)

```bash
# 1) Xác nhận version
curl -s http://TARGET/khong-ton-tai | grep -i "Apache Tomcat"   # -> Apache Tomcat/7.0.96

# 2) Dò endpoint Struts (.action/.do)
#    tìm trang xử lý form/action của ứng dụng

# 3) Khai thác S2-045 (OGNL qua Content-Type) để chạy lệnh:
python struts-pwn.py --url "http://TARGET/<endpoint>.action" -c "id"
python struts-pwn.py --url "http://TARGET/<endpoint>.action" -c "cat /path/to/flag"

#    hoặc Metasploit:
#    use exploit/multi/http/struts2_content_type_ognl
#    set RHOSTS TARGET ; set TARGETURI /<endpoint> ; run

# 4) Đọc flag từ output lệnh (ls để tìm file flag trước nếu cần)
```

## Flag

flag{...}  *(nguồn không nêu — writeup gốc không ghi flag vì flag xuất hiện runtime trên server live đã gỡ; SOLUTIONS_VN.md xác nhận không có giá trị flag.)*

## Gặp lại thì xử lý thế nào (playbook)

1. "Well-known vulnerability" + banner dịch vụ → **fingerprint version** (trang 404, header `Server`, `/manager`), rồi tra CVE tương ứng.
2. Tomcat: phân biệt lỗ hổng **tầng ứng dụng** (Struts2 OGNL) vs **tầng Tomcat** (PUT JSP CVE-2017-12617, Ghostcat CVE-2020-1938) — cách khai thác khác hẳn.
3. Struts2: thử S2-045 (Content-Type OGNL) trước vì PoC phổ biến; nếu không trúng thử S2-057/048.
4. Dùng PoC public (`struts-pwn.py`, Metasploit) đúng version/endpoint; nhiều PoC kén payload nên thử vài biến thể.
5. Có RCE → `id`/`ls` định vị flag, rồi `cat`. Chỉ làm trên hệ thống được phép/lab CTF.
