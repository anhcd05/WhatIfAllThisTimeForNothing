# quarantine-vsbx

- **Category:** Reversing (phân tích mã độc)
- **File đề:** `challenge.bin` — file bị **cách ly (quarantine)** bởi phần mềm anti-malware, không có trên đĩa repo (nằm trên môi trường thi). Không phải PE/ELF nên **không disassembly được**; phân tích tập trung vào định dạng quarantine + bóc obfuscation PHP.

## Tóm tắt đề
Một file khả nghi bị cách ly từ một web server bị tấn công, giao dưới tên `challenge.bin`. Server đã bị biến thành **redirector** dẫn nạn nhân tới các site EC (thương mại điện tử) giả mạo — chiến dịch **"Japanese Keyword Hack" / Blackhat SEO**. File đã bị AV mã hóa khi cách ly; phải giải mã container → thu được PHP → bóc nhiều lớp obfuscation → lấy flag ở cuối script.

**Luật đề:** KHÔNG dùng dịch vụ online (UnPHP/VirusTotal) vì làm lộ nội dung đề ra công khai (bị phạt); chỉ dùng offline (CyberChef desktop, `php -a`). Đây là malware thật → làm trong sandbox.

## Phân tích (chi tiết: định dạng/khóa/lớp obfuscation)
1. **Nhận diện container cách ly.** `xxd challenge.bin | head` → đọc **4 byte magic đầu** → tra ra định dạng **VSBX** (quarantine của Trend Micro). VSBX về bản chất là một biến đổi/XOR đơn giản để "vô hiệu" file (tránh vô tình chạy) nhưng vẫn giữ để điều tra.
   - *Hướng sai:* `file challenge.bin`, đổi đuôi `.zip`/`.gz` → đều thất bại vì đây là định dạng AV độc quyền, không phải archive chuẩn.
2. **Giải mã quarantine bằng DeXRAY.pl** (Hexacorn) — tool offline chuyên decode quarantine của nhiều AV (RC4/Blowfish/XOR...). Cần Perl modules: `Crypt::RC4`, `Digest::CRC`, `Crypt::Blowfish`, `Archive::Zip`, `OLE::Storage_Lite`.
   - Output: `challenge.bin.00000096_TREND2.out` = một **file PHP**.
3. **PHP obfuscate nhiều lớp** (webshell/SEO malware điển hình):
   1. **Tên biến gây rối** chỉ gồm `O o 0 _` (nhìn gần giống nhau).
   2. **Bảng thay thế (substitution table)** đặt trong `urldecode()` để ánh xạ ký tự.
   3. **`strtr()` + `substr()`** đổi/cắt chuỗi theo bảng.
   4. **`base64_decode()` biến thể** — alphabet tùy biến: **hoán vị dải 0–51 ↔ 52–104** của bảng Base64 chuẩn.
   5. **`eval()`** thực thi chuỗi payload cuối.
4. Bóc hết các lớp → ở **cuối script** xuất hiện decoder + chuỗi flag.

Mẫu một lớp điển hình:
```php
$O0O = "urldecode"; $Oo0 = $O0O("%73%75%62%73%74%72");             // "substr"
$o0O = $O0O("%62%61%73%65%36%34%5f%64%65%63%6f%64%65");             // "base64_decode"
$key = "nkT3...";                                                   // alphabet biến thể
eval( $o0O( strtr($payload, $key, $std_b64) ) );                    // lớp eval cuối
```

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Nhận diện magic → chọn đúng decoder (DeXRAY cho VSBX):** VÌ SAO: file không đọc/chạy trực tiếp được; phải khôi phục payload gốc trước, và container AV cần đúng thuật toán giải (DeXRAY tự nhận dạng).
- **Bóc obfuscation offline bằng `php -a`, thay `eval(` → `echo(`:** VÌ SAO: in ra lớp kế mà **không chạy** payload độc (không gọi mạng/C2), bóc lần lượt an toàn, đúng luật đề.
- **Dựng lại Base64 alphabet biến thể trước khi decode:** VÌ SAO: dùng bảng chuẩn sẽ ra rác; phải phát hiện hoán vị 0–51 ↔ 52–104 và ánh xạ về Base64 chuẩn — bước quyết định.

## Lời giải chi tiết (bước + lệnh sạch)
```bash
# 1) nhận diện + giải quarantine
xxd challenge.bin | head                 # 4 byte đầu -> VSBX (Trend Micro)
cpan Crypt::RC4 Digest::CRC Crypt::Blowfish Archive::Zip OLE::Storage_Lite
perl DeXRAY.pl challenge.bin             # -> challenge.bin.00000096_TREND2.out (PHP)

# 2) bóc obfuscation offline: in layer kế thay vì thực thi
php -r '$s=file_get_contents("stage0.php"); $s=str_replace("eval(","echo(",$s); eval("?>".$s);' > stage1.php
# lặp: urldecode-table -> strtr/substr -> base64(custom) -> eval
php -r 'echo base64_decode(strtr($x, $custom_alphabet, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"));'
```
Sau 4–5 lần lặp, payload cuối là redirector + chuỗi flag ở cuối file.

## Flag
flag{Euclids_Elements}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** file "quarantine" từ AV (magic lạ như VSBX); payload PHP obfuscate bằng `O o 0 _`; nhiều lớp `base64_decode/strtr/substr/eval`.
- **Quy trình:** (1) xác định container qua magic → chọn decoder (DeXRAY); (2) giải quarantine lấy payload; (3) khử obfuscation theo lớp: bảng substitution → base64 biến thể → theo `eval` tới payload cuối; (4) đọc đuôi file.
- **Công cụ:** DeXRAY.pl (+ Perl modules), CyberChef desktop, `php -a`.
- **Bẫy:** KHÔNG upload dịch vụ online (luật phạt + lộ đề); base64 biến thể ra rác nếu dùng bảng chuẩn; chép nhầm `0`↔`O`; AV có thể báo động khi bung (malware thật) → sandbox; thiếu Perl module gây lỗi khó hiểu.
