# Tuyển tập Challenge — Set A — Bản tóm tắt (cheatsheet)

> Bản rút gọn 1 dòng/bài. Chi tiết đầy đủ (8 mục/bài, có script + hash + đính chính) xem **`SOLUTIONS_VN.md`**.
> Gồm **37 bài** / 8 mảng. File đề nằm trong `ctf/`.

## Bảng flag

| # | Bài | Category | Phương pháp (1 dòng) | Flag |
|--:|---|---|---|---|
| 1 | Turning Grille trong DOCX | Crypto | docx=zip → đảo bit (Cipher=jpg) + XOR (filter=png) → lưới Fleissner | `flag{FleissnerGrill}` |
| 2 | Periodic-Decimal Vigenère | Crypto | Vigenère, khóa = chữ số tuần hoàn của 1/17 | ⚠️ không tái tạo sạch |
| 3 | Small-Prime RSA | Crypto | p,q 12-bit → brute cặp nguyên tố <4096; p=1429,q=1531 | `a world safe to exchange digital information` ✅ |
| 4 | Memory Secret Hunt | Forensic | memory dump → 3 mảnh base64 client_secret → nối+decode | *(server)* |
| 5 | TLS Keylog Recovery | Forensic | Volatility dump Chrome → TLS keylog → LFI/log poisoning → apt privesc | *(server /root/flag.txt)* |
| 6 | XOR Backup Recovery | Forensic | git restore cryptor.py; khóa=f(timestamp,arg)=202410100338/SetA → XOR | *(server)* |
| 7 | Anagram Author ID | MISC | giải anagram → đoạn mở đầu Peter Rabbit | `Helen Beatrix Potter` |
| 8 | Chatbot Prompt Injection | MISC | prompt injection + nhập số chia hết 3 + xin "từng phần" | `flag{S3cr3t_Gu4rdi4n}` |
| 9 | SHA-256 File Match | MISC | SHA-256 100 file → file60/62/79 → nối base64 | `flag{h4sh_browns_with_onions_4_bre4kf4st}` ✅ |
| 10 | Spot the CVE (PHP-CGI) | Network | php-cgi arg injection (auto_prepend_file=php://input) | `CVE-2012-1823` |
| 11 | Time-based Blind SQLi | Network | time-based blind SQLi, dùng timing gói (sleep 5s=TRUE) | `flag{https://youtu.be/wE11GYxsE7M}` ✅ |
| 12 | ICMP Covert Channel | Network | base64 trong ICMP payload, `.`=delimiter, decode từng run | `flag{IC3B3RG_IS_JUS7_TH3_T1P}` ✅ |
| 13 | Mail-Zip | Network | email: zip(base64)+pass(base64) → unzip | `flag{!7 w4$ 34$y j06 w4$n'7 !7??}` ✅ |
| 14 | To the "future" - 1 | Network | Mirai: lọc gói scan (seq==dst IP) → gói C2 đầu | `flag{143.93.131.169:23:75240531}` |
| 15 | To the "future" - 2 | Network | giả bot Mirai, parse lệnh DDoS → DNS flood | `flag{2:53:60}` |
| 16 | Multiply compressed file | OSINT | 3 zip lồng (Fukaya-City/NEWoMan-SHINJUKU/Tokyo-Tower) → lnk → Wayback → base64 | *(base64 trên Wayback)* |
| 17 | Reverse-Image Restaurant | OSINT | Google Lens ảnh món ăn → tabelog restaurant code | `flag{13249397}` |
| 18 | Social-Media Alias OSINT | OSINT | PDF redaction giả → email → EPIEOS Skype → pivot alias → domain | `flag{hiropi1991tanapon@gmail.com:enj0y555crypt0:h00r@y-g00d-j0b.com}` |
| 19 | Flight-Tracking OSINT | OSINT | ADS-B Exchange: reg OE-IOI, lùi 2h → Hungary | `flag{OE-IOI:Hungary}` |
| 20 | Password Crackme | Reversing | debugger đọc so sánh mật khẩu = `5117-023` | `flag{criminal_evidence_brought_to_LIGHT}` |
| 21 | Combat bogus EC - 1 | Reversing | VSBX → DeXRAY → giải obfuscate PHP (O/o/0/_) → eval | `flag{Euclids_Elements}` |
| 22 | Combat bogus EC - 2 | Rev/Web | gọi C2 service.myshop.local lấy sitemap → /200095etidm62z.htm | `flag{H4ck3dCMS}` |
| 23 | SEH Crackme | Reversing | SEH chia-0 + IsDebuggerPresent; ghép mảnh chuỗi | ⚠️ ZIP ZipCrypto, không bẻ được |
| 24 | Game Win-Counter Patch | Reversing | patch `2C 01 00 00`→`01 00 00 00` (300→1) | `flag{rock_crushes_scissors_water_erodes_rocks}` |
| 25 | LSB to QR Code | Stego | LSB → 625 bit → ma trận 25×25 → QR | QR = `now you see me!!` ✅ |
| 26 | LSB-Half Fake PDF | Stego | pdf=png → LSB Half (StegOnline) | `flag{M4rker_f4iled}` |
| 27 | LSB Blue Channel | Stego | LSB blue = `B@NGK0K` → OpenStego extract | `flag{A_picture_is_worth_@_thousand_words}` |
| 28 | PNG IHDR/CRC Repair | Stego | LSB R+G="height 580" → sửa IHDR 555→580 + CRC 8cc4f996 | `flag{Broaden_your_horizons_to_find_the_FLAG!35}` |
| 29 | Whitespace Stego | Stego | OpenStego → song.txt → stegsnow (whitespace) | `flag{Hurray_clap_your_hands}` |
| 30 | Exfiltrate database | Web | MySQL SELECT ... INTO OUTFILE /var/www/html | `flag{MustC0nfigure-secure-file-priv}` |
| 31 | Exploit old windows | Web | upload.aspx webshell → PrintNightmare getsystem → ADS flag.txt:flag | *(server, ADS)* |
| 32 | Origin Behind CDN (SSRF) | Web | SSRF imgcdn.php?pic=base64(url) → ipinfo lộ origin | `flag{Claim_Abuse_to_Network_Admin}` |
| 33 | Concurrency Ticket Race | Web | async 19 request song song (aiohttp) | `flag{H4rdToGet0TameshiTick3t}` |
| 34 | Please find the flag | Web | cmd injection bypass (dùng `find` giữ `|`) → 4n5w3r.ini /etc | *(server)* |
| 35 | Flask SSTI Session Forgery | Web | SSTI {{config}} lộ SECRET_KEY → giả cookie time=future | *(server)* |
| 36 | Login Blind SQLi | Web | blind SQLi: len=29, SUBSTR dò từng ký tự | `flag{*-SQL-*}` |
| 37 | YARA Argument Injection | Web | argument injection option `-s` (shlex chặn cmd inj) | *(server)* |

**Phân bố**: Crypto 3 · Forensic 3 · MISC 3 · Network 6 · OSINT 4 · Reversing 5 · Stego 5 · Web 8 = **37**.

✅ = flag tự khôi phục/xác minh bằng phân tích tĩnh trong tài liệu này.
⚠️ = chưa giải được hoàn toàn (xem đính chính trong `SOLUTIONS_VN.md`).
