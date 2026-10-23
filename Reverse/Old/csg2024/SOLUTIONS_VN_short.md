# Cyber SEA Game 2024 — Bản tóm tắt (cheatsheet)

> Bản rút gọn 1 dòng/bài. Chi tiết đầy đủ (8 mục/bài, có script + hash + đính chính) xem **`SOLUTIONS_VN.md`**.
> Nguồn: repo `cyberc0dex/ctf-csg2024` (`ctf/` = đề, `solution/` = writeup PDF). Tổng **37 bài** / 8 mảng.

## Bảng flag

| # | Bài | Category | Phương pháp (1 dòng) | Flag |
|--:|---|---|---|---|
| 1 | Can you extract hidden files? | Crypto | docx=zip → đảo bit (Cipher=jpg) + XOR (filter=png) → lưới Fleissner | `CSG_FLAG{FleissnerGrill}` |
| 2 | Simple Crypto | Crypto | Vigenère, khóa = chữ số tuần hoàn của 1/17 | ⚠️ không tái tạo sạch |
| 3 | Small RSA | Crypto | p,q 12-bit → brute cặp nguyên tố <4096; p=1429,q=1531 | `a world safe to exchange digital information` ✅ |
| 4 | Can you give us the secret | Forensic | memory dump → 3 mảnh base64 client_secret → nối+decode | *(server)* |
| 5 | Can you parse TLS traffic | Forensic | Volatility dump Chrome → TLS keylog → LFI/log poisoning → apt privesc | *(server /root/flag.txt)* |
| 6 | recovery | Forensic | git restore cryptor.py; khóa=f(timestamp,arg)=202410100338/CyberSeaGame → XOR | *(server)* |
| 7 | Author | MISC | giải anagram → đoạn mở đầu Peter Rabbit | `Helen Beatrix Potter` |
| 8 | Chatbot Deception | MISC | prompt injection + nhập số chia hết 3 + xin "từng phần" | `CSG_FLAG{S3cr3t_Gu4rdi4n}` |
| 9 | Hash | MISC | SHA-256 100 file → file60/62/79 → nối base64 | `CSG_FLAG{h4sh_browns_with_onions_4_bre4kf4st}` ✅ |
| 10 | Can you spot the CVE# | Network | php-cgi arg injection (auto_prepend_file=php://input) | `CVE-2012-1823` |
| 11 | Data Breach | Network | time-based blind SQLi, dùng timing gói (sleep 5s=TRUE) | `CSG_FLAG{https://youtu.be/wE11GYxsE7M}` ✅ |
| 12 | icmp | Network | base64 trong ICMP payload, `.`=delimiter, decode từng run | `CSG_FLAG{IC3B3RG_IS_JUS7_TH3_T1P}` ✅ |
| 13 | PPAP | Network | email: zip(base64)+pass(base64) → unzip | `CSG_FLAG{!7 w4$ 34$y j06 w4$n'7 !7??}` ✅ |
| 14 | To the "future" - 1 | Network | Mirai: lọc gói scan (seq==dst IP) → gói C2 đầu | `CSG_FLAG{143.93.131.169:23:75240531}` |
| 15 | To the "future" - 2 | Network | giả bot Mirai, parse lệnh DDoS → DNS flood | `CSG_FLAG{2:53:60}` |
| 16 | Multiply compressed file | OSINT | 3 zip lồng (Fukaya-City/NEWoMan-SHINJUKU/Tokyo-Tower) → lnk → Wayback → base64 | *(base64 trên Wayback)* |
| 17 | Ramen | OSINT | Google Lens ảnh món ăn → tabelog restaurant code | `CSG_FLAG{13249397}` |
| 18 | SNS investigation | OSINT | PDF redaction giả → email → EPIEOS Skype → pivot alias → domain | `CSG_FLAG{hiropi1991tanapon@gmail.com:enj0y555crypt0:h00r@y-g00d-j0b.com}` |
| 19 | Telegram Cofounder | OSINT | ADS-B Exchange: reg OE-IOI, lùi 2h → Hungary | `CSG_FLAG{OE-IOI:Hungary}` |
| 20 | Bad Tool | Reversing | debugger đọc so sánh mật khẩu = `5117-023` | `CSG_FLAG{criminal_evidence_brought_to_LIGHT}` |
| 21 | Combat bogus EC - 1 | Reversing | VSBX → DeXRAY → giải obfuscate PHP (O/o/0/_) → eval | `CSG_FLAG{Euclids_Elements}` |
| 22 | Combat bogus EC - 2 | Rev/Web | gọi C2 service.myshop.trend lấy sitemap → /200095etidm62z.htm | `CSG_FLAG{H4ck3dCMS}` |
| 23 | ReverseMe | Reversing | SEH chia-0 + IsDebuggerPresent; ghép mảnh chuỗi | ⚠️ ZIP ZipCrypto, không bẻ được |
| 24 | Rock Paper Scissors | Reversing | patch `2C 01 00 00`→`01 00 00 00` (300→1) | `CSG_FLAG{rock_crushes_scissors_water_erodes_rocks}` |
| 25 | LINE to PLAIN | Stego | LSB → 625 bit → ma trận 25×25 → QR | QR = `now you see me!!` ✅ |
| 26 | Marker | Stego | pdf=png → LSB Half (StegOnline) | `CSG_FLAG{M4rker_f4iled}` |
| 27 | steg1 | Stego | LSB blue = `B@NGK0K` → OpenStego extract | `CSG_FLAG{A_picture_is_worth_@_thousand_words}` |
| 28 | steg2 | Stego | LSB R+G="height 580" → sửa IHDR 555→580 + CRC 8cc4f996 | `CSG_FLAG{Broaden_your_horizons_to_find_the_FLAG!35}` |
| 29 | steg3 | Stego | OpenStego → song.txt → stegsnow (whitespace) | `CSG_FLAG{Hurray_clap_your_hands}` |
| 30 | Exfiltrate database | Web | MySQL SELECT ... INTO OUTFILE /var/www/html | `CSG_FLAG{MustC0nfigure-secure-file-priv}` |
| 31 | Exploit old windows | Web | upload.aspx webshell → PrintNightmare getsystem → ADS flag.txt:flag | *(server, ADS)* |
| 32 | Find origin server | Web | SSRF imgcdn.php?pic=base64(url) → ipinfo lộ origin | `CSG_FLAG{Claim_Abuse_to_Network_Admin}` |
| 33 | Get the ticket | Web | async 19 request song song (aiohttp) | `CSG_FLAG{H4rdToGet0TameshiTick3t}` |
| 34 | Please find the flag | Web | cmd injection bypass (dùng `find` giữ `|`) → 4n5w3r.ini /etc | *(server)* |
| 35 | timeTraveler | Web | SSTI {{config}} lộ SECRET_KEY → giả cookie time=future | *(server)* |
| 36 | Web Hacking Challenge 1 | Web | blind SQLi: len=29, SUBSTR dò từng ký tự | `CSG_FLAG{*-SQL-*}` |
| 37 | yara | Web | argument injection option `-s` (shlex chặn cmd inj) | *(server)* |

**Phân bố**: Crypto 3 · Forensic 3 · MISC 3 · Network 6 · OSINT 4 · Reversing 5 · Stego 5 · Web 8 = **37**.

✅ = flag tự khôi phục/xác minh bằng phân tích tĩnh trong tài liệu này.
⚠️ = chưa giải được hoàn toàn (xem đính chính trong `SOLUTIONS_VN.md`).
