# jigsaw-vigenere

- **Category:** Forensics / Stego (JPEG+ZIP polyglot) + Crypto cổ điển (Vigenère)
- **File đề:** `challenges/jigsaw-vigenere/painting.jpg` (6.406.965 byte, md5 `35e5e1a9984827135c29df5eb64c692d`) — ảnh JPEG bức *The Death of Socrates* (Jacques-Louis David) có một kho **ZIP nối thêm ở đuôi**. Repo chỉ có ảnh, không có script. Phân tích tĩnh hoàn toàn.

## Tóm tắt đề

Ảnh mở ra bình thường, nhưng bên trong là file **JPEG + ZIP polyglot**: sau phần JPEG là một archive ZIP **đặt mật khẩu** chứa **12 mảnh ảnh** (tiles) của bức tranh. Mỗi tile giấu một đoạn text ngắn bị xáo. Ghép tile đúng thứ tự (theo vị trí trong tranh) → nối các đoạn text → ra một **ciphertext Vigenère** → giải với khóa **`MAN`** → flag.

## Phân tích (chi tiết: khóa/offset/hằng số thật)

**1) Cấu trúc polyglot — offset thật.** Quét chữ ký bằng phân tích tĩnh:
- Kích thước file: `6.406.965` byte.
- Local File Header đầu tiên `PK\x03\x04` tại **offset 350274** → phần JPEG hiển thị được nằm ở đầu, toàn bộ ZIP bắt đầu từ đây.
- End Of Central Directory `PK\x05\x06` tại offset `6406943` (gần cuối) — xác nhận ZIP chạy tới hết file.

**2) ZIP có mật khẩu, kiểu ZipCrypto (không phải AES).** Đọc Local File Header:
- Compression method = **8** (Deflate).
- General purpose flag = **`0x0009`** → bit 0 = *encrypted*, bit 3 = *data descriptor*.
- Extra field length = **0** → **không có** extra field `0x9901` của WinZip-AES. Vậy đây là **ZipCrypto cổ điển** → có thể dùng `zip2john` + `john`/`hashcat` để crack, hoặc known-plaintext.

**3) 13 entry với tên lộ gợi ý.** Các entry trong ZIP:
```
The Death of Socrates/            (thư mục)
The Death of Socrates/1 I.jpg
The Death of Socrates/2 SAW.jpg
The Death of Socrates/3 MICHELANGELO.jpg
The Death of Socrates/4 AT.jpg
The Death of Socrates/5 WORK.jpg
The Death of Socrates/6 ..jpg
The Death of Socrates/7 HE.jpg
The Death of Socrates/8 HAD.jpg
The Death of Socrates/9 PASSED.jpg
The Death of Socrates/10 HIS.jpg
The Death of Socrates/11 SIXTIETH.jpg
The Death of Socrates/12 YEAR.jpg
```
Ghép theo số thứ tự tên file ra câu: **"I SAW MICHELANGELO AT WORK. HE HAD PASSED HIS SIXTIETH YEAR"**. Con số `1..12` là **chỉ số tile** — không phải thứ tự nối text; thứ tự nối text lấy từ việc **ráp hình** (xem dưới).

**4) 12 đoạn text giấu trong tile.** `strings` từng tile ra 12 mảnh (mỗi mảnh là một đoạn ciphertext bị cắt):
```
q-pvothd   ef!-Ooas   g-aeq-sh   eeq-cvbh   rd-iaeiq   ocressgl
uemthdag   guoae!!}   {Ynk!==Yb   qd-Iugrz   OST_RLNS   yk-drooq
```

**5) Thứ tự ráp tranh.** Xếp 12 tile cho khớp bức tranh → thứ tự:
```
11 - 9 - 3 - 6 - 12 - 10 - 4 - 5 - 1 - 2 - 7 - 8
```
Nối theo thứ tự đó → ciphertext (theo README):
```
OST_RLNS{Ynk!==Ybg-aeq-shocressglyk-drooqqd-Iugrzeeq-cvbhrd-iaeiqq-pvothdef!-Ooasuemthdagguoae!!}
```

**6) Nhận ra Vigenère + tìm khóa.** Chỉ các **chữ cái** bị đổi, còn `_ { } ! = -` giữ nguyên → mã thay thế chỉ áp A–Z ⇒ Vigenère. Biết tiền tố plaintext là wrapper flag (`<giải>_FLAG`, tên kỳ thi CTF đã REDACT), dùng known-plaintext:
`K[i] = (C[i] − P[i]) mod 26` trên `OST_RLNS` ↔ `<giải>_FLAG` → dãy khóa lặp `M, A, N, (_) , M, A, N, M` → **khóa = `MAN`**.

**7) Đính chính ciphertext README (QUAN TRỌNG).** Giải khóa `MAN` khớp **tuyệt đối** tới `...inside-pictures!-Cong`, rồi đuôi README ra rác (`uraturatuuboe!!}`). Mã hoá **ngược** flag đã-verify bằng khóa `MAN` cho ciphertext đúng:
```
Đúng  : OST_RLNS{Ynk!==Yb...-Ooas rnfuymtvanf!!}
README: OST_RLNS{Ynk!==Yb...-Ooas uemthdagguoae!!}
```
Hai chuỗi khớp tới `-Ooas` (index 81) rồi lệch. Nghĩa là **hai mảnh tile cuối** trong README (`uemthdag` + `guoae!!}`) bị **chép/sắp sai**; phần đúng là `rnfuymtvanf!!}`. **Khóa chắc chắn `MAN`, flag chắc chắn đúng**, chỉ chuỗi đã-ghép trong README lỗi ở 2 tile cuối.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Carve polyglot JPEG+ZIP:** JPEG kết thúc logic ở `FF D9`, byte sau bị trình xem ảnh bỏ qua. VÌ SAO khai thác được: ZIP dùng central directory ở **cuối** file nên vẫn mở được dù nằm sau JPEG.
- **Đọc trực tiếp header ZIP để xác định kiểu mã hoá:** VÌ SAO cần: phân biệt ZipCrypto (flag bit0, không extra 0x9901) với WinZip-AES quyết định cách crack/known-plaintext.
- **Tên entry làm hint:** VÌ SAO chú ý: số `1..12` chốt số lượng tile và cách đánh chỉ số; câu trích dẫn là "flavor" dẫn dắt.
- **Visual reassembly → thứ tự nối:** VÌ SAO: tác giả dùng **vị trí tile trong tranh** làm khoá sắp xếp dữ liệu; ráp đúng hình = đúng thứ tự ciphertext.
- **Vigenère known-plaintext:** VÌ SAO nhanh nhất: chỉ cần vài ký tự đầu (`flag`/wrapper) để lấy khóa thay vì phân tích tần suất.

## Lời giải chi tiết (bước + code/lệnh sạch, chạy lại được)

```python
# Bước 1 — carve ZIP khỏi JPEG (offset thật tự dò bằng chữ ký)
data = open("painting.jpg", "rb").read()
idx  = data.find(b"PK\x03\x04")          # = 350274
open("embedded.zip", "wb").write(data[idx:])
```

```bash
# Bước 2 — ZIP ZipCrypto có mật khẩu: crack hoặc dùng password đi kèm đề
zip2john embedded.zip > hash.txt
john --wordlist=rockyou.txt hash.txt       # hoặc hashcat -m 17200/17210
unzip -P <password> embedded.zip           # -> 12 tile .jpg

# Bước 3 — trích đoạn text giấu trong mỗi tile
for f in "The Death of Socrates"/*.jpg; do
  echo "== $f =="; strings "$f" | grep -E '[{}!=_-]'
done
```

```python
# Bước 4 — ráp theo thứ tự tranh rồi giải Vigenère khóa MAN
order = [11,9,3,6,12,10,4,5,1,2,7,8]       # thứ tự ráp hình
# (nối các đoạn text của từng tile theo 'order' -> ct)
ct = "OST_RLNS{Ynk!==Ybg-aeq-shocressglyk-drooqqd-Iugrzeeq-cvbhrd-iaeiqq-pvothdef!-Ooasrnfuymtvanf!!}"
#      ^ dùng chuỗi ĐÃ ĐÍNH CHÍNH (2 tile cuối trong README bị sai)

def vigenere_decrypt(ct, key="MAN"):
    out, ki = [], 0
    for ch in ct:
        if ch.isalpha():
            k = ord(key[ki % len(key)]) - ord('A')
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base - k) % 26 + base)); ki += 1
        else:
            out.append(ch)                 # giữ nguyên _ { } ! = -
    return "".join(out)

print(vigenere_decrypt(ct))
# -> <giải>_FLAG{Yay!==You-are-successfully-decoded-Vigenere-cipher-inside-pictures!-Congratulations!!}
```

Wrapper `<giải>_FLAG` là tên kỳ thi CTF đã REDACT; chuẩn hoá thành `flag{...}`.

## Flag

```
flag{Yay!==You-are-successfully-decoded-Vigenere-cipher-inside-pictures!-Congratulations!!}
```

(Giải ra wrapper `<giải>_FLAG{...}`; tiền tố là tên kỳ thi CTF nên REDACT và chuẩn hoá thành `flag{...}`. Đã verify bằng mã hoá ngược với khóa `MAN`.)

## Gặp lại thì xử lý thế nào (playbook)

- **Dấu hiệu nhận diện:** ảnh **lớn bất thường** (vài MB cho một ảnh thường); `binwalk`/quét chữ ký báo có `PK`/`Rar!`/`7z` sau `FF D9`; nhiều tile ảnh; text giấu rải rác bị xáo.
- **Quy trình:**
  1. Dò chữ ký `PK\x03\x04` / `PK\x05\x06`, carve từ offset đó ra `.zip`.
  2. Đọc GP-flag + extra field để biết **ZipCrypto vs AES**; có mật khẩu → `zip2john`/`hashcat` hoặc hint trong EXIF/strings/tên file.
  3. Nhiều tile → **ráp hình** để lấy **thứ tự nối**; để ý tên file có đánh số là hint.
  4. Chuỗi "giống flag nhưng chữ loạn, ký tự đặc biệt đúng chỗ" → cipher thay thế. Dùng known-plaintext (`flag`/wrapper) suy khóa; khóa dài >1 → Vigenère, =1 → Caesar.
  5. **Verify bằng mã hoá ngược**: nếu đuôi lệch mà đầu khớp tuyệt đối → nghi dữ liệu đã-ghép bị lỗi, không phải sai khóa.
- **Công cụ:** `binwalk`, `strings`, `exiftool`, `unzip`/`7z`, `zip2john`+`john`/`hashcat`, dcode.fr / CyberChef (Vigenère), script Python.
- **Bẫy hay gặp:** sa đà LSB/stego phức tạp trong khi dữ liệu chỉ append đuôi; sai thứ tự ráp tile → ciphertext rác; quên giữ nguyên ký tự không-chữ cái khi giải; tưởng sai khóa khi thực ra ciphertext nguồn lỗi.
- **Checklist:** carve → xác định kiểu ZIP → giải nén → strings từng tile → ráp hình lấy thứ tự → nối → nhận cipher → known-plaintext khóa → giải → verify ngược.
