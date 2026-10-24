# batch-unwrap

- **Category:** Misc / Reverse — script obfuscation + stego (ZIP có mật khẩu)
- **File đề:**
  - `kimpampara.txt` — 35904 byte, md5 `b309de56a7094b9a955869789b08c87a`. Một khối text dài chỉ gồm ký tự base64.
  - `unf0rgiven.zip` — 88339 byte, md5 `d7dafe3cc075835585200987f31b4b15`. ZIP đặt mật khẩu, bên trong đúng 1 file `Congratulations!.png` (kích thước giải nén 90736 byte, nén 88165 byte, cờ mã hóa bật).
  - `command.txt` — 3366 byte, batch script đã giải sẵn (bản tham khảo).
  - `solve.py` — script giải (chứa 1 lỗi nhỏ, xem bên dưới).

## Tóm tắt đề

Đề cho một blob text khổng lồ (`kimpampara.txt`) và một file ZIP có mật khẩu (`unf0rgiven.zip`). Bên trong ZIP chỉ có 1 ảnh PNG đang bị mã hóa. Nhiệm vụ: giải khối text để **trích ra mật khẩu**, rồi dùng mật khẩu đó mở ZIP.

**Bản chất đáp án:** kết quả cần nộp là **MẬT KHẨU mở ZIP** `F1r3NIc3$4Lyfe`, KHÔNG phải một chuỗi dạng `flag{...}`. Chuỗi này được một batch script in ra ở câu cuối: *"...here is the password F1r3NIc3$4Lyfe"*.

## Phân tích (chi tiết: khóa/offset/hằng số thật)

Chuỗi giải mã đi qua 3 lớp. Mọi hằng số dưới đây đọc trực tiếp từ file đề.

### Lớp 1 — Base64 hai lần (double base64)

80 byte đầu của `kimpampara.txt`:

```
VlNzd01EUXdWU3N3TURZMVZTc3dNRFl6VlNzd01EWTRWU3N3TURaR1ZTc3dNREl3VlNzd01EWkdWU3N3
```

Toàn file là ký tự base64 hợp lệ. Decode base64 **một lần** → kết quả *vẫn* là chuỗi base64 (dấu hiệu nhận biết lớp kép). Decode **lần hai** → ra một văn bản chỉ gồm các token dạng `U+HHHH`.

Chú ý: giải base64 lớp ngoài của đoạn trên ra chuỗi bắt đầu `VSs0MDQw VSs0MDY1 ...` kiểu `U+0040`... — đây chính là lớp base64 thứ hai cần decode tiếp.

### Lớp 2 — Danh sách codepoint `U+HHHH`

Sau khi decode 2 lớp base64, văn bản là một chuỗi gồm **3366 token** `U+HHHH` (hex 4 chữ số). Lấy phần hex của từng token rồi `chr(int(h,16))` → thu được **3366 byte** (khớp đúng kích thước `command.txt` = 3366 byte). Kết quả là một **Windows batch script**. Regex trích: `U\+([0-9A-Fa-f]{4})`.

### Lớp 3 — Batch obfuscation bằng `%VAR:~OFFSET,1%`

Đầu script (đọc từ `command.txt`, dòng 4–6) có 3 "alphabet" nền — đây là các khóa thật:

```bat
set HPOJs=YXSWCJUBLPNZGIAHDMKRVFTEQO
set BeoPl=clpadkuxztisfnerygwobmhqvj
set kufzE=8394265017
```

Cú pháp `%TEN:~OFFSET,LEN%` trong `cmd.exe` cắt chuỗi con từ biến `TEN`, bắt đầu tại `OFFSET` (đếm từ 0), lấy `LEN` ký tự. Toàn bộ script dựng lệnh/chữ bằng hàng loạt lookup 1 ký tự `%VAR:~i,1%`. Ví dụ `%BeoPl:~11,1%%BeoPl:~14,1%%BeoPl:~9,1%` = `BeoPl[11]BeoPl[14]BeoPl[9]` = `s`+`e`+`t` = từ khóa `set`.

Script **tự dẫn xuất thêm 3 alphabet** qua các dòng `set NAME=...` (giá trị cũng được ghép từ các alphabet cũ). Mô phỏng tĩnh cho ra chính xác (đã verify):

```
MVMwc = uozdvfqmxwljiethgpnrbyaksc
GUefu = 1748963052
hOKCW = VKURPBCQYDHMILFOGZXEWATJSN
```

Dòng cuối (dòng 14 của `command.txt`) là một lệnh `echo` khổng lồ dùng cả 6 alphabet với cú pháp `%%VAR:~i,1%%` (dấu `%` nhân đôi). Lý do nhân đôi: lệnh này được **sinh ra động** rồi chạy lại, nên cần sống sót qua một vòng phân giải của `cmd.exe`. Khi phân giải, các wrapper `%x%` còn dư (tham chiếu biến không tồn tại) nở thành chuỗi rỗng, để lại đúng các ký tự thật của thông điệp.

Mô phỏng dòng `echo` này → thông điệp cuối (đã verify bằng Python):

```
Good job and Congratulations... To open the ZIP file, here is the password F1r3NIc3$4Lyfe
```

→ **Mật khẩu ZIP = `F1r3NIc3$4Lyfe`**.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Phát hiện encode nhiều lớp:** blob chỉ chứa ký tự base64; decode 1 lần *vẫn* ra base64 ⇒ nghi double base64. VÌ SAO: một lần decode đúng thường ra dữ liệu có cấu trúc khác (nhị phân/ASCII thường), còn ra base64 sạch lần nữa là đặc trưng của lớp kép.
- **Codepoint `U+HHHH` → ký tự:** mẫu `U+` + đúng 4 hex lặp đều ⇒ danh sách codepoint. VÌ SAO chắc chắn: số token (3366) khớp chính xác kích thước script đích (3366 byte) — mỗi codepoint = 1 byte ASCII.
- **De-obfuscate batch `%VAR:~i,1%` bằng MÔ PHỎNG TĨNH, không chạy:** VÌ SAO không chạy — (a) an toàn, không thực thi mã lạ; (b) logic thuần là tra bảng (substring lookup) nên mô phỏng bằng Python cho kết quả y hệt mà không rủi ro. Quy trình: thay mỗi `%VAR:~off,1%` bằng 1 ký tự tương ứng, xử lý trước các dòng `set NAME=...` để nạp alphabet dẫn xuất, rồi mới bung dòng `echo`.
- **Mở ZIP ZipCrypto cổ điển bằng `pwd=`:** Python `zipfile` đọc được ZIP mã hóa ZipCrypto khi có mật khẩu — không cần crack.

## Lời giải chi tiết (bước + code sạch, chạy lại được)

> Lưu ý: `solve.py` gốc có lỗi — dòng 50 gọi `KIMPAMPARA.read_text()` trong khi `KIMPAMPARA` là một `str` tên file, không phải `pathlib.Path`, nên chạy thẳng sẽ `AttributeError`. Bản dưới đã sửa bằng `open(...).read()`. Đã chạy lại và xác nhận ra đúng mật khẩu.

```python
import base64, re, zipfile

# --- Lớp 1 + 2: double base64 -> chuỗi "U+HHHH" -> text batch ---
blob   = open("kimpampara.txt").read().strip()          # đọc khối base64
inner  = base64.b64decode(base64.b64decode(blob))        # DECODE HAI LẦN
cps    = re.findall(rb"U\+([0-9A-Fa-f]{4})", inner)      # 3366 codepoint
script = "".join(chr(int(c, 16)) for c in cps)           # -> batch script (3366 byte)

# --- Lớp 3: mô phỏng cmd.exe (tra bảng, KHÔNG chạy .bat) ---
env = {                                                  # 3 alphabet nền trong script
    "HPOJs": "YXSWCJUBLPNZGIAHDMKRVFTEQO",
    "BeoPl": "clpadkuxztisfnerygwobmhqvj",
    "kufzE": "8394265017",
}

def expand(line):
    # thay mọi %VAR:~OFF,1% bằng đúng 1 ký tự env[VAR][OFF]
    return re.sub(r"%([A-Za-z]+):~(\d+),1%",
                  lambda m: env[m.group(1)][int(m.group(2))]
                            if m.group(1) in env else m.group(0), line)

# nạp 3 alphabet dẫn xuất qua các dòng `set NAME=...`
for line in script.splitlines():
    s = expand(line.strip())
    m = re.match(r"^set\s+([A-Za-z]+)=(\S+)$", s, re.IGNORECASE)
    if m:
        env[m.group(1)] = m.group(2)
# -> MVMwc=uozdvfqmxwljiethgpnrbyaksc, GUefu=1748963052, hOKCW=VKURPBCQYDHMILFOGZXEWATJSN

# bung dòng echo cuối (%%VAR:~i,1%% -> sau 1 vòng còn %VAR...%)
echo_line = next(l for l in script.splitlines() if "=echo " in l)
template  = expand(echo_line.split("=echo ", 1)[1])
message   = expand(template).replace("%", "")            # bỏ wrapper %x% thừa (bung rỗng)
print(message)
# -> Good job and Congratulations... here is the password F1r3NIc3$4Lyfe

# --- Dùng mật khẩu mở ZIP ---
z = zipfile.ZipFile("unf0rgiven.zip")
data = z.read("Congratulations!.png", pwd=b"F1r3NIc3$4Lyfe")   # giải mã OK
open("Congratulations.png", "wb").write(data)
```

Hoặc mở nhanh ngoài shell (chú ý single-quote vì mật khẩu chứa `$`):

```bash
unzip -P 'F1r3NIc3$4Lyfe' unf0rgiven.zip   # -> Congratulations!.png (PNG 1080x1080)
```

Ảnh giải ra là một **lá cờ trắng** kèm chữ *"Congratulations!"* — lối chơi chữ xác nhận đã làm đúng.

## Flag

```
F1r3NIc3$4Lyfe
```

> Đây là **MẬT KHẨU mở ZIP**, KHÔNG phải chuỗi dạng `flag{...}`. Dạng chuỗi là leetspeak: `F1r3`=Fire, `NIc3`=Nice, `4Lyfe`=for life. Nếu hệ chấm yêu cầu wrapper khác thì nguồn không nêu — đáp án nộp đúng như trên.

## Gặp lại thì xử lý thế nào (playbook)

- **Dấu hiệu dạng bài:** một blob toàn ký tự base64 + một archive có mật khẩu đi kèm. Mật khẩu gần như chắc nằm trong blob.
- **Quy trình:**
  1. Giải base64 lặp cho tới khi ra text có cấu trúc (CyberChef "Magic", hoặc vòng lặp `b64decode`). Nếu decode xong *vẫn* là base64 ⇒ decode tiếp.
  2. Ra danh sách `U+HHHH` / `\uXXXX` / mảng số ⇒ map về ký tự bằng `chr()`. Đối chiếu số token với kích thước mục tiêu để chắc chắn.
  3. Ra batch/PowerShell/JS bị obfuscate ⇒ **mô phỏng tĩnh** (thay substring `%VAR:~i,1%`, nạp biến `set` trước, rồi bung dòng tạo chuỗi). TUYỆT ĐỐI không chạy script lạ.
  4. Rút mật khẩu → mở archive. Nội dung (ảnh/file) có thể là flag, hoặc chính mật khẩu là đáp án.
- **Bẫy hay gặp:** dừng ở lớp base64 đầu; chạy thẳng `.bat` lạ (nguy hiểm); quên wrapper `%x%` thừa trong `cmd` bung rỗng; ký tự `$` trong mật khẩu khi dùng shell cần single-quote.
- **Checklist ngắn:** mấy lớp base64? → codepoint→text? → batch obfuscation? → emulate `%VAR:~i,1%` + `set` → lấy pass → mở zip.
