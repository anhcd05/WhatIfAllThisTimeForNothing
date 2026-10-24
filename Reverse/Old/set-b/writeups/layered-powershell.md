# layered-powershell

- **Category:** Crypto
- **File đề:** `layered-powershell/README.md` chứa một blob Base64 rất dài. Không có file nhị phân — toàn bộ payload nằm trong text.

## Tóm tắt đề

Đề cho một **blob Base64 dài**. Tên bài gợi ý đây là mô phỏng **fileless malware** kiểu PowerShell: payload được bọc nhiều lớp (Base64 + charcode + gọi `iex` gián tiếp) để né antivirus. Nhiệm vụ: bóc các lớp và tìm flag — **giải tĩnh, không thực thi**.

## Phân tích (chi tiết)

**Lớp 1 — Base64.** Blob mở đầu bằng `KCgo...` và kết thúc bằng `...LUpvaW4gJycp` rồi `=`. Giải Base64 ra một dòng PowerShell:

```
(((102,117,110,99,116,105,111,110,32,83,104,111,119,...,41,59) | %{ ([Int]$_ -as [char]) }) -Join '') | &($env:comspec[4,15,25] -Join '')
```

Nhận ra cấu trúc kinh điển của PowerShell obfuscation:

- `(102,117,110,...)` là **danh sách mã ký tự (charcode) thập phân**.
- `| %{ ([Int]$_ -as [char]) }` map mỗi số → ký tự (`[char]`).
- `-Join ''` nối thành một chuỗi lệnh.
- `| &( ... )` thực thi chuỗi đó.

**Thủ thuật giấu `iex`.** `$env:comspec` trên Windows là `C:\Windows\system32\cmd.exe`. Lấy ký tự tại chỉ số `[4,15,25]`:

- index 4 = `i` (trong `C:\Wi...` → đếm 0-based: `C`=0, `:`=1, `\`=2, `W`=3, `i`=4),
- index 15 = `e`,
- index 25 = `x`.

Ghép lại `-Join ''` → `iex` (alias của `Invoke-Expression`). Tức là tác giả gọi `iex` mà **không viết thẳng chữ "iex"** để tránh bị quét chữ ký. Đây chính là lý do không nên chạy: `&(... )` sẽ thực thi chuỗi charcode.

**Lớp 2 — charcode → ASCII.** Đổi danh sách số sang ký tự, ra đoạn PowerShell thật:

```powershell
function ShowDummyFlag($flag){
  $md5 = [System.Security.Cryptography.MD5]::Create();
  $str = [System.Text.Encoding]::ASCII.GetBytes($flag.substring($flag.indexof("{")+1,$flag.substring($flag.indexof("{")+1).Length-1));
  $hash = $md5.ComputeHash($str);
  $hs = "";
  $hash | %{ $hs += $_.ToString("x2") };
  $flag_hash = $flag.substring(0,$flag.indexof("{")+1) + $hs + $flag.substring($flag.indexof("}"));
  echo $flag_hash;
};
ShowDummyFlag("flag{Fileless_Malware_Often_Uses_ShellScript}");
```

Đọc ra ngay: hàm `ShowDummyFlag` lấy phần giữa `{...}`, tính **MD5** của nó rồi in `flag{<md5>}` — đây là một **"dummy flag"** đánh lừa. **Flag thật nằm nguyên trong tham số truyền vào lời gọi** `ShowDummyFlag("flag{...}")`, không cần chạy hàm.

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **Base64 decode** lớp ngoài. *Vì sao:* PowerShell hay dùng `-EncodedCommand`/Base64; blob kết thúc `=` xác nhận.
2. **Charcode decode** (số thập phân → `[char]`). *Vì sao:* đây là kỹ thuật `-Join` charcode phổ biến để giấu lệnh khỏi bộ quét chuỗi.
3. **Đọc tĩnh, không `iex`.** *Vì sao:* `&($env:comspec[4,15,25] -Join '')` = `iex`; chạy nó sẽ thực thi payload. Với mẫu malware (dù lành) luôn giải tĩnh.
4. **Nhận diện bẫy dummy flag.** *Vì sao:* hàm tính MD5 để in `flag{<md5>}`; nếu chạy sẽ ra hash dễ tưởng nhầm là flag. Flag thật là chuỗi gốc truyền vào.

## Lời giải chi tiết (bước + code/lệnh sạch)

```python
import base64, re

blob = open("README.md").read()
# lấy đúng dòng Base64 dài trong code block đầu tiên
b64 = re.search(r'KCgo[A-Za-z0-9+/=]+', blob).group(0)

layer1 = base64.b64decode(b64).decode()      # lệnh PowerShell với danh sách charcode
# trích danh sách số nằm trong '((( ... ) |'
nums = re.search(r'\(\(\((.*?)\)\s*\|', layer1).group(1)
script = ''.join(chr(int(n)) for n in nums.split(','))
print(script)
# -> function ShowDummyFlag($flag){...}; ShowDummyFlag("flag{Fileless_Malware_Often_Uses_ShellScript}");
```

Trong chuỗi `script`, đọc tham số của `ShowDummyFlag(...)` là ra flag.

Cách bằng CyberChef (không chạy code): `From Base64` → `From Charcode` (delimiter = `Comma`) → đọc chuỗi PowerShell → lấy tham số của `ShowDummyFlag`.

## Flag

flag{Fileless_Malware_Often_Uses_ShellScript}

## Gặp lại thì xử lý thế nào (playbook)

1. Blob dài kết thúc `=`, khởi đầu `-EncodedCommand`/Base64 → **Base64 decode** trước.
2. Thấy danh sách số `(…,…,…)` + `[char]`/`-Join`/`%{}` → **charcode → ASCII**.
3. Thấy `&(...)`, `iex`, `Invoke-Expression`, hoặc chỉ-số-ký-tự của `$env:comspec`/`$shellid`/`$PSHOME` → đó là lời gọi thực thi ẩn → **tuyệt đối không chạy**, chỉ đọc.
4. Nếu script "tính hash rồi in flag" → cẩn thận **dummy flag**; tìm chuỗi gốc được truyền/so sánh, đó mới là flag thật.
5. Nếu còn lớp nữa (XOR, gzip/Deflate, SecureString, replace) → lặp lại quy trình bóc lớp cho tới khi ra lệnh/flag.
6. Công cụ bóc tách an toàn: CyberChef, `PowerShell -NoProfile` với `AMSI`/log, hoặc đơn giản giải tĩnh bằng Python như trên.
