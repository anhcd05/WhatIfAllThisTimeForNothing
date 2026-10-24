# teleprinter-code

- **Category:** Misc / Encoding (teleprinter / Baudot-ITA2 + spelling alphabet)
- **File đề:**
  - `oddfile.txt` — 2180 byte (2178 byte nội dung), md5 `a2a7730f246d6fac829ddfe59a9be01e`. Gồm một câu tiếng Anh ở đầu rồi một luồng dài chỉ ký tự `.` và `-`.
  - `description.txt` — mô tả đề (nói về điện báo/telegraph, nhấn mạnh Morse, gợi ý flag dạng `flag{LOOK.SOMETHING.LIKE.THIS}`).
  - `solve.py` — script giải, tự chọn biến thể bit đúng.

## Tóm tắt đề

File mở đầu bằng câu văn cảnh *"We lived in coded times when it was not easy and the rewere shades of grey and ambiguity"* (chỉ là bối cảnh), rồi theo sau là **luồng dài chỉ gồm `.` và `-`**. Mô tả đề nói về điện báo và Morse — nhưng Morse là **mồi nhử (red herring)**. Luồng này thực ra là mã **Baudot / ITA2** (5-bit cố định), giải xong lại ra một dãy **từ đánh vần vô tuyến (radio spelling alphabet)**, lấy chữ cái đầu mỗi từ mới ra flag.

## Phân tích (chi tiết: khóa/offset/hằng số thật)

### Số liệu thật (đọc từ `oddfile.txt`)

- Câu tiếng Anh ở đầu không chứa `.`/`-`.
- Luồng tín hiệu: **2088 ký tự** `.`/`-` (898 dấu `.`, 1190 dấu `-`).
- `2088 mod 5 = 3` ⇒ chia nhóm 5 bit được **417 nhóm** (2085 bit), **3 bit cuối dư bị bỏ** (phần đuôi padding không mang chữ).

### Lớp 1 — Loại trừ Morse, xác định ITA2 (5-bit)

Morse có độ dài ký tự thay đổi nên **bắt buộc có dấu phân tách** giữa chữ/từ. Luồng ở đây liền mạch, đồng đều, không có dấu tách ⇒ **không phải Morse** mà là mã **độ dài cố định**. Gợi ý trong đề về điện báo "đời cũ" chỉ về **Baudot / ITA2** — mã teleprinter 5 bit, 32 tổ hợp, có hai chế độ LETTERS (LTRS) và FIGURES (FIGS). Ở bài này chỉ cần ép chế độ **LETTERS**.

Bảng ITA2 LETTERS thật dùng trong `solve.py` (5 bit → ký tự):

```python
ITA2_LTRS = {
    0b00000:'', 0b00001:'E', 0b00010:'\n', 0b00011:'A', 0b00100:' ',
    0b00101:'S', 0b00110:'I', 0b00111:'U', 0b01000:'\r', 0b01001:'D',
    0b01010:'R', 0b01011:'J', 0b01100:'N', 0b01101:'F', 0b01110:'C',
    0b01111:'K', 0b10000:'T', 0b10001:'Z', 0b10010:'L', 0b10011:'W',
    0b10100:'H', 0b10101:'Y', 0b10110:'P', 0b10111:'Q', 0b11000:'O',
    0b11001:'B', 0b11010:'G', 0b11011:'FIGS', 0b11100:'M', 0b11101:'X',
    0b11110:'V', 0b11111:'LTRS'
}
```

### Lớp 1b — Định chiều bit (biến thể THẬT đã thắng)

Không biết `.`=1 hay `.`=0, cũng không biết có đảo thứ tự 5 bit trong nhóm hay không ⇒ thử **4 biến thể** và chấm điểm bằng "số từ đánh vần hợp lệ giải được". Kết quả chạy thực tế trên luồng của `oddfile.txt`:

| Biến thể | Ánh xạ | Đảo nhóm 5 | Điểm (số chữ) |
|---|---|---|---|
| **THẮNG** | `.`=`1`, `-`=`0` | không | **61** |
| | `.`=`1`, `-`=`0` | có | 0 |
| | `.`=`0`, `-`=`1` | không | 0 |
| | `.`=`0`, `-`=`1` | có | 0 |

⇒ Biến thể đúng: **`.` → bit 1, `-` → bit 0, KHÔNG đảo nhóm, MSB-first**.

### Lớp 2 — Bảng đánh vần vô tuyến → chữ cái đầu

Văn bản ITA2 giải ra là một dãy **từ đánh vần radio** (kiểu Bắc Âu/Thụy Điển): `CAESAR SIGURD GUSTAV ...`. Bảng thật (`SWE` trong `solve.py`):

```
ADAM=A BERTIL=B CAESAR=C DAVID=D ERIK=E FILIP=F GUSTAV=G HELGE=H IVAR=I
JOHAN=J KALLE=K LUDVIG=L MARTIN=M NIKLAS=N OLOF=O PETTER=P QVINTUS=Q
RUDOLF=R SIGURD=S TORE=T URBAN=U VIKTOR=V WILHELM=W XERXES=X YNGVE=Y ZETA=Z
```

Lấy chữ cái đầu mỗi từ, ghép lại (chuỗi 61 chữ thực tế giải ra):

```
<REDACTED>UNDERSCOREFLAGOPENINGBRACEPUNCHCARDSAREDEADNOWCLOSINGBRACE
```

### Lớp 3 — Chuẩn hóa token thành ký hiệu

- `UNDERSCORE → _`
- `OPENINGBRACE → {`
- `CLOSINGBRACE → }`

Ghép lại ra flag. (Tiền tố đầu chuỗi được đánh vần ra tên định danh của **giải** nên đã REDACT — xem mục Flag.)

## Kỹ thuật áp dụng (+ VÌ SAO)

- **ITA2 / Baudot 5-bit:** VÌ SAO chọn — luồng nhị-phân-hóa-được (chỉ 2 ký hiệu) nhưng giải Morse không ra, đề gợi "điện báo đời cũ"; mã 5-bit cố định độ dài là lời giải, không cần dấu phân tách.
- **Brute-force định chiều bit (4 biến thể) + chấm điểm:** VÌ SAO — ánh xạ `.`/`-`→bit và thứ tự bit trong nhóm đều mơ hồ; chấm bằng số từ đánh vần khớp giúp tự chọn đúng (ở đây chỉ biến thể `.`=1/`-`=0/không đảo cho điểm > 0).
- **Spelling alphabet mapping:** VÌ SAO nhận ra — văn bản ITA2 ra toàn tên riêng (ADAM, CAESAR, GUSTAV, SIGURD...) ⇒ đó là bảng đánh vần radio; map về chữ cái đầu là lớp mã thứ hai.
- **Chuẩn hóa token ký hiệu:** các dấu `_ { }` được đánh vần thành `UNDERSCORE / OPENINGBRACE / CLOSINGBRACE` để không phá vỡ hệ "toàn chữ cái" của bảng đánh vần.

## Lời giải chi tiết (bước + code sạch, chạy lại được)

`solve.py` chạy toàn bộ pipeline và tự chọn biến thể. Phần cốt lõi (chạy trực tiếp trên luồng của `oddfile.txt`, đã verify):

```python
import re

ITA2_LTRS = {0b00000:'',0b00001:'E',0b00010:'\n',0b00011:'A',0b00100:' ',
 0b00101:'S',0b00110:'I',0b00111:'U',0b01000:'\r',0b01001:'D',0b01010:'R',
 0b01011:'J',0b01100:'N',0b01101:'F',0b01110:'C',0b01111:'K',0b10000:'T',
 0b10001:'Z',0b10010:'L',0b10011:'W',0b10100:'H',0b10101:'Y',0b10110:'P',
 0b10111:'Q',0b11000:'O',0b11001:'B',0b11010:'G',0b11011:'FIGS',0b11100:'M',
 0b11101:'X',0b11110:'V',0b11111:'LTRS'}

SWE = {'ADAM':'A','BERTIL':'B','CAESAR':'C','DAVID':'D','ERIK':'E','FILIP':'F',
 'GUSTAV':'G','HELGE':'H','IVAR':'I','JOHAN':'J','KALLE':'K','LUDVIG':'L',
 'MARTIN':'M','NIKLAS':'N','OLOF':'O','PETTER':'P','QVINTUS':'Q','RUDOLF':'R',
 'SIGURD':'S','TORE':'T','URBAN':'U','VIKTOR':'V','WILHELM':'W','XERXES':'X',
 'YNGVE':'Y','ZETA':'Z'}

def extract_dot_dash(s):            # chỉ giữ . và - (bỏ câu văn cảnh ở đầu)
    return ''.join(re.findall(r'[.\-]+', s))

def bits_from_stream(stream, dot_as, dash_as, reverse_chunk=False):
    b = stream.replace('.', dot_as).replace('-', dash_as)
    if reverse_chunk:
        return ''.join(b[i:i+5][::-1] for i in range(0, len(b)-len(b)%5, 5))
    return b[:(len(b)//5)*5]         # cắt bỏ đuôi dư (2088 -> 2085 bit)

def ita2_force_letters(bits):        # mỗi 5 bit -> 1 ký tự LETTERS
    txt = ''.join(ITA2_LTRS.get(int(bits[i:i+5],2), '') for i in range(0,len(bits),5))
    for tok in ('LTRS','FIGS'):
        txt = txt.replace(tok, ' ')
    return re.sub(r'[\r\n\t]+', ' ', txt)

def words_to_letters(text):          # mỗi từ đánh vần -> chữ cái đầu
    return ''.join(SWE[w.upper()] for w in re.split(r'[^A-Za-z]+', text)
                   if w and w.upper() in SWE)

stream = extract_dot_dash(open('oddfile.txt').read())   # 2088 ký tự
best = ''
for da, ha, rev in [('1','0',False),('1','0',True),('0','1',False),('0','1',True)]:
    letters = words_to_letters(ita2_force_letters(bits_from_stream(stream, da, ha, rev)))
    if len(letters) > len(best):
        best = letters
# best = '<REDACTED>UNDERSCOREFLAGOPENINGBRACEPUNCHCARDSAREDEADNOWCLOSINGBRACE'

flag = (best.replace('UNDERSCORE','_')
             .replace('OPENINGBRACE','{').replace('CLOSINGBRACE','}'))
print(flag)
```

Chạy thực tế:

```bash
$ python solve.py
<REDACTED>_FLAG{PUNCHCARDSAREDEADNOW}
```

Phần lõi flag là `PUNCHCARDSAREDEADNOW`; tiền tố/wrapper chuẩn hóa thành `flag{...}`.

## Flag

```
flag{PUNCHCARDSAREDEADNOW}
```

> Lưu ý: chuỗi literal mà `solve.py` in ra có một tiền tố là **tên định danh của giải** ngay trước `_FLAG{...}`. Tiền tố đó đã được REDACT ở writeup này; lõi flag `PUNCHCARDSAREDEADNOW` là phần cần nộp, trình bày chuẩn dưới dạng `flag{PUNCHCARDSAREDEADNOW}`. Ý nghĩa: *"punch cards are dead now"* (thẻ đục lỗ nay đã tuyệt chủng) — đùa về công nghệ cổ, khớp chủ đề "very old odd file" và mã Baudot cổ.

## Gặp lại thì xử lý thế nào (playbook)

- **Dấu hiệu dạng bài:** stream chỉ gồm 2 ký hiệu (`.-`, `01`, `AB`, hai màu...) và đề cố ý gợi Morse. Nghi ngờ "KHÔNG phải Morse" ngay khi stream quá đều và không có khoảng ngắt.
- **Quy trình:**
  1. Lọc đúng 2 ký hiệu, đếm độ dài. Chia hết (gần) cho 5 ⇒ nghĩ ITA2/Baudot (5-bit); chia hết cho 8 ⇒ nghĩ ASCII/byte. (Ở đây 2088, mod 5 = 3, bỏ 3 bit đuôi.)
  2. Thử cả 2 cách ánh xạ ký hiệu→bit và cả đảo bit trong nhóm (4 biến thể). Chấm điểm bằng "số từ/chữ có nghĩa" để tự chọn.
  3. Output ra chuỗi tên riêng lạ (ADAM, CAESAR, ALPHA, ANTON...) ⇒ bảng đánh vần radio (Thụy Điển/NATO/Đức...). Map về chữ cái đầu.
  4. Chuẩn hóa các từ ký hiệu (UNDERSCORE, OPENINGBRACE...) thành dấu rồi ráp flag.
- **Bẫy hay gặp:** mặc định là Morse; quên chế độ LTRS/FIGS của ITA2 (ở bài này chỉ cần LETTERS); quên thử đảo chiều bit; map nhầm bảng spelling của ngôn ngữ khác; quên xử lý bit đuôi dư.
- **Công cụ thay thế:** CyberChef có operation "ITA2 / Baudot" và cho đổi chiều bit — thử trực quan thay vì tự code.
- **Checklist ngắn:** 2 ký hiệu? → độ dài %5 hay %8? → 4 biến thể bit, chấm điểm? → từ có nghĩa? → spelling alphabet? → chuẩn hóa token → ráp flag.
