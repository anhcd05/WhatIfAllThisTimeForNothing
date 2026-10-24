# xor-halves

- **Category:** Crypto (XOR / known-plaintext / base64)
- **File đề:** `challenges/xor-halves/chall.txt` (1186 byte) — vài cặp mẫu `(CipherText, PlainText)` và một `CipherText` cuối cần giải ra flag. Kèm `solve.py` (script giải của tác giả). Phân tích tĩnh, không cần chạy nhị phân.

## Tóm tắt đề

`chall.txt` cho một số ví dụ "số nguyên đã mã hoá" (encrypted integers) kèm bản rõ tương ứng, rồi yêu cầu giải mảng số cuối để lấy flag:

```
CipherText: -44, -34, -15, 25, 88, 4, -87, -108, ... (72 số)
PlainText : Hello? Hello? Anybody home?

CipherText: -43, -86, -19, 6, 99, 27, -64, -36, 16, 64, -44, 116, 8, -80, -89, -71,
            -121, -103, -89, 106, 58, 67, -111, -69, 69, 114, -102, 2, 108, -8, -10, -47   (32 số)
PlainText : Great Scott!

CipherText: -48, 35, -55, -93, 63, -103, 81, 85, ... (80 số)
PlainText = Flag?

As always, the flag starts with "flag", you know.
```

Mỗi ciphertext là mảng **số nguyên có dấu** trong khoảng −128..127.

## Phân tích (chi tiết: khóa/offset/hằng số thật)

**1) Số có dấu = byte bù hai.** Mỗi phần tử là một byte biểu diễn ở dạng two's complement: giá trị âm `v` tương ứng byte `v & 0xFF` (hay `v + 256`). Ví dụ `-48` = `0xD0` = 208. Khi XOR, dấu không quan trọng, chỉ cần quy về 0..255.

**2) Mọi độ dài đều chẵn và chia đôi được.** Đây là manh mối cốt lõi:
- `Great Scott!` → 32 số → 2 nửa × 16.
- `Hello? Hello? Anybody home?` → 72 số → 2 nửa × 36.
- Ciphertext flag → **80 số → 2 nửa × 40** (offset chia: `cipher[:40]` và `cipher[40:]`).

**3) Đối chiếu với base64 của plaintext.** `base64("Great Scott!")` = `R3JlYXQgU2NvdHQh` dài đúng **16** ký tự = nửa đầu. `base64("Hello? Hello? Anybody home?")` dài **36** = nửa đầu. Vậy mỗi ciphertext = `base64(plaintext)` (độ dài N) **nối** thêm N byte nữa.

**4) Keystream nằm lộ thiên ở nửa sau.** Thử giả thuyết `nửa_đầu XOR nửa_sau = base64(plaintext)`:
- Với `Great Scott!`: 16 byte đầu XOR 16 byte sau → ra đúng `R3JlYXQgU2NvdHQh` → base64-decode = `Great Scott!`. ✅
- Bằng chứng củng cố: đuôi khóa của mẫu `Great Scott!` là `-121,-103,-89,106,58,67,-111,-69,69,114,-102,2,108,-8,-10,-47`. Chính chuỗi này **xuất hiện lại** làm một đoạn trong ciphertext `Hello?...` (byte thứ 17..32). Chứng tỏ keystream sinh theo một quy luật nội bộ — nhưng **ta không cần biết quy luật đó**, vì khóa luôn được chép nguyên vào **nửa sau** của chính ciphertext.

**Công thức thật:** `plaintext = base64_decode( cipher[:len/2] XOR cipher[len/2:] )`.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Known-plaintext attack:** có cặp (cipher, plain) → suy ngược cấu trúc. VÌ SAO dùng được: khi biết bản rõ, ta tự tính `base64(plain)` và so với ciphertext để phát hiện bố cục "nửa đầu = data XOR key, nửa sau = key".
- **XOR đối hợp (involution):** `A XOR B XOR B = A`. VÌ SAO quan trọng: vì key = nửa sau nằm ngay trong ciphertext, chỉ cần XOR hai nửa là khử key, không cần brute-force.
- **Nhận diện lớp base64 trung gian:** sau XOR ra toàn ký tự `A–Za–z0–9+/=`. VÌ SAO: tác giả base64 hoá plaintext trước để kết quả XOR rơi vào tập ký tự in được, dễ ngụy trang thành "số"; nếu không decode tiếp sẽ tưởng sai.

## Lời giải chi tiết (bước + code/lệnh sạch, chạy lại được)

```python
# solve_xor_halves.py  — chạy: python3 solve_xor_halves.py
import base64

# Ciphertext flag (80 số có dấu) lấy từ chall.txt, quy về byte 0..255 bằng & 0xFF
raw = [-48,35,-55,-93,63,-103,81,85,54,1,-108,-4,-16,77,5,58,
       -5,-57,15,-106,-112,-92,-119,-126,-55,-80,-75,-27,41,27,11,-71,
       -59,33,112,-75,19,-95,-1,50,                      # hết nửa đầu (40 byte)
       -127,18,-121,-21,103,-87,11,24,103,84,-16,-53,-90,127,60,79,
       -97,-127,54,-64,-56,-106,-72,-22,-88,-126,-29,-125,125,92,93,-51,
       -89,19,69,-35,73,-26,-87,11]                      # nửa sau = keystream
cipher = [b & 0xFF for b in raw]

half = len(cipher) // 2                       # = 40
data, key = cipher[:half], cipher[half:]      # tách 2 nửa
b64 = bytes(d ^ k for d, k in zip(data, key)) # XOR -> chuỗi base64
print(base64.b64decode(b64).decode())
```

Giải thích từng bước:
1. **Quy byte:** `b & 0xFF` đưa mọi số âm về 0..255 (two's complement).
2. **Tách offset 40/40:** `data = cipher[:40]`, `key = cipher[40:]`.
3. **XOR khử keystream:** `data[i] ^ key[i]` ra byte base64.
4. **base64-decode** ra chuỗi cuối.

Chuỗi base64 trung gian là `Q1NHX0ZMQUd7V29udF9VX21ha2VfTGVtb25hZGV9`, decode ra `<giải>_FLAG{Wont_U_make_Lemonade}` — tiền tố wrapper mang **tên kỳ thi CTF** đã được REDACT; chuẩn hoá về `flag{...}`.

Kiểm chứng bằng cặp mẫu (nên làm trước khi tin kết quả):
```python
gs = [b & 0xFF for b in [-43,-86,-19,6,99,27,-64,-36,16,64,-44,116,8,-80,-89,-71,
                         -121,-103,-89,106,58,67,-111,-69,69,114,-102,2,108,-8,-10,-47]]
h = len(gs)//2
print(base64.b64decode(bytes(a^b for a,b in zip(gs[:h],gs[h:]))).decode())  # -> Great Scott!
```

## Flag

```
flag{Wont_U_make_Lemonade}
```

(Wrapper thật giải ra là `<giải>_FLAG{Wont_U_make_Lemonade}`; tiền tố là tên kỳ thi CTF nên đã REDACT và chuẩn hoá thành `flag{...}`. Nội dung flag không đổi; các bản rõ mẫu "Great Scott!", "Anybody home?" là thoại phim *Back to the Future* — chủ đề bộ đề.)

## Gặp lại thì xử lý thế nào (playbook)

- **Dấu hiệu nhận diện:** đề cho "mảng số" kèm vài cặp (cipher, plain) và một cipher cần giải; độ dài luôn **chẵn**; có đoạn byte **lặp lại** giữa các mẫu.
- **Quy trình:**
  1. Quy mọi số về byte 0..255 (`v & 0xFF`).
  2. Đo độ dài, thử bố cục **2 nửa**: tính `base64(plain_mẫu)`, so độ dài với nửa đầu để xác nhận.
  3. XOR hai nửa; nếu ra toàn ký tự in được → thử decode **base64** (hoặc hex) ở lớp trong.
  4. **Verify trên cặp mẫu** rồi mới áp cho cipher flag.
- **Bẫy hay gặp:** quên quy số âm → XOR lệch; quên lớp base64 → tưởng ra rác; đi tìm "thuật toán sinh key" trong khi key nằm sẵn ở nửa sau.
- **Checklist:** byte hoá? độ dài chẵn? tách nửa? XOR → in được? decode base64/hex? verify mẫu? → áp flag.
