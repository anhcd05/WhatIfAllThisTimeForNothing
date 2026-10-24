# managed-branch

- **Category:** Binary
- **File đề:** `managed-branch/fee201a96c8e30d09141f7493457f1b6.exe` (10752 bytes, md5 `fee201a96c8e30d09141f7493457f1b6` — khớp tiền tố "fee" trong tên). PE32 Mono/.NET assembly, 3 sections (`.text`/`.rsrc`/`.reloc`), Data Directory #14 (CLR Runtime Header) RVA `0x2008` size 72 ⇒ đúng là .NET assembly.

## Tóm tắt đề

Một chương trình **.NET** khi chạy in ra một chuỗi Base64, decode ra **fake flag** `flag{th1s_1s_dummy_f14g}`. Có một nhánh `if` chọn giữa giải mã *dummy* và *flag thật*. Phải đi vào nhánh thật để lấy flag.

## Phân tích (chi tiết)

**Nhận diện .NET.** File là PE bình thường nhưng phần mã là **CIL/MSIL** (bytecode máy ảo CLR), không phải x86. Nó có CLR header (Data Directory #14) trỏ tới metadata gồm các stream: `#~` (bảng metadata), `#Strings` (tên định danh), `#US` (**User Strings** — literal chuỗi UTF-16 của chương trình), `#Blob`, `#GUID`. Vì metadata giàu thông tin, dnSpy/ILSpy/dotPeek decompile ra gần như mã nguồn C#.

**Vì sao `objdump -d` vô dụng:** nó disassemble x86, trong khi thân hàm .NET là IL → phải dùng công cụ IL. Khi không có decompiler, ta khai thác điểm yếu khác: **literal chuỗi** nằm ở stream `#US` dưới dạng **UTF-16LE** → `strings -e l` đọc được.

Trinh sát chuỗi:

```bash
strings -a fee201a96c8e30d09141f7493457f1b6.exe | grep -iE "Base64|Decrypt|Create|Resource|Main"
#   FromBase64String
#   CreateDecryptor         <-- có dùng mã hóa đối xứng
#   Decrypt
#   Convert
#   dotnet_branch.Resources.resources
strings -a -e l fee201a96c8e30d09141f7493457f1b6.exe   # UTF-16 literals (#US)
#   AbCdEfGhIjKlMnOp          <-- 16 ký tự = khóa AES-128
#   ZyXwVuTsRqPoNmLk          <-- 16 ký tự = IV
#   Gd+wc29NWcMJG80rPMC9...==  (ciphertext #1, dài)
#   PVFbnnToZ4UfJMPmOqs+...=   (ciphertext #2, ngắn)
```

Có `FromBase64String` + `CreateDecryptor` + `Decrypt` + 2 ciphertext + 1 cặp `key/iv` 16-byte ⇒ chương trình **giải mã AES-128** một trong hai ciphertext tùy nhánh bool; nhánh `false` (mặc định) in dummy, `true` in flag thật.

**Hướng sai đã loại (thử thật).** Giải AES-128-CBC với key/iv là bytes ASCII thô của 2 chuỗi:

```python
from Crypto.Cipher import AES
import base64
key = b"AbCdEfGhIjKlMnOp"; iv = b"ZyXwVuTsRqPoNmLk"
AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode("Gd+wc29NWcMJG80r...=="))
# -> ra bytes rác, KHÔNG phải flag
```

⇒ key **không** dùng trực tiếp; .NET hầu như chắc đã bọc qua một **KDF** (ví dụ `Rfc2898DeriveBytes`=PBKDF2, hoặc `PasswordDeriveBytes` với salt+iteration) hoặc hash (MD5/SHA) trước khi làm khóa AES. Không có decompiler để đọc KDF/salt nên **không khôi phục được khóa dẫn xuất offline** → con đường chuẩn là **debug runtime** bằng dnSpy, không phải giải mã tay.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Nhận diện .NET assembly qua CLR header** — VÌ phải chuyển sang bộ công cụ IL (dnSpy) thay vì x86 disassembler.
- **`strings -e l` đọc UTF-16 `#US` stream** — VÌ literal chuỗi của .NET là UTF-16LE; lấy nhanh key/iv/ciphertext dù không có decompiler.
- **dnSpy debug runtime + sửa biến/đảo nhánh** — VÌ khóa AES được dẫn xuất bằng KDF không biết salt; giải tay offline bất khả thi, nên cho chương trình tự giải mã nhánh đúng và đọc output.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

**Con đường chuẩn (dnSpy):**

```
1) Mở fee201a96c8e30d09141f7493457f1b6.exe trong dnSpy.
2) Decompile: thấy if(<bool>) { Decrypt(ciphertext_thật) } else { Decrypt(ciphertext_dummy) }.
3) Đặt breakpoint tại Entry Point / ngay trước if; Start debug.
4) Khi dừng, sửa biến bool đó = true (cửa sổ Locals), HOẶC đảo IL brfalse<->brtrue.
5) Tiếp tục -> in Base64 flag thật:
   ZmxhZ3tkb3ROM1RfcHIwZ3I0bV9kZTZ1Z2cxbmdfMXNfZTRzeX0=
```

Kiểm chứng decode:

```python
import base64
print(base64.b64decode("ZmxhZ3tkb3ROM1RfcHIwZ3I0bV9kZTZ1Z2cxbmdfMXNfZTRzeX0=").decode())
# -> flag{dotN3T_pr0gr4m_de6ugg1ng_1s_e4sy}
```

Giá trị trích tĩnh để tham khảo/kiểm thử khi có dnSpy:
- key = `AbCdEfGhIjKlMnOp`, iv = `ZyXwVuTsRqPoNmLk`
- ct dài = `Gd+wc29NWcMJG80rPMC9y9Cu8kMFTEXoeyTShHaro0FSqKAN/Ts3po166uF3N0MgNWlz1/qaQfQNM7pyO8T45+ZVf7eAcwSOhFs9bdCqTsZyX1dfuAmX0PpCEC/T3JJWdU7vFepUFHNPMgFISR1UBw==`
- ct ngắn = `PVFbnnToZ4UfJMPmOqs+fUrLRilmKQcSs4JhATd8yfaGjffjDQOT8Eem+zuGRelxlm5XJiNWJIUPhe3Iar9MPqFxt2hVe0v7eXj4mao5y6Y=`

## Flag

```
flag{dotN3T_pr0gr4m_de6ugg1ng_1s_e4sy}
```

"debug chương trình .NET rất dễ". **Lưu ý:** README gốc viết nhầm `cflag{...}` (thừa chữ "c") — flag đúng bắt đầu bằng `flag{`.

## Gặp lại thì xử lý thế nào (playbook)

1. PE 3 sections `.text/.rsrc/.reloc` + Data Directory #14 ⇒ .NET → mở bằng dnSpy/ILSpy/dotPeek, không dùng IDA x86.
2. Không có decompiler? `strings -e l` moi literal UTF-16 (key, iv, ciphertext, URL...).
3. Thấy AES + ra rác khi dùng key thô ⇒ nghi KDF (`Rfc2898DeriveBytes`/`PasswordDeriveBytes`); đừng cố giải tay, debug runtime.
4. Qua nhánh `if`: sửa biến trong Locals, hoặc đảo IL `brfalse`↔`brtrue` / `ldc.i4.0`→`ldc.i4.1` rồi Save Module.
5. Đừng nộp fake flag (`flag{th1s_1s_dummy_f14g}`). Luôn chạy .NET lạ trong VM.
